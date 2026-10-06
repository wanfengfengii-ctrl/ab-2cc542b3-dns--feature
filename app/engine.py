"""Offline IXFR replay engine.

The engine is deliberately free of any web framework dependency: it takes a
plain request payload (``dict``) and either returns the final, canonical zone
snapshot or raises :class:`ReplayError` carrying a *stable* error code that
pinpoints the offending change (1-based; ``0`` denotes the starting zone).

Rules implemented:

* Every change starts by deleting the current SOA and ends by adding a single,
  unique new SOA whose serial strictly advances per RFC 1982 serial arithmetic
  (32-bit, including wraparound).
* Every delete must hit an existing, identical RR (name/type/TTL/rdata).
* Every add must neither duplicate an existing RR nor another add in the same
  change; an RRset keeps one TTL.
* CNAME never coexists with any other data at the same owner name.
* The apex always holds exactly one SOA.
* A failing change — and therefore the whole replay — never produces a partial
  snapshot: each change is applied to a private copy first.

Optional ``continuityChecks`` pin critical names across the whole rollout:
each check is re-resolved at the starting snapshot and after every committed
change, following the (unique) CNAME chain from its normalized name to the
chain terminal. The terminal must stay inside the zone and keep every
required address type (``A``/``AAAA``); loops, dangling targets, out-of-zone
endpoints and missing address families reject the whole replay with
``CONTINUITY_CHECK_FAILED`` and no partial result.
"""

from __future__ import annotations

import copy
import hashlib
import re
from dataclasses import dataclass, field
from ipaddress import AddressValueError, IPv4Address, IPv6Address
from typing import Any

SERIAL_MOD = 1 << 32
SERIAL_HALF = 1 << 31
MAX_TTL = (1 << 31) - 1
MAX_RECORDS = 5000
MAX_CHANGES = 64
MAX_CHECKS = 32

RTYPES = ("SOA", "A", "AAAA", "CNAME", "TXT")
RTYPE_ORDER = {rtype: index for index, rtype in enumerate(RTYPES)}
ADDRESS_TYPES = ("A", "AAAA")

_LABEL_RE = re.compile(r"^(?:\*|[A-Za-z0-9_](?:[A-Za-z0-9_-]*[A-Za-z0-9_])?)$")


class ReplayError(Exception):
    """Validation failure with a stable machine-readable code."""

    def __init__(
        self,
        code: str,
        rule: str,
        change: int = 0,
        message: str = "",
        *,
        record: int | None = None,
        field: str | None = None,
        check: str | None = None,
    ) -> None:
        super().__init__(message or rule)
        self.code = code
        self.rule = rule
        self.change = change
        self.message = message or rule
        self.record = record
        self.field = field
        self.check = check

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "rule": self.rule,
            "change": self.change,
            "message": self.message,
        }
        if self.record is not None:
            payload["record"] = self.record
        if self.field is not None:
            payload["field"] = self.field
        if self.check is not None:
            payload["check"] = self.check
        return payload


@dataclass
class RRset:
    ttl: int
    rdatas: set[tuple[Any, ...]] = field(default_factory=set)


@dataclass
class Record:
    name: str
    rtype: str
    ttl: int
    rdata: tuple[Any, ...]

    def identity(self) -> tuple[Any, ...]:
        return (self.name, self.rtype, self.ttl, *self.rdata)


@dataclass
class ContinuityCheck:
    """A resolution invariant re-verified at every snapshot of the replay.

    ``required`` holds the address types the chain terminal must keep, in
    canonical ``ADDRESS_TYPES`` order and free of duplicates.
    """

    check_id: str
    name: str
    required: tuple[str, ...]


# ---------------------------------------------------------------------------
# Normalization helpers
# ---------------------------------------------------------------------------


def normalize_name(value: Any, change: int, field_name: str = "name") -> str:
    """DNS names are compared case-insensitively; canonicalize to lowercase.

    A single trailing dot (absolute form) is accepted and stripped so that
    ``Example.COM.`` and ``example.com`` denote the same owner.
    """

    if not isinstance(value, str):
        raise ReplayError(
            "INVALID_RECORD", "field_must_be_string", change, field=field_name
        )
    name = value
    if name.endswith("."):
        name = name[:-1]
    if not name or len(name) > 253:
        raise ReplayError(
            "INVALID_RECORD", "invalid_name_length", change, field=field_name
        )
    labels = name.split(".")
    for label in labels:
        if not label or len(label) > 63 or not _LABEL_RE.match(label):
            raise ReplayError(
                "INVALID_RECORD", "invalid_name_label", change, field=field_name
            )
    return name.lower()


def _uint(value: Any, field_name: str, change: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ReplayError(
            "INVALID_RECORD", "field_must_be_integer", change, field=field_name
        )
    if not 0 <= value <= maximum:
        raise ReplayError(
            "INVALID_RECORD", "field_out_of_range", change, field=field_name
        )
    return value


def _ttl(value: Any, change: int) -> int:
    return _uint(value, "ttl", change, MAX_TTL)


def normalize_record(raw: Any, change: int, index: int | None = None) -> Record:
    if not isinstance(raw, dict):
        raise ReplayError("INVALID_RECORD", "record_must_be_object", change)
    rtype = raw.get("type")
    if not isinstance(rtype, str) or rtype.upper() not in RTYPE_ORDER:
        raise ReplayError(
            "INVALID_RECORD",
            "unsupported_rtype",
            change,
            field="type",
            record=index if index is not None else -1,
        )
    rtype = rtype.upper()
    name = normalize_name(raw.get("name"), change)
    ttl = _ttl(raw.get("ttl"), change)

    def need_string(field_name: str) -> str:
        value = raw.get(field_name)
        if not isinstance(value, str):
            raise ReplayError(
                "INVALID_RECORD", "field_must_be_string", change, field=field_name
            )
        return value

    if rtype == "SOA":
        rdata = (
            normalize_name(raw.get("mname"), change, "mname"),
            normalize_name(raw.get("rname"), change, "rname"),
            _uint(raw.get("serial"), "serial", change, SERIAL_MOD - 1),
            _uint(raw.get("refresh"), "refresh", change, MAX_TTL),
            _uint(raw.get("retry"), "retry", change, MAX_TTL),
            _uint(raw.get("expire"), "expire", change, MAX_TTL),
            _uint(raw.get("minimum"), "minimum", change, MAX_TTL),
        )
    elif rtype == "A":
        address = need_string("address")
        try:
            rdata = (str(IPv4Address(address)),)
        except (AddressValueError, ValueError):
            raise ReplayError(
                "INVALID_RECORD", "invalid_ipv4_address", change, field="address"
            )
    elif rtype == "AAAA":
        address = need_string("address")
        try:
            rdata = (str(IPv6Address(address)).lower(),)
        except (AddressValueError, ValueError):
            raise ReplayError(
                "INVALID_RECORD", "invalid_ipv6_address", change, field="address"
            )
    elif rtype == "CNAME":
        rdata = (normalize_name(raw.get("target"), change, "target"),)
    else:  # TXT — character strings are case sensitive in the DNS.
        rdata = (need_string("text"),)

    return Record(name=name, rtype=rtype, ttl=ttl, rdata=rdata)


# ---------------------------------------------------------------------------
# Serial arithmetic (RFC 1982)
# ---------------------------------------------------------------------------


def serial_advances(old: int, new: int) -> bool:
    """True iff ``new`` is strictly after ``old`` in 32-bit serial space."""

    if old == new:
        return False
    return 0 < (new - old) % SERIAL_MOD < SERIAL_HALF


# ---------------------------------------------------------------------------
# Zone mutation, with all invariants enforced
# ---------------------------------------------------------------------------


def _record_existing(zone: dict[tuple[str, str], RRset], record: Record) -> bool:
    rrset = zone.get((record.name, record.rtype))
    return rrset is not None and rrset.ttl == record.ttl and record.rdata in rrset.rdatas


def _delete(
    zone: dict[tuple[str, str], RRset], record: Record, change: int, index: int
) -> None:
    rrset = zone.get((record.name, record.rtype))
    if rrset is None or record.rdata not in rrset.rdatas:
        raise ReplayError(
            "DELETE_NOT_FOUND",
            "delete_must_hit_existing_record",
            change,
            record=index,
        )
    if rrset.ttl != record.ttl:
        # Same name/type/rdata but a different TTL is not the same RR.
        raise ReplayError(
            "DELETE_NOT_FOUND",
            "delete_ttl_mismatch",
            change,
            record=index,
        )
    rrset.rdatas.remove(record.rdata)
    if not rrset.rdatas:
        del zone[(record.name, record.rtype)]


def _add(
    zone: dict[tuple[str, str], RRset], record: Record, change: int, index: int
) -> None:
    key = (record.name, record.rtype)
    rrset = zone.get(key)

    if record.rtype == "CNAME":
        for other_type in _types_at(zone, record.name):
            # Every other type at the same owner is a hard conflict, and a
            # second *distinct* CNAME target is a coexistence violation too;
            # an identical duplicate CNAME is reported below as a duplicate.
            if other_type != "CNAME":
                raise ReplayError(
                    "CNAME_CONFLICT",
                    "cname_cannot_coexist",
                    change,
                    record=index,
                )
        existing_cname = zone.get(key)
        if (
            existing_cname is not None
            and record.rdata not in existing_cname.rdatas
        ):
            raise ReplayError(
                "CNAME_CONFLICT",
                "cname_cannot_coexist",
                change,
                record=index,
            )
    else:
        if (record.name, "CNAME") in zone:
            raise ReplayError(
                "CNAME_CONFLICT",
                "cname_cannot_coexist",
                change,
                record=index,
            )

    if rrset is not None:
        if rrset.ttl != record.ttl:
            raise ReplayError(
                "TTL_MISMATCH",
                "rrset_ttl_must_be_consistent",
                change,
                record=index,
            )
        if record.rdata in rrset.rdatas:
            raise ReplayError(
                "RECORD_DUPLICATE",
                "add_must_not_duplicate",
                change,
                record=index,
            )
        rrset.rdatas.add(record.rdata)
    else:
        zone[key] = RRset(ttl=record.ttl, rdatas={record.rdata})


def _types_at(zone: dict[tuple[str, str], RRset], name: str) -> set[str]:
    return {rtype for (owner, rtype) in zone if owner == name}


# ---------------------------------------------------------------------------
# Request envelope validation
# ---------------------------------------------------------------------------


def _records_list(value: Any, change: int, key: str) -> list[Any]:
    if not isinstance(value, list):
        raise ReplayError(
            "INVALID_CHANGE", f"{key}_must_be_array", change, field=key
        )
    return value


def _name_in_zone(name: str, apex: str) -> bool:
    return name == apex or name.endswith("." + apex)


def _parse_continuity_checks(payload: dict[str, Any]) -> list[ContinuityCheck] | None:
    """Validate the optional ``continuityChecks`` envelope.

    Returns ``None`` when the field is omitted (the legacy contract). Names
    are normalized like record owners; the in-zone requirement is enforced
    later, once the apex is known.
    """

    raw = payload.get("continuityChecks")
    if raw is None:
        return None
    if not isinstance(raw, list):
        raise ReplayError(
            "REQUEST_MALFORMED",
            "continuity_checks_must_be_array",
            field="continuityChecks",
        )
    if not 1 <= len(raw) <= MAX_CHECKS:
        raise ReplayError(
            "REQUEST_MALFORMED",
            "continuity_checks_count_out_of_range",
            field="continuityChecks",
        )
    checks: list[ContinuityCheck] = []
    seen_ids: set[str] = set()
    for entry in raw:
        if not isinstance(entry, dict):
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_must_be_object",
                field="continuityChecks",
            )
        check_id = entry.get("id")
        if not isinstance(check_id, str) or not check_id:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_id_must_be_nonempty_string",
                field="continuityChecks",
            )
        if check_id in seen_ids:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_id_not_unique",
                field="continuityChecks",
            )
        seen_ids.add(check_id)
        raw_name = entry.get("name")
        if not isinstance(raw_name, str):
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_name_must_be_string",
                field="continuityChecks",
            )
        try:
            name = normalize_name(raw_name, 0)
        except ReplayError:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_name_invalid",
                field="continuityChecks",
            ) from None
        raw_types = entry.get("requiredTypes")
        if not isinstance(raw_types, list) or not raw_types:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "required_types_must_be_nonempty_array",
                field="continuityChecks",
            )
        required: list[str] = []
        for value in raw_types:
            if not isinstance(value, str) or value.upper() not in ADDRESS_TYPES:
                raise ReplayError(
                    "REQUEST_MALFORMED",
                    "unsupported_required_type",
                    field="continuityChecks",
                )
            rtype = value.upper()
            if rtype not in required:
                required.append(rtype)
        required.sort(key=ADDRESS_TYPES.index)
        checks.append(
            ContinuityCheck(check_id=check_id, name=name, required=tuple(required))
        )
    return checks


# ---------------------------------------------------------------------------
# Continuity checks: CNAME-chain resolution at every snapshot
# ---------------------------------------------------------------------------


def _continuity_failure(
    rule: str, check: ContinuityCheck, change: int, detail: str
) -> ReplayError:
    return ReplayError(
        "CONTINUITY_CHECK_FAILED",
        rule,
        change,
        f"check {check.check_id!r}: {detail}",
        check=check.check_id,
    )


def _resolve_terminal(
    zone: dict[tuple[str, str], RRset],
    names: set[str],
    apex: str,
    check: ContinuityCheck,
    change: int,
) -> str:
    """Follow the unique CNAME chain from the check name to its terminal.

    The engine guarantees at most one CNAME rdata per owner name, so the
    chain is unambiguous. Loops, dangling targets and out-of-zone endpoints
    are all continuity failures located at ``change`` (0 = starting zone).
    """

    visited: set[str] = set()
    name = check.name
    while True:
        if name in visited:
            raise _continuity_failure(
                "cname_chain_loop", check, change, f"CNAME chain loops at {name}"
            )
        visited.add(name)
        if name not in names:
            raise _continuity_failure(
                "cname_chain_broken", check, change, f"{name} has no records"
            )
        cname = zone.get((name, "CNAME"))
        if cname is None:
            return name
        target = next(iter(cname.rdatas))[0]
        if not _name_in_zone(target, apex):
            raise _continuity_failure(
                "chain_terminal_outside_zone",
                check,
                change,
                f"CNAME target {target} is outside the zone",
            )
        name = target


def _evaluate_continuity(
    zone: dict[tuple[str, str], RRset],
    apex: str,
    checks: list[ContinuityCheck],
    change: int,
) -> None:
    """Re-verify every check against one snapshot, in check input order."""

    names = {owner for (owner, _) in zone}
    for check in checks:
        terminal = _resolve_terminal(zone, names, apex, check, change)
        for rtype in check.required:
            if (terminal, rtype) not in zone:
                raise _continuity_failure(
                    "missing_required_type",
                    check,
                    change,
                    f"chain terminal {terminal} has no {rtype} record",
                )


def _continuity_results(
    zone: dict[tuple[str, str], RRset],
    apex: str,
    checks: list[ContinuityCheck],
    change: int,
) -> list[dict[str, Any]]:
    """Resolution outcomes at the final snapshot, in check input order.

    Only called after the final snapshot passed evaluation, so resolution
    cannot fail here. Addresses are stably sorted per address family, in the
    same canonical string order as the snapshot records.
    """

    names = {owner for (owner, _) in zone}
    results: list[dict[str, Any]] = []
    for check in checks:
        terminal = _resolve_terminal(zone, names, apex, check, change)
        addresses = {
            rtype: sorted(rdata[0] for rdata in zone[(terminal, rtype)].rdatas)
            for rtype in check.required
        }
        results.append(
            {"id": check.check_id, "terminal": terminal, "addresses": addresses}
        )
    return results


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------


def replay(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ReplayError("REQUEST_MALFORMED", "payload_must_be_object")

    start = payload.get("start")
    if not isinstance(start, list) or not start:
        raise ReplayError(
            "REQUEST_MALFORMED", "start_must_be_nonempty_array", field="start"
        )
    changes = payload.get("changes")
    if not isinstance(changes, list) or not (1 <= len(changes) <= MAX_CHANGES):
        raise ReplayError(
            "REQUEST_MALFORMED",
            "changes_count_out_of_range",
            field="changes",
        )
    checks = _parse_continuity_checks(payload)

    total_records = len(start) + sum(
        len(_records_list(change.get("deletes"), index + 1, "deletes"))
        + len(_records_list(change.get("adds"), index + 1, "adds"))
        for index, change in enumerate(changes)
        if isinstance(change, dict)
    )
    if total_records > MAX_RECORDS:
        raise ReplayError(
            "REQUEST_LIMIT", "record_count_exceeds_5000", field="records"
        )

    # --- Build the starting zone -------------------------------------------------
    zone: dict[tuple[str, str], RRset] = {}
    apex: str | None = None
    soa_record: Record | None = None
    start_records: list[Record] = []

    for index, raw in enumerate(start):
        record = normalize_record(raw, 0, index)
        start_records.append(record)
        if record.rtype == "SOA":
            if soa_record is not None:
                raise ReplayError(
                    "INITIAL_SOA_MULTIPLE",
                    "apex_must_have_one_soa",
                    0,
                    record=index,
                )
            soa_record = record
            apex = record.name
        _add(zone, record, 0, index)

    if soa_record is None or apex is None:
        raise ReplayError("INITIAL_SOA_MISSING", "start_must_include_soa")

    for index, record in enumerate(start_records):
        if not _name_in_zone(record.name, apex):
            raise ReplayError(
                "NAME_OUTSIDE_ZONE", "record_name_outside_zone", 0, record=index
            )

    if checks is not None:
        for check in checks:
            if not _name_in_zone(check.name, apex):
                raise ReplayError(
                    "REQUEST_MALFORMED",
                    "continuity_check_name_outside_zone",
                    field="continuityChecks",
                )
        # The starting snapshot must already satisfy every check.
        _evaluate_continuity(zone, apex, checks, 0)

    current_serial: int = soa_record.rdata[2]

    # --- Apply changes sequentially, each atomically -----------------------------
    for change_index, raw_change in enumerate(changes, start=1):
        if not isinstance(raw_change, dict):
            raise ReplayError(
                "INVALID_CHANGE", "change_must_be_object", change_index
            )
        deletes = _records_list(raw_change.get("deletes"), change_index, "deletes")
        adds = _records_list(raw_change.get("adds"), change_index, "adds")
        if not deletes or not adds:
            raise ReplayError(
                "INVALID_CHANGE",
                "change_must_delete_and_add",
                change_index,
            )

        candidate = copy.deepcopy(zone)

        # First operation must be the *current* SOA.
        first = normalize_record(deletes[0], change_index, 0)
        if first.rtype != "SOA":
            raise ReplayError(
                "CHANGE_MUST_START_WITH_SOA",
                "first_delete_must_be_current_soa",
                change_index,
                record=0,
            )
        if first.name != apex:
            raise ReplayError(
                "SOA_NOT_AT_APEX", "soa_must_be_at_apex", change_index, record=0
            )
        if first.rdata[2] != current_serial:
            raise ReplayError(
                "CHANGE_MUST_START_WITH_SOA",
                "first_delete_must_be_current_soa",
                change_index,
                record=0,
            )
        if not _record_existing(candidate, first):
            # It names the current serial but is otherwise not the live RR
            # (TTL/timers differ), so it is still a delete that misses.
            raise ReplayError(
                "DELETE_NOT_FOUND",
                "delete_must_hit_existing_record",
                change_index,
                record=0,
            )
        _delete(candidate, first, change_index, 0)

        # Remaining deletes: ordinary RRs only, each must exist.
        for position, raw_record in enumerate(deletes[1:], start=1):
            record = normalize_record(raw_record, change_index, position)
            if not _name_in_zone(record.name, apex):
                raise ReplayError(
                    "NAME_OUTSIDE_ZONE",
                    "record_name_outside_zone",
                    change_index,
                    record=position,
                )
            if record.rtype == "SOA":
                raise ReplayError(
                    "UNEXPECTED_SOA",
                    "only_one_soa_pair_per_change",
                    change_index,
                    record=position,
                )
            _delete(candidate, record, change_index, position)

        # Adds: the last operation is the new unique SOA.
        for position, raw_record in enumerate(adds, start=1):
            record = normalize_record(raw_record, change_index, position)
            is_last = position == len(adds)
            if record.rtype != "SOA" and not _name_in_zone(record.name, apex):
                raise ReplayError(
                    "NAME_OUTSIDE_ZONE",
                    "record_name_outside_zone",
                    change_index,
                    record=position,
                )
            if is_last and record.rtype != "SOA":
                raise ReplayError(
                    "CHANGE_MUST_END_WITH_SOA",
                    "last_add_must_be_new_soa",
                    change_index,
                    record=position,
                )
            if record.rtype == "SOA":
                if not is_last:
                    raise ReplayError(
                        "UNEXPECTED_SOA",
                        "new_soa_must_be_last_add",
                        change_index,
                        record=position,
                    )
                if record.name != apex:
                    raise ReplayError(
                        "SOA_NOT_AT_APEX",
                        "soa_must_be_at_apex",
                        change_index,
                        record=position,
                    )
                if not serial_advances(current_serial, record.rdata[2]):
                    raise ReplayError(
                        "SERIAL_NOT_ADVANCED",
                        "serial_must_advance_per_rfc1982",
                        change_index,
                        record=position,
                    )
            _add(candidate, record, change_index, position)

        # The candidate must finish with exactly one SOA at the apex.
        apex_types = _types_at(candidate, apex)
        if "SOA" not in apex_types or len(candidate[(apex, "SOA")].rdatas) != 1:
            raise ReplayError(
                "SOA_NOT_UNIQUE", "apex_must_have_one_soa", change_index
            )

        zone = candidate
        current_serial = _soa_serial(zone, apex)
        if checks is not None:
            # Every intermediate snapshot must keep the checked names
            # resolvable — a transient loss rejects the whole rollout.
            _evaluate_continuity(zone, apex, checks, change_index)

    result = build_snapshot(zone, apex, current_serial, len(changes))
    if checks is not None:
        result["continuity"] = _continuity_results(zone, apex, checks, len(changes))
    return result


def _soa_serial(zone: dict[tuple[str, str], RRset], apex: str) -> int:
    rdata = next(iter(zone[(apex, "SOA")].rdatas))
    return rdata[2]


# ---------------------------------------------------------------------------
# Canonical output + digest
# ---------------------------------------------------------------------------


def _rdata_fields(rtype: str, rdata: tuple[Any, ...]) -> dict[str, Any]:
    if rtype == "SOA":
        return {
            "mname": rdata[0],
            "rname": rdata[1],
            "serial": rdata[2],
            "refresh": rdata[3],
            "retry": rdata[4],
            "expire": rdata[5],
            "minimum": rdata[6],
        }
    if rtype in ("A", "AAAA"):
        return {"address": rdata[0]}
    if rtype == "CNAME":
        return {"target": rdata[0]}
    return {"text": rdata[0]}


def _rdata_tokens(rtype: str, rdata: tuple[Any, ...]) -> list[str]:
    if rtype == "SOA":
        return [str(part) for part in rdata]
    return [str(rdata[0])]


def canonical_records(
    zone: dict[tuple[str, str], RRset]
) -> list[dict[str, Any]]:
    keys = sorted(zone, key=lambda key: (key[0], RTYPE_ORDER[key[1]]))
    result: list[dict[str, Any]] = []
    for name, rtype in keys:
        rrset = zone[(name, rtype)]
        for rdata in sorted(rrset.rdatas, key=lambda rd: _rdata_tokens(rtype, rd)):
            record = {"name": name, "type": rtype, "ttl": rrset.ttl}
            record.update(_rdata_fields(rtype, rdata))
            result.append(record)
    return result


def snapshot_digest(zone: dict[tuple[str, str], RRset]) -> str:
    lines: list[str] = []
    for name, rtype in sorted(zone, key=lambda key: (key[0], RTYPE_ORDER[key[1]])):
        rrset = zone[(name, rtype)]
        for rdata in sorted(rrset.rdatas, key=lambda rd: _rdata_tokens(rtype, rd)):
            tokens = [name, rtype, str(rrset.ttl), *_rdata_tokens(rtype, rdata)]
            lines.append(" ".join(tokens))
    canonical = ("\n".join(lines) + "\n").encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def build_snapshot(
    zone: dict[tuple[str, str], RRset],
    apex: str,
    final_serial: int,
    changes_applied: int,
) -> dict[str, Any]:
    return {
        "apex": apex,
        "final_serial": final_serial,
        "changes_applied": changes_applied,
        "records": canonical_records(zone),
        "sha256": snapshot_digest(zone),
    }
