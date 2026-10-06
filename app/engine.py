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
* With optional ``continuityChecks``, every critical host must resolve through
  its unique in-zone CNAME chain to an owner carrying each required address
  family at the starting snapshot and after every complete change.
* A failing change — and therefore the whole replay — never produces a partial
  snapshot: each change is applied to a private copy first.
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
MAX_CONTINUITY_CHECKS = 32
CHECK_ADDRESS_TYPES = ("A", "AAAA")

RTYPES = ("SOA", "A", "AAAA", "CNAME", "TXT")
RTYPE_ORDER = {rtype: index for index, rtype in enumerate(RTYPES)}

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
        reason: str | None = None,
        index: int | None = None,
    ) -> None:
        super().__init__(message or rule)
        self.code = code
        self.rule = rule
        self.change = change
        self.message = message or rule
        self.record = record
        self.field = field
        self.check = check
        self.reason = reason
        self.index = index

    def to_payload(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "code": self.code,
            "rule": self.rule,
            "change": self.change,
            "message": self.message,
        }
        if self.check is not None:
            payload["check"] = self.check
        if self.reason is not None:
            payload["reason"] = self.reason
        if self.index is not None:
            payload["index"] = self.index
        if self.record is not None:
            payload["record"] = self.record
        if self.field is not None:
            payload["field"] = self.field
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


# ---------------------------------------------------------------------------
# Continuity checks: critical hosts must resolve at every snapshot
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ContinuityCheck:
    check_id: str
    name: str
    required_types: tuple[str, ...]


def parse_continuity_checks(value: Any) -> list[ContinuityCheck]:
    """Validate the optional ``continuityChecks`` envelope (1–32 entries).

    Each entry carries a unique non-empty ``id`` and a non-empty
    ``requiredTypes`` list restricted to ``A`` / ``AAAA``. The owner name is
    normalized here; the in-zone requirement is enforced against the apex in
    :func:`replay`.
    """

    if value is None:
        return []
    if not isinstance(value, list) or not (1 <= len(value) <= MAX_CONTINUITY_CHECKS):
        raise ReplayError(
            "REQUEST_MALFORMED",
            "continuity_checks_count_out_of_range",
            field="continuityChecks",
        )

    checks: list[ContinuityCheck] = []
    seen_ids: set[str] = set()
    for position, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_must_be_object",
                field="continuityChecks",
                index=position,
            )
        check_id = raw.get("id")
        if not isinstance(check_id, str) or not check_id:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_id_required",
                field="id",
                index=position,
            )
        if check_id in seen_ids:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_id_must_be_unique",
                field="id",
                index=position,
            )
        seen_ids.add(check_id)

        try:
            name = normalize_name(raw.get("name"), 0, "name")
        except ReplayError:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "continuity_check_invalid_name",
                field="name",
                check=check_id,
                index=position,
            )

        required = raw.get("requiredTypes")
        if not isinstance(required, list) or not required:
            raise ReplayError(
                "REQUEST_MALFORMED",
                "required_types_must_be_nonempty_array",
                field="requiredTypes",
                check=check_id,
                index=position,
            )
        required_types: list[str] = []
        for rtype in required:
            if not isinstance(rtype, str) or rtype.upper() not in CHECK_ADDRESS_TYPES:
                raise ReplayError(
                    "REQUEST_MALFORMED",
                    "required_type_must_be_A_or_AAAA",
                    field="requiredTypes",
                    check=check_id,
                    index=position,
                )
            rtype = rtype.upper()
            # Harmless duplicates (e.g. ["A", "A"]) collapse to one family.
            if rtype not in required_types:
                required_types.append(rtype)

        checks.append(ContinuityCheck(check_id, name, tuple(required_types)))
    return checks


def _continuity_failure(
    check: ContinuityCheck,
    change: int,
    reason: str,
    message: str,
) -> ReplayError:
    return ReplayError(
        "CONTINUITY_CHECK_FAILED",
        "continuity_check_must_hold_at_every_snapshot",
        change,
        message,
        check=check.check_id,
        reason=reason,
    )


def _resolve_continuity_check(
    zone: dict[tuple[str, str], RRset],
    apex: str,
    check: ContinuityCheck,
    change: int,
) -> dict[str, Any]:
    """Follow the unique CNAME chain and verify the terminal address records.

    Returns the per-check result fragment (canonical terminal plus one stably
    sorted address list per required family). Raises ``CONTINUITY_CHECK_FAILED``
    on loops, dangling/broken chains, out-of-zone terminals or a missing
    required address family.
    """

    visited: set[str] = set()
    current = check.name
    while True:
        if current in visited:
            raise _continuity_failure(
                check,
                change,
                "cname_chain_loop",
                f"CNAME chain for check {check.check_id!r} loops at {current!r}",
            )
        visited.add(current)

        cname_rrset = zone.get((current, "CNAME"))
        if cname_rrset is None:
            break
        # Zone invariants already guarantee a single CNAME target per owner;
        # a multi-target RRSet cannot describe a unique chain.
        if len(cname_rrset.rdatas) != 1:
            raise _continuity_failure(
                check,
                change,
                "cname_target_not_unique",
                f"CNAME chain for check {check.check_id!r} is not unique at {current!r}",
            )
        current = next(iter(cname_rrset.rdatas))[0]

    terminal = current
    if not _name_in_zone(terminal, apex):
        raise _continuity_failure(
            check,
            change,
            "cname_chain_outside_zone",
            f"CNAME chain for check {check.check_id!r} ends outside the zone at {terminal!r}",
        )

    owner_has_data = any(owner == terminal for owner, _ in zone)
    if not owner_has_data:
        raise _continuity_failure(
            check,
            change,
            "cname_chain_broken",
            f"CNAME chain for check {check.check_id!r} dangles at {terminal!r}",
        )

    addresses: dict[str, list[str]] = {}
    for rtype in check.required_types:
        rrset = zone.get((terminal, rtype))
        if rrset is None or not rrset.rdatas:
            raise _continuity_failure(
                check,
                change,
                "missing_required_address",
                f"terminal {terminal!r} lacks required {rtype} records for "
                f"check {check.check_id!r}",
            )
        addresses[rtype] = sorted(rdata[0] for rdata in rrset.rdatas)

    return {
        "id": check.check_id,
        "canonicalName": terminal,
        "addresses": addresses,
    }


def evaluate_continuity(
    zone: dict[tuple[str, str], RRset],
    apex: str,
    checks: list[ContinuityCheck],
    change: int,
) -> list[dict[str, Any]]:
    return [
        _resolve_continuity_check(zone, apex, check, change) for check in checks
    ]


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
    continuity_checks = parse_continuity_checks(payload.get("continuityChecks"))

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

    if continuity_checks:
        for check in continuity_checks:
            if not _name_in_zone(check.name, apex):
                raise ReplayError(
                    "NAME_OUTSIDE_ZONE",
                    "continuity_check_name_outside_zone",
                    0,
                    check=check.check_id,
                )
        # The critical hosts must resolve already at the starting snapshot.
        evaluate_continuity(zone, apex, continuity_checks, 0)

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

        # Every critical host must still resolve after each complete change.
        if continuity_checks:
            check_results = evaluate_continuity(
                zone, apex, continuity_checks, change_index
            )

    snapshot = build_snapshot(zone, apex, current_serial, len(changes))
    if continuity_checks:
        # The last complete change *is* the final snapshot; its evaluation is
        # reused so success results match exactly what was just validated.
        snapshot["continuityChecks"] = check_results
    return snapshot


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
