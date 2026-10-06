"""Continuity checks for POST /api/dns/ixfr/replay.

When ``continuityChecks`` is supplied, every critical host must resolve —
through its unique CNAME chain to an in-zone terminal carrying every required
address family — at the starting snapshot and after every complete change.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.engine import SERIAL_MOD, ReplayError, replay

from .conftest import change, rr, soa

client = TestClient(app)


def check(check_id: str, name: str, *types: str) -> dict:
    return {"id": check_id, "name": name, "requiredTypes": list(types)}


def _start():
    return [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("example.com", "AAAA", 300, address="2001:db8::1"),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
        rr("ns1.example.com", "AAAA", 300, address="2001:db8::a"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
    ]


def payload(changes, start=None, checks=None):
    body: dict = {
        "start": start if start is not None else _start(),
        "changes": changes,
    }
    if checks is not None:
        body["continuityChecks"] = checks
    return body


# ---------------------------------------------------------------------------
# Contract: omitting the option leaves the original response untouched
# ---------------------------------------------------------------------------


def test_omitted_continuity_checks_keeps_original_contract():
    changes = [change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")])]
    result = replay(payload(changes))
    assert "continuityChecks" not in result
    assert set(result) == {
        "apex",
        "final_serial",
        "changes_applied",
        "records",
        "sha256",
    }


def test_checks_do_not_change_records_digest_or_serial():
    changes = [
        change(100, 101, adds=[rr("example.com", "A", address="192.0.2.2")]),
        change(101, 102, adds=[rr("example.com", "AAAA", address="2001:db8::2")]),
    ]
    plain = replay(payload(changes))
    guarded = replay(
        payload(changes, checks=[check("web", "www.example.com", "A", "AAAA")])
    )
    assert guarded["records"] == plain["records"]
    assert guarded["sha256"] == plain["sha256"]
    assert guarded["final_serial"] == plain["final_serial"]
    assert guarded["changes_applied"] == plain["changes_applied"]


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        [],
        "nope",
        [check(f"c{i}", "example.com", "A") for i in range(33)],
    ],
)
def test_check_count_must_be_1_to_32(bad):
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=bad))
    assert exc.value.code == "REQUEST_MALFORMED"


def test_check_entry_must_be_object():
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=["not-an-object"]))
    assert exc.value.code == "REQUEST_MALFORMED"


@pytest.mark.parametrize(
    "bad_entry",
    [
        {"name": "example.com", "requiredTypes": ["A"]},            # no id
        {"id": "", "name": "example.com", "requiredTypes": ["A"]},  # empty id
        {"id": 5, "name": "example.com", "requiredTypes": ["A"]},   # non-string
    ],
)
def test_check_id_required(bad_entry):
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=[bad_entry]))
    assert exc.value.code == "REQUEST_MALFORMED"


def test_check_ids_must_be_unique():
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                checks=[
                    check("web", "example.com", "A"),
                    check("web", "ns1.example.com", "A"),
                ],
            )
        )
    assert exc.value.code == "REQUEST_MALFORMED"
    assert exc.value.field == "id"


@pytest.mark.parametrize(
    "required",
    [
        None,
        [],
        ["CNAME"],
        ["A", "TXT"],
        ["aaaaa"],
        "A",
        [7],
    ],
)
def test_required_types_must_be_nonempty_A_or_AAAA(required):
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                checks=[{"id": "web", "name": "example.com", "requiredTypes": required}],
            )
        )
    assert exc.value.code == "REQUEST_MALFORMED"


def test_check_name_is_normalized():
    # Mixed case / trailing dot resolve to the same canonical owner.
    result = replay(
        payload(
            [change(100, 101)],
            checks=[check("web", "WWW.Example.COM.", "A")],
        )
    )
    entry = result["continuityChecks"][0]
    assert entry["id"] == "web"
    assert entry["canonicalName"] == "example.com"


def test_check_name_outside_zone_rejected():
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                checks=[check("web", "www.example.org", "A")],
            )
        )
    assert exc.value.code == "NAME_OUTSIDE_ZONE"
    assert exc.value.check == "web"


def test_check_invalid_name_is_malformed_request():
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                checks=[{"id": "web", "name": "bad name", "requiredTypes": ["A"]}],
            )
        )
    assert exc.value.code == "REQUEST_MALFORMED"
    assert exc.value.check == "web"


def test_explicit_null_checks_keeps_original_contract():
    body = payload([change(100, 101)])
    body["continuityChecks"] = None
    assert "continuityChecks" not in replay(body)


def test_duplicate_required_types_collapse():
    result = replay(
        payload(
            [change(100, 101)],
            checks=[{"id": "web", "name": "example.com", "requiredTypes": ["A", "a"]}],
        )
    )
    assert result["continuityChecks"][0]["addresses"] == {"A": ["192.0.2.1"]}


# ---------------------------------------------------------------------------
# Successful resolution
# ---------------------------------------------------------------------------


def test_direct_owner_with_required_families():
    result = replay(
        payload(
            [change(100, 101, adds=[rr("example.com", "A", address="192.0.2.2")])],
            checks=[check("apex", "example.com", "A", "AAAA")],
        )
    )
    entry = result["continuityChecks"][0]
    assert entry["canonicalName"] == "example.com"
    assert entry["addresses"] == {
        "A": ["192.0.2.1", "192.0.2.2"],
        "AAAA": ["2001:db8::1"],
    }


def test_cname_chain_followed_to_terminal():
    start = _start() + [
        rr("alias.example.com", "CNAME", 300, target="www.example.com"),
    ]
    result = replay(
        payload(
            [change(100, 101)],
            start=start,
            checks=[check("alias", "alias.example.com", "A")],
        )
    )
    entry = result["continuityChecks"][0]
    assert entry["canonicalName"] == "example.com"
    assert entry["addresses"] == {"A": ["192.0.2.1"]}


def test_results_follow_input_order():
    result = replay(
        payload(
            [change(100, 101)],
            checks=[
                check("zzz", "ns1.example.com", "A"),
                check("aaa", "example.com", "AAAA"),
                check("mmm", "www.example.com", "A", "AAAA"),
            ],
        )
    )
    entries = result["continuityChecks"]
    assert [e["id"] for e in entries] == ["zzz", "aaa", "mmm"]
    assert entries[0]["canonicalName"] == "ns1.example.com"
    assert entries[1]["canonicalName"] == "example.com"
    assert entries[2]["canonicalName"] == "example.com"


def test_addresses_are_stably_sorted():
    changes = [
        change(
            100,
            101,
            adds=[
                rr("ns1.example.com", "A", address="192.0.2.9"),
                rr("ns1.example.com", "A", address="192.0.2.2"),
                rr("ns1.example.com", "AAAA", address="2001:db8::9"),
                rr("ns1.example.com", "AAAA", address="2001:db8::1"),
            ],
        )
    ]
    result = replay(
        payload(changes, checks=[check("ns", "ns1.example.com", "A", "AAAA")])
    )
    addresses = result["continuityChecks"][0]["addresses"]
    assert addresses["A"] == ["192.0.2.10", "192.0.2.2", "192.0.2.9"]
    assert addresses["AAAA"] == ["2001:db8::1", "2001:db8::9", "2001:db8::a"]


def test_chain_terminal_can_move_between_changes():
    # www initially points at example.com; repoint it at ns1 in one change
    # (delete old CNAME, add new one) — both terminals carry the A family.
    repoint = change(
        100,
        101,
        deletes=[rr("www.example.com", "CNAME", target="example.com")],
        adds=[rr("www.example.com", "CNAME", target="ns1.example.com")],
    )
    result = replay(payload([repoint], checks=[check("web", "www.example.com", "A")]))
    assert result["continuityChecks"][0]["canonicalName"] == "ns1.example.com"
    assert result["continuityChecks"][0]["addresses"] == {"A": ["192.0.2.10"]}


# ---------------------------------------------------------------------------
# Failures at the starting snapshot
# ---------------------------------------------------------------------------


def test_missing_family_at_start_fails_at_change_zero():
    # ns1 has only A; requiring AAAA must fail before any change applies.
    start = [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101, adds=[rr("ns1.example.com", "AAAA", address="2001:db8::a")])],
                start=start,
                checks=[check("ns", "ns1.example.com", "A", "AAAA")],
            )
        )
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.change == 0
    assert exc.value.check == "ns"
    assert exc.value.reason == "missing_required_address"


def test_unresolvable_name_at_start_is_broken_chain():
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                checks=[check("ghost", "ghost.example.com", "A")],
            )
        )
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.change == 0
    assert exc.value.reason == "cname_chain_broken"


def test_chain_loop_at_start_fails():
    start = _start() + [
        rr("loop1.example.com", "CNAME", 300, target="loop2.example.com"),
        rr("loop2.example.com", "CNAME", 300, target="loop1.example.com"),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                start=start,
                checks=[check("loop", "loop1.example.com", "A")],
            )
        )
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.reason == "cname_chain_loop"


def test_chain_leaving_zone_at_start_fails():
    start = _start() + [
        rr("ext.example.com", "CNAME", 300, target="example.org"),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                [change(100, 101)],
                start=start,
                checks=[check("ext", "ext.example.com", "A")],
            )
        )
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.reason == "cname_chain_outside_zone"


# ---------------------------------------------------------------------------
# Failures at intermediate snapshots — no "final OK but mid-flight lost"
# ---------------------------------------------------------------------------


def test_temporary_loss_in_middle_change_rejected():
    # Change 1 adds a second IPv4; change 2 briefly deletes *both* apex As and
    # re-adds one; change 3 would restore normality. The middle snapshot must
    # reject even though the terminal is healthy again at the end.
    changes = [
        change(100, 101, adds=[rr("example.com", "A", address="192.0.2.3")]),
        change(
            101,
            102,
            deletes=[
                rr("example.com", "A", address="192.0.2.1"),
                rr("example.com", "A", address="192.0.2.3"),
            ],
        ),
        change(102, 103, adds=[rr("example.com", "A", address="192.0.2.1")]),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=[check("web", "www.example.com", "A")]))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.change == 2
    assert exc.value.check == "web"
    assert exc.value.reason == "missing_required_address"


def test_broken_chain_introduced_midway_rejected():
    changes = [
        change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")]),
        change(
            101,
            102,
            deletes=[rr("www.example.com", "CNAME", target="example.com")],
            adds=[rr("www.example.com", "CNAME", target="gone.example.com")],
        ),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=[check("web", "www.example.com", "A")]))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.change == 2
    assert exc.value.reason == "cname_chain_broken"


def test_chain_loop_introduced_midway_rejected():
    changes = [
        change(
            100,
            101,
            deletes=[rr("www.example.com", "CNAME", target="example.com")],
            adds=[
                rr("www.example.com", "CNAME", target="hop.example.com"),
                rr("hop.example.com", "CNAME", target="www.example.com"),
            ],
        ),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=[check("web", "www.example.com", "A")]))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.change == 1
    assert exc.value.reason == "cname_chain_loop"


def test_out_of_zone_redirection_midway_rejected():
    changes = [
        change(
            100,
            101,
            deletes=[rr("www.example.com", "CNAME", target="example.com")],
            adds=[rr("www.example.com", "CNAME", target="elsewhere.example.org")],
        ),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=[check("web", "www.example.com", "A")]))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.reason == "cname_chain_outside_zone"


def test_first_failing_check_in_input_order_is_reported():
    # Both checks are valid at the start; one change deletes ns1's A so the
    # second check fails first (input order), even though www is fine.
    changes = [
        change(
            100,
            101,
            deletes=[rr("ns1.example.com", "A", address="192.0.2.10")],
        )
    ]
    with pytest.raises(ReplayError) as exc:
        replay(
            payload(
                changes,
                checks=[
                    check("web", "www.example.com", "A"),
                    check("ns", "ns1.example.com", "A"),
                ],
            )
        )
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.check == "ns"
    assert exc.value.change == 1


# ---------------------------------------------------------------------------
# HTTP layer
# ---------------------------------------------------------------------------


def test_api_continuity_success_envelope():
    body = payload(
        [
            change(100, 101),
            change(
                101,
                102,
                adds=[rr("example.com", "A", address="192.0.2.2")],
            ),
        ],
        checks=[check("web", "www.example.com", "A", "AAAA")],
    )
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    entries = data["continuityChecks"]
    assert entries == [
        {
            "id": "web",
            "canonicalName": "example.com",
            "addresses": {
                "A": ["192.0.2.1", "192.0.2.2"],
                "AAAA": ["2001:db8::1"],
            },
        }
    ]
    assert "records" in data and len(data["sha256"]) == 64


def test_api_continuity_failure_is_422_and_leaks_nothing():
    changes = [
        change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")]),
        change(
            101,
            102,
            deletes=[rr("example.com", "A", address="192.0.2.1")],
        ),
    ]
    body = payload(changes, checks=[check("web", "www.example.com", "A")])
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    full = response.json()
    assert set(full.keys()) == {"error"}
    error = full["error"]
    assert error["code"] == "CONTINUITY_CHECK_FAILED"
    assert error["change"] == 2
    assert error["check"] == "web"
    assert error["reason"] == "missing_required_address"
    assert error["rule"] == "continuity_check_must_hold_at_every_snapshot"
    assert error["message"]


def test_api_continuity_failure_at_start_is_change_zero():
    body = payload(
        [change(100, 101)],
        checks=[check("ghost", "ghost.example.com", "A")],
    )
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "CONTINUITY_CHECK_FAILED"
    assert error["change"] == 0
    assert error["check"] == "ghost"


def test_api_malformed_continuity_checks():
    body = payload([change(100, 101)], checks=[])
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "REQUEST_MALFORMED"
