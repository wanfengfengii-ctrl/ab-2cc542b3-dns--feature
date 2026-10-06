"""Continuity checks: resolution invariants at every replay snapshot.

Covers the engine rules and the HTTP contract of the optional
``continuityChecks`` field on ``POST /api/dns/ixfr/replay``.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import app
from app.engine import MAX_CHECKS, ReplayError, replay

from .conftest import change, rr, soa

client = TestClient(app)


def start_zone():
    return [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("example.com", "AAAA", 300, address="2001:db8::1"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
        rr("app.example.com", "CNAME", 300, target="www.example.com"),
    ]


def payload(changes, checks=None, start=None):
    body = {
        "start": start if start is not None else start_zone(),
        "changes": changes,
    }
    if checks is not None:
        body["continuityChecks"] = checks
    return body


def web_check(**overrides):
    check = {"id": "web", "name": "www.example.com", "requiredTypes": ["A"]}
    check.update(overrides)
    return check


# ---------------------------------------------------------------------------
# Legacy contract when the option is omitted
# ---------------------------------------------------------------------------


def test_omitted_checks_keep_legacy_response_shape():
    result = replay(payload([change(100, 101)]))
    assert "continuity" not in result
    assert result["final_serial"] == 101
    assert len(result["sha256"]) == 64


def test_records_digest_and_serial_unchanged_by_checks():
    changes = [
        change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")])
    ]
    plain = replay(payload(changes))
    guarded = replay(payload(changes, checks=[web_check()]))
    assert guarded["records"] == plain["records"]
    assert guarded["sha256"] == plain["sha256"]
    assert guarded["final_serial"] == plain["final_serial"]
    assert guarded["changes_applied"] == plain["changes_applied"]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_checks_pass_at_start_and_after_every_change():
    result = replay(
        payload(
            [
                change(
                    100,
                    101,
                    adds=[rr("mail.example.com", "A", address="192.0.2.20")],
                ),
                change(101, 102),
            ],
            checks=[web_check()],
        )
    )
    assert result["continuity"] == [
        {"id": "web", "terminal": "example.com", "addresses": {"A": ["192.0.2.1"]}}
    ]
    assert result["final_serial"] == 102
    assert result["changes_applied"] == 2


def test_results_follow_check_input_order():
    checks = [
        {"id": "app", "name": "app.example.com", "requiredTypes": ["A", "AAAA"]},
        {"id": "web", "name": "www.example.com", "requiredTypes": ["A"]},
        {"id": "apex", "name": "example.com", "requiredTypes": ["AAAA"]},
    ]
    result = replay(payload([change(100, 101)], checks=checks))
    assert [entry["id"] for entry in result["continuity"]] == ["app", "web", "apex"]
    # app -> www -> example.com: the chain endpoint is reported, canonicalized.
    assert result["continuity"][0]["terminal"] == "example.com"
    assert result["continuity"][0]["addresses"] == {
        "A": ["192.0.2.1"],
        "AAAA": ["2001:db8::1"],
    }


def test_addresses_are_stably_sorted_per_family():
    changes = [
        change(
            100,
            101,
            adds=[
                rr("example.com", "A", address="192.0.2.9"),
                rr("example.com", "A", address="192.0.2.2"),
                rr("example.com", "AAAA", address="2001:db8::9"),
                rr("example.com", "AAAA", address="2001:db8::2"),
            ],
        )
    ]
    result = replay(payload(changes, checks=[web_check(requiredTypes=["A", "AAAA"])]))
    addresses = result["continuity"][0]["addresses"]
    assert addresses["A"] == ["192.0.2.1", "192.0.2.2", "192.0.2.9"]
    assert addresses["AAAA"] == ["2001:db8::1", "2001:db8::2", "2001:db8::9"]


def test_terminal_reflects_the_final_snapshot():
    changes = [
        change(
            100,
            101,
            deletes=[rr("www.example.com", "CNAME", target="example.com")],
            adds=[
                rr("www.example.com", "CNAME", target="mail.example.com"),
                rr("mail.example.com", "A", address="192.0.2.20"),
            ],
        )
    ]
    result = replay(payload(changes, checks=[web_check()]))
    assert result["continuity"][0]["terminal"] == "mail.example.com"
    assert result["continuity"][0]["addresses"] == {"A": ["192.0.2.20"]}


def test_check_name_is_normalized():
    checks = [web_check(name="WWW.Example.COM.")]
    result = replay(payload([change(100, 101)], checks=checks))
    assert result["continuity"][0]["terminal"] == "example.com"


def test_required_types_case_insensitive_and_deduplicated():
    checks = [web_check(requiredTypes=["aaaa", "A", "a"])]
    result = replay(payload([change(100, 101)], checks=checks))
    assert list(result["continuity"][0]["addresses"].keys()) == ["A", "AAAA"]


# ---------------------------------------------------------------------------
# Continuity failures: stable code, check id, change number, reason
# ---------------------------------------------------------------------------


def test_missing_address_family_at_start_snapshot():
    start = start_zone() + [rr("only4.example.com", "A", 300, address="192.0.2.44")]
    checks = [{"id": "v6", "name": "only4.example.com", "requiredTypes": ["AAAA"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=checks, start=start))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.rule == "missing_required_type"
    assert exc.value.change == 0
    assert exc.value.check == "v6"


def test_failure_pinpoints_the_intermediate_change():
    changes = [
        change(100, 101),
        change(101, 102, deletes=[rr("example.com", "A", 300, address="192.0.2.1")]),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=[web_check()]))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.rule == "missing_required_type"
    assert exc.value.change == 2
    assert exc.value.check == "web"


def test_transient_loss_fails_even_if_a_later_change_would_fix():
    changes = [
        change(100, 101, deletes=[rr("example.com", "A", 300, address="192.0.2.1")]),
        change(101, 102, adds=[rr("example.com", "A", 300, address="192.0.2.3")]),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=[web_check()]))
    assert exc.value.change == 1


def test_first_failing_check_in_input_order_is_reported():
    start = start_zone() + [rr("solo.example.com", "A", 300, address="192.0.2.50")]
    changes = [
        change(
            100,
            101,
            deletes=[
                rr("example.com", "A", 300, address="192.0.2.1"),
                rr("solo.example.com", "A", 300, address="192.0.2.50"),
            ],
        )
    ]
    checks = [
        {"id": "solo", "name": "solo.example.com", "requiredTypes": ["A"]},
        web_check(),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=checks, start=start))
    assert exc.value.change == 1
    # solo.example.com lost its only record: the name itself is gone.
    assert exc.value.check == "solo"
    assert exc.value.rule == "cname_chain_broken"


def test_cname_loop_detected():
    start = start_zone() + [
        rr("loop1.example.com", "CNAME", 300, target="loop2.example.com"),
        rr("loop2.example.com", "CNAME", 300, target="loop1.example.com"),
    ]
    checks = [{"id": "loop", "name": "loop1.example.com", "requiredTypes": ["A"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=checks, start=start))
    assert exc.value.code == "CONTINUITY_CHECK_FAILED"
    assert exc.value.rule == "cname_chain_loop"
    assert exc.value.change == 0


def test_self_referential_cname_is_a_loop():
    start = start_zone() + [
        rr("self.example.com", "CNAME", 300, target="self.example.com")
    ]
    checks = [{"id": "self", "name": "self.example.com", "requiredTypes": ["A"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=checks, start=start))
    assert exc.value.rule == "cname_chain_loop"


def test_loop_formed_by_a_later_change():
    changes = [
        change(
            100,
            101,
            deletes=[rr("app.example.com", "CNAME", target="www.example.com")],
            adds=[rr("app.example.com", "CNAME", target="app.example.com")],
        )
    ]
    checks = [{"id": "app", "name": "app.example.com", "requiredTypes": ["A"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=checks))
    assert exc.value.rule == "cname_chain_loop"
    assert exc.value.change == 1


def test_dangling_cname_is_a_broken_chain():
    start = start_zone() + [
        rr("ghost.example.com", "CNAME", 300, target="missing.example.com")
    ]
    checks = [{"id": "ghost", "name": "ghost.example.com", "requiredTypes": ["A"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=checks, start=start))
    assert exc.value.rule == "cname_chain_broken"
    assert exc.value.change == 0


def test_checked_name_deleted_mid_replay_is_broken():
    changes = [
        change(
            100,
            101,
            deletes=[rr("app.example.com", "CNAME", target="www.example.com")],
        )
    ]
    checks = [{"id": "app", "name": "app.example.com", "requiredTypes": ["A"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, checks=checks))
    assert exc.value.rule == "cname_chain_broken"
    assert exc.value.change == 1


def test_cname_target_outside_zone_rejected():
    start = start_zone() + [
        rr("ext.example.com", "CNAME", 300, target="cdn.other.org")
    ]
    checks = [{"id": "ext", "name": "ext.example.com", "requiredTypes": ["A"]}]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=checks, start=start))
    assert exc.value.rule == "chain_terminal_outside_zone"
    assert exc.value.change == 0


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "checks",
    [
        "not-a-list",
        [],
        [web_check()] * (MAX_CHECKS + 1),
        [[]],
        [{"name": "www.example.com", "requiredTypes": ["A"]}],
        [{"id": "", "name": "www.example.com", "requiredTypes": ["A"]}],
        [{"id": 7, "name": "www.example.com", "requiredTypes": ["A"]}],
        [
            {"id": "dup", "name": "www.example.com", "requiredTypes": ["A"]},
            {"id": "dup", "name": "example.com", "requiredTypes": ["A"]},
        ],
        [{"id": "x", "name": 42, "requiredTypes": ["A"]}],
        [{"id": "x", "name": "bad name.example.com", "requiredTypes": ["A"]}],
        [{"id": "x", "name": "www.example.com"}],
        [{"id": "x", "name": "www.example.com", "requiredTypes": []}],
        [{"id": "x", "name": "www.example.com", "requiredTypes": "A"}],
        [{"id": "x", "name": "www.example.com", "requiredTypes": ["TXT"]}],
        [{"id": "x", "name": "www.example.com", "requiredTypes": ["A", 1]}],
        [{"id": "x", "name": "other.org", "requiredTypes": ["A"]}],
        [{"id": "x", "name": "deep.other.org", "requiredTypes": ["A"]}],
    ],
    ids=[
        "not_a_list",
        "empty",
        "too_many",
        "entry_not_object",
        "id_missing",
        "id_empty",
        "id_not_string",
        "id_not_unique",
        "name_not_string",
        "name_invalid",
        "required_types_missing",
        "required_types_empty",
        "required_types_not_list",
        "required_type_unsupported",
        "required_type_not_string",
        "name_outside_zone",
        "name_outside_zone_deep",
    ],
)
def test_malformed_continuity_checks_rejected(checks):
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 101)], checks=checks))
    assert exc.value.code == "REQUEST_MALFORMED"


def test_thirty_two_checks_accepted():
    start = start_zone() + [
        rr(f"h{i}.example.com", "A", 300, address="192.0.2.1") for i in range(31)
    ]
    checks = [
        {"id": f"check-{i}", "name": f"h{i}.example.com", "requiredTypes": ["A"]}
        for i in range(31)
    ]
    checks.append(web_check())
    result = replay(payload([change(100, 101)], checks=checks, start=start))
    assert len(result["continuity"]) == 32


# ---------------------------------------------------------------------------
# HTTP contract
# ---------------------------------------------------------------------------


def test_api_success_includes_continuity_block():
    body = payload([change(100, 101)], checks=[web_check()])
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["continuity"] == [
        {"id": "web", "terminal": "example.com", "addresses": {"A": ["192.0.2.1"]}}
    ]
    assert data["final_serial"] == 101
    assert len(data["sha256"]) == 64


def test_api_omitted_checks_have_no_continuity_key():
    response = client.post("/api/dns/ixfr/replay", json=payload([change(100, 101)]))
    assert response.status_code == 200
    assert "continuity" not in response.json()


def test_api_continuity_failure_payload_is_stable_and_complete():
    body = payload(
        [
            change(100, 101),
            change(
                101, 102, deletes=[rr("example.com", "A", 300, address="192.0.2.1")]
            ),
        ],
        checks=[web_check()],
    )
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    data = response.json()
    # No records, digest or any partial replay result.
    assert set(data.keys()) == {"error"}
    error = data["error"]
    assert error["code"] == "CONTINUITY_CHECK_FAILED"
    assert error["check"] == "web"
    assert error["change"] == 2
    assert error["rule"] == "missing_required_type"
    assert error["message"]


def test_api_continuity_failure_at_start_snapshot_reports_change_zero():
    start = start_zone() + [rr("only4.example.com", "A", 300, address="192.0.2.44")]
    body = payload(
        [change(100, 101)],
        checks=[{"id": "v6", "name": "only4.example.com", "requiredTypes": ["AAAA"]}],
        start=start,
    )
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "CONTINUITY_CHECK_FAILED"
    assert error["change"] == 0
    assert error["check"] == "v6"


def test_api_malformed_checks_are_422():
    body = payload([change(100, 101)], checks=[])
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "REQUEST_MALFORMED"
    assert error["rule"] == "continuity_checks_count_out_of_range"


def test_limits_include_max_checks():
    response = client.get("/api/dns/ixfr/limits")
    assert response.status_code == 200
    assert response.json()["max_checks"] == MAX_CHECKS
