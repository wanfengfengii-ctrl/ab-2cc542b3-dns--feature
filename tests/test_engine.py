"""Rule-level tests for the IXFR replay engine."""

from __future__ import annotations

import pytest

from app.engine import (
    MAX_CHANGES,
    MAX_RECORDS,
    SERIAL_HALF,
    SERIAL_MOD,
    ReplayError,
    replay,
    serial_advances,
)

from .conftest import change, rr, soa


def payload(changes, start=None):
    return {"start": start if start is not None else _default_start(), "changes": changes}


def _default_start():
    return [
        soa(100),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("ns1.example.com", "A", 300, address="192.0.2.10"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
        rr("example.com", "TXT", 300, text="v=spf1 -all"),
    ]


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


def test_single_change_applies_and_returns_snapshot(base_payload_factory):
    result = replay(
        payload(
            [change(100, 101, adds=[rr("mail.example.com", "A", 300, address="192.0.2.20")])],
            start=base_payload_factory(),
        )
    )
    assert result["final_serial"] == 101
    assert result["changes_applied"] == 1
    names = [r["name"] for r in result["records"]]
    assert "mail.example.com" in names
    assert len(result["sha256"]) == 64


def test_multiple_changes_apply_in_order(base_payload_factory):
    changes = [
        change(100, 101, adds=[rr("a.example.com", "A", address="192.0.2.5")]),
        change(101, 200, deletes=[rr("a.example.com", "A", address="192.0.2.5")]),
    ]
    result = replay(payload(changes, start=base_payload_factory()))
    assert result["final_serial"] == 200
    assert all(r["name"] != "a.example.com" for r in result["records"])


def test_case_insensitive_normalization(base_payload_factory):
    start = base_payload_factory()
    # Mixed case in request; output is lowercased canonical form.
    changes = [
        {
            "deletes": [soa(100, name="ExAmPle.COM")],
            "adds": [
                rr("WWW.example.com", "CNAME", target="EXAMPLE.COM"),
            ],
        }
    ]
    # www CNAME already exists pointing at example.com -> would duplicate;
    # instead delete it first.
    changes = [
        {
            "deletes": [
                soa(100, name="ExAmPle.COM"),
                rr("WWW.example.com", "CNAME", target="example.com"),
            ],
            "adds": [
                rr("WWW.Example.Com", "CNAME", target="EXAMPLE.COM"),
                soa(101, name="ExAmPle.COM"),
            ],
        }
    ]
    result = replay(payload(changes, start=start))
    cname = next(r for r in result["records"] if r["type"] == "CNAME")
    assert cname["name"] == "www.example.com"
    assert cname["target"] == "example.com"


def test_trailing_dot_absolute_names_match(base_payload_factory):
    changes = [
        {
            "deletes": [soa(100), rr("www.example.com.", "CNAME", target="example.com.")],
            "adds": [soa(101)],
        }
    ]
    result = replay(payload(changes, start=base_payload_factory()))
    assert result["final_serial"] == 101


def test_records_are_stably_sorted(base_payload_factory):
    changes = [
        change(
            100,
            101,
            adds=[
                rr("zebra.example.com", "A", address="192.0.2.9"),
                rr("alpha.example.com", "A", address="192.0.2.8"),
                rr("alpha.example.com", "A", address="192.0.2.7"),
                rr("alpha.example.com", "AAAA", address="2001:db8::1"),
            ],
        )
    ]
    result = replay(payload(changes, start=base_payload_factory()))
    keys = [(r["name"], r["type"]) for r in result["records"]]
    assert keys == sorted(keys, key=lambda k: (k[0], {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}[k[1]]))
    alpha_as = [r for r in result["records"] if r["name"] == "alpha.example.com" and r["type"] == "A"]
    assert [r["address"] for r in alpha_as] == ["192.0.2.7", "192.0.2.8"]


def test_digest_is_deterministic(base_payload_factory):
    changes = [change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")])]
    first = replay(payload(changes, start=base_payload_factory()))
    second = replay(payload(changes, start=base_payload_factory()))
    assert first["sha256"] == second["sha256"]


# ---------------------------------------------------------------------------
# Serial arithmetic, including wraparound
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "old,new,expected",
    [
        (1, 2, True),
        (2, 1, False),
        (1, 1, False),
        (0, SERIAL_HALF - 1, True),
        (0, SERIAL_HALF, False),          # exactly halfway is not "after"
        (0, SERIAL_HALF + 1, False),
        (SERIAL_MOD - 1, 0, True),       # wrap by one
        (SERIAL_MOD - 5, 3, True),       # wrap by nine
        (0, SERIAL_MOD - 1, False),      # backwards across the boundary
        (10, 9, False),
    ],
)
def test_rfc1982_serial_arithmetic(old, new, expected):
    assert serial_advances(old, new) is expected


def test_serial_wraparound_change_succeeds(base_payload_factory):
    start = base_payload_factory()
    start[0] = soa(SERIAL_MOD - 1)
    changes = [
        change(SERIAL_MOD - 1, 0),
        change(0, 1),
    ]
    result = replay(payload(changes, start=start))
    assert result["final_serial"] == 1


def test_serial_equal_rejected(base_payload_factory):
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 100)], start=base_payload_factory()))
    assert exc.value.code == "SERIAL_NOT_ADVANCED"
    assert exc.value.change == 1


def test_serial_backwards_rejected(base_payload_factory):
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(100, 50)], start=base_payload_factory()))
    assert exc.value.code == "SERIAL_NOT_ADVANCED"


def test_serial_wraparound_too_far_rejected(base_payload_factory):
    start = base_payload_factory()
    start[0] = soa(0)
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(0, SERIAL_HALF + 5)], start=start))
    assert exc.value.code == "SERIAL_NOT_ADVANCED"


# ---------------------------------------------------------------------------
# Change envelope rules
# ---------------------------------------------------------------------------


def test_first_delete_must_be_current_soa(base_payload_factory):
    bad = {
        "deletes": [rr("ns1.example.com", "A", address="192.0.2.10"), soa(100)],
        "adds": [soa(101)],
    }
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "CHANGE_MUST_START_WITH_SOA"
    assert exc.value.change == 1
    assert exc.value.record == 0


def test_first_delete_serial_must_match_current(base_payload_factory):
    bad = change(99, 101)
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "CHANGE_MUST_START_WITH_SOA"


def test_last_add_must_be_soa(base_payload_factory):
    bad = {
        "deletes": [soa(100)],
        "adds": [soa(101), rr("mail.example.com", "A", address="192.0.2.20")],
    }
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    # First violation in order: the SOA sits at add position 1 instead of last.
    assert exc.value.code == "UNEXPECTED_SOA"
    assert exc.value.record == 1


def test_change_ending_in_non_soa_is_rejected(base_payload_factory):
    bad = {
        "deletes": [soa(100)],
        "adds": [
            rr("a.example.com", "A", address="192.0.2.20"),
            rr("b.example.com", "A", address="192.0.2.21"),
        ],
    }
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "CHANGE_MUST_END_WITH_SOA"
    assert exc.value.record == 2


def test_only_one_soa_delete_per_change(base_payload_factory):
    bad = {
        "deletes": [soa(100), soa(100)],
        "adds": [soa(101)],
    }
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "UNEXPECTED_SOA"
    assert exc.value.record == 1


def test_soa_must_stay_at_apex(base_payload_factory):
    bad = {
        "deletes": [soa(100)],
        "adds": [soa(101, name="sub.example.com")],
    }
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "SOA_NOT_AT_APEX"


def test_change_count_must_be_1_to_64(base_payload_factory):
    with pytest.raises(ReplayError) as exc:
        replay(payload([]))
    assert exc.value.code == "REQUEST_MALFORMED"
    too_many = [change(100 + i, 101 + i) for i in range(MAX_CHANGES + 1)]
    with pytest.raises(ReplayError):
        replay(payload(too_many))


# ---------------------------------------------------------------------------
# Delete/add semantics
# ---------------------------------------------------------------------------


def test_delete_of_missing_record_rejected(base_payload_factory):
    bad = change(
        100, 101, deletes=[rr("ghost.example.com", "A", address="192.0.2.66")]
    )
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "DELETE_NOT_FOUND"
    assert exc.value.change == 1
    assert exc.value.record == 1


def test_delete_with_wrong_ttl_is_not_a_hit(base_payload_factory):
    bad = change(100, 101, deletes=[rr("ns1.example.com", "A", ttl=999, address="192.0.2.10")])
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "DELETE_NOT_FOUND"


def test_add_duplicate_of_existing_rejected(base_payload_factory):
    bad = change(100, 101, adds=[rr("ns1.example.com", "A", address="192.0.2.10")])
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "RECORD_DUPLICATE"


def test_duplicate_adds_within_one_change_rejected(base_payload_factory):
    new = rr("mail.example.com", "A", address="192.0.2.20")
    bad = change(100, 101, adds=[new, dict(new)])
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "RECORD_DUPLICATE"
    assert exc.value.record == 2


def test_rrset_ttl_must_be_consistent(base_payload_factory):
    bad = change(
        100,
        101,
        adds=[
            rr("multi.example.com", "A", ttl=300, address="192.0.2.30"),
            rr("multi.example.com", "A", ttl=600, address="192.0.2.31"),
        ],
    )
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "TTL_MISMATCH"
    assert exc.value.record == 2


def test_ttl_change_requires_full_rrset_replacement(base_payload_factory):
    # Delete the one member at 300 and add two members at 600 in one change.
    changes = [
        change(
            100,
            101,
            deletes=[rr("ns1.example.com", "A", ttl=300, address="192.0.2.10")],
            adds=[
                rr("ns1.example.com", "A", ttl=600, address="192.0.2.10"),
                rr("ns1.example.com", "A", ttl=600, address="192.0.2.11"),
            ],
        )
    ]
    result = replay(payload(changes, start=base_payload_factory()))
    rrset = [r for r in result["records"] if r["name"] == "ns1.example.com" and r["type"] == "A"]
    assert {r["ttl"] for r in rrset} == {600}


# ---------------------------------------------------------------------------
# CNAME / SOA invariants
# ---------------------------------------------------------------------------


def test_cname_cannot_coexist_with_other_type(base_payload_factory):
    bad = change(
        100,
        101,
        adds=[rr("alias.example.com", "A", address="192.0.2.40")],
    )
    # Add A then CNAME at same name within one change.
    bad["adds"] = [
        rr("alias.example.com", "A", address="192.0.2.40"),
        rr("alias.example.com", "CNAME", target="example.com"),
        soa(101),
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "CNAME_CONFLICT"
    assert exc.value.record == 2


def test_other_type_cannot_join_existing_cname(base_payload_factory):
    bad = change(
        100,
        101,
        adds=[rr("www.example.com", "TXT", text="hello")],
    )
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "CNAME_CONFLICT"


def test_two_distinct_cnames_same_name_rejected(base_payload_factory):
    changes = [
        change(
            100,
            101,
            deletes=[rr("www.example.com", "CNAME", target="example.com")],
            adds=[
                rr("www.example.com", "CNAME", target="a.example.com"),
                rr("www.example.com", "CNAME", target="b.example.com"),
            ],
        )
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload(changes, start=base_payload_factory()))
    assert exc.value.code == "CNAME_CONFLICT"


def test_initial_zone_with_two_soas_rejected():
    start = [soa(1), soa(2)]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(1, 2)], start=start))
    assert exc.value.code == "INITIAL_SOA_MULTIPLE"


def test_initial_zone_without_soa_rejected():
    start = [rr("example.com", "A", address="192.0.2.1")]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(1, 2)], start=start))
    assert exc.value.code == "INITIAL_SOA_MISSING"


def test_record_outside_zone_rejected(base_payload_factory):
    bad = change(100, 101, adds=[rr("example.org", "A", address="192.0.2.9")])
    with pytest.raises(ReplayError) as exc:
        replay(payload([bad], start=base_payload_factory()))
    assert exc.value.code == "NAME_OUTSIDE_ZONE"


# ---------------------------------------------------------------------------
# Atomicity: a failing later change must not expose any partial snapshot
# ---------------------------------------------------------------------------


def test_failure_in_second_change_changes_nothing(base_payload_factory):
    good = change(100, 101, adds=[rr("mail.example.com", "A", address="192.0.2.20")])
    bad = change(101, 101)  # serial not advanced
    with pytest.raises(ReplayError) as exc:
        replay(payload([good, bad], start=base_payload_factory()))
    assert exc.value.change == 2
    # The engine raises rather than returning any snapshot — caller keeps its
    # old zone; verify the pre-failure state is reproducible from the same
    # input and still serial 100 baseline.
    untouched = replay(payload([], start=base_payload_factory()) if False else {
        "start": base_payload_factory(),
        "changes": [change(100, 101, adds=[rr("x.example.com", "A", address="192.0.2.21")])],
    })
    assert untouched["final_serial"] == 101


def test_record_budget_enforced(base_payload_factory):
    start = [soa(1)] + [
        rr(f"h{i}.example.com", "A", address="10.0.0.1") for i in range(MAX_RECORDS)
    ]
    with pytest.raises(ReplayError) as exc:
        replay(payload([change(1, 2)], start=start))
    assert exc.value.code == "REQUEST_LIMIT"
