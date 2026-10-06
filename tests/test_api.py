"""HTTP-level tests for POST /api/dns/ixfr/replay, including wraparound."""

from __future__ import annotations

import pytest

from fastapi.testclient import TestClient

from app.api import app
from app.engine import SERIAL_MOD

from .conftest import change, rr, soa

client = TestClient(app)


def _start():
    return [
        soa(SERIAL_MOD - 2),
        rr("example.com", "A", 300, address="192.0.2.1"),
        rr("www.example.com", "CNAME", 300, target="example.com"),
    ]


def test_healthz():
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_replay_success_envelope():
    body = {
        "start": _start(),
        "changes": [change(SERIAL_MOD - 2, SERIAL_MOD - 1)],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200
    data = response.json()
    assert data["final_serial"] == SERIAL_MOD - 1
    assert data["apex"] == "example.com"
    assert len(data["sha256"]) == 64
    # canonical, stable ordering
    keys = [(r["name"], r["type"]) for r in data["records"]]
    assert keys == sorted(keys, key=lambda k: (k[0], {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}[k[1]]))


def test_api_serial_wraparound_smoke():
    """End-to-end wraparound: 2^32-2 -> 2^32-1 -> 0 -> 1."""
    body = {
        "start": _start(),
        "changes": [
            change(SERIAL_MOD - 2, SERIAL_MOD - 1),
            change(SERIAL_MOD - 1, 0),
            change(0, 1),
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["final_serial"] == 1
    assert data["changes_applied"] == 3


def test_api_error_locates_change_and_rule():
    body = {
        "start": _start(),
        "changes": [
            change(SERIAL_MOD - 2, SERIAL_MOD - 1),
            change(SERIAL_MOD - 1, SERIAL_MOD - 1),  # equal serial
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "SERIAL_NOT_ADVANCED"
    assert error["rule"] == "serial_must_advance_per_rfc1982"
    assert error["change"] == 2
    assert "records" not in response.json()


def test_api_missing_delete_is_422_with_change_and_record():
    body = {
        "start": _start(),
        "changes": [
            change(
                SERIAL_MOD - 2,
                SERIAL_MOD - 1,
                deletes=[rr("nope.example.com", "A", address="192.0.2.55")],
            )
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "DELETE_NOT_FOUND"
    assert error["change"] == 1
    assert error["record"] == 1


def test_api_cname_conflict():
    body = {
        "start": _start(),
        "changes": [
            {
                "deletes": [soa(SERIAL_MOD - 2)],
                "adds": [
                    rr("www.example.com", "A", address="192.0.2.80"),
                    soa(SERIAL_MOD - 1),
                ],
            }
        ],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "CNAME_CONFLICT"


def test_malformed_json_body():
    response = client.post(
        "/api/dns/ixfr/replay",
        content=b"{not json",
        headers={"content-type": "application/json"},
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "REQUEST_MALFORMED"


def test_no_partial_snapshot_field_on_failure():
    # serial moves backwards across the 32-bit boundary -> rejected
    body = {"start": _start(), "changes": [change(SERIAL_MOD - 2, SERIAL_MOD - 3)]}
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert set(response.json().keys()) == {"error"}


@pytest.mark.parametrize(
    "record",
    [
        {"name": "x.example.com", "type": "A", "ttl": 300, "address": "999.1.1.1"},
        {"name": "x.example.com", "type": "AAAA", "ttl": 300, "address": "nope"},
        {"name": "x.example.com", "type": "SOA", "ttl": 300},
        {"name": "bad name.example.com", "type": "A", "ttl": 300, "address": "1.2.3.4"},
        {"name": "x.example.com", "type": "MX", "ttl": 300},
        {"name": "x.example.com", "type": "A", "ttl": -1, "address": "1.2.3.4"},
    ],
)
def test_invalid_record_shapes(record):
    body = {
        "start": [soa(SERIAL_MOD - 2), record],
        "changes": [change(SERIAL_MOD - 2, SERIAL_MOD - 1)],
    }
    response = client.post("/api/dns/ixfr/replay", json=body)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "INVALID_RECORD"
