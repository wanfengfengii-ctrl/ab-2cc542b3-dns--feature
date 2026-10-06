"""Test fixtures shared by the suite."""

from __future__ import annotations

import pytest

from app.engine import SERIAL_MOD


def soa(serial: int, name: str = "example.com", ttl: int = 3600, **overrides):
    record = {
        "name": name,
        "type": "SOA",
        "ttl": ttl,
        "mname": "ns1." + name if not name.endswith(".arpa") else "ns1." + name,
        "rname": "hostmaster." + name,
        "serial": serial % SERIAL_MOD,
        "refresh": 7200,
        "retry": 3600,
        "expire": 1209600,
        "minimum": 60,
    }
    record.update(overrides)
    return record


def rr(name: str, rtype: str, ttl: int = 300, **rdata):
    record = {"name": name, "type": rtype, "ttl": ttl}
    record.update(rdata)
    return record


def change(serial_from: int, serial_to: int, deletes=None, adds=None,
           apex: str = "example.com"):
    """Build a well-formed change: old SOA delete first, new SOA add last."""
    return {
        "deletes": [soa(serial_from, apex), *(deletes or [])],
        "adds": [*(adds or []), soa(serial_to, apex)],
    }


@pytest.fixture
def base_payload_factory():
    def _make(extra_start=None):
        start = [
            soa(100),
            rr("example.com", "A", 300, address="192.0.2.1"),
            rr("ns1.example.com", "A", 300, address="192.0.2.10"),
            rr("ns1.example.com", "AAAA", 300, address="2001:db8::a"),
            rr("www.example.com", "CNAME", 300, target="example.com"),
            rr("example.com", "TXT", 300, text="v=spf1 -all"),
        ]
        if extra_start:
            start.extend(extra_start)
        return start

    return _make
