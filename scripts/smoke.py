#!/usr/bin/env python3
"""One-shot API smoke test used by the Compose ``verify`` service.

It exercises the running API over HTTP only:

1. health endpoint,
2. a successful replay that crosses the 32-bit serial boundary (wraparound),
3. deterministic digest and canonical ordering,
4. an illegal log that must be rejected with a stable, change-located error
   code and must never leak a partial snapshot,
5. the ``continuityChecks`` option: a guarded replay succeeds with terminal
   details, while a host that only fails at an *intermediate* snapshot is
   rejected with check id / change / reason and no partial results.

Exits 0 only when every assertion holds.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = os.environ.get("API_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
WRAP = 1 << 32


def soa(serial: int) -> dict:
    return {
        "name": "example.com",
        "type": "SOA",
        "ttl": 3600,
        "mname": "ns1.example.com",
        "rname": "hostmaster.example.com",
        "serial": serial % WRAP,
        "refresh": 7200,
        "retry": 3600,
        "expire": 1209600,
        "minimum": 60,
    }


def a(name: str, address: str, ttl: int = 300) -> dict:
    return {"name": name, "type": "A", "ttl": ttl, "address": address}


def aaaa(name: str, address: str, ttl: int = 300) -> dict:
    return {"name": name, "type": "AAAA", "ttl": ttl, "address": address}


def cname(name: str, target: str, ttl: int = 300) -> dict:
    return {"name": name, "type": "CNAME", "ttl": ttl, "target": target}


def continuity_check(check_id: str, name: str, *required_types: str) -> dict:
    return {"id": check_id, "name": name, "requiredTypes": list(required_types)}


def change(serial_from: int, serial_to: int, deletes=None, adds=None) -> dict:
    return {
        "deletes": [soa(serial_from), *(deletes or [])],
        "adds": [*(adds or []), soa(serial_to)],
    }


def request(method: str, path: str, body=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        BASE_URL + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read() or b"{}")


def check(label: str, condition: bool, detail: str = "") -> None:
    if not condition:
        print(f"FAIL: {label} {detail}".rstrip())
        sys.exit(1)
    print(f"PASS: {label}")


def main() -> int:
    status, body = request("GET", "/healthz")
    check("healthz returns 200", status == 200 and body.get("status") == "ok")

    start = [
        soa(WRAP - 2),
        a("example.com", "192.0.2.1"),
        a("ns1.example.com", "192.0.2.10"),
    ]

    # --- Successful replay crossing the serial boundary ---------------------
    payload = {
        "start": start,
        "changes": [
            change(WRAP - 2, WRAP - 1, adds=[a("mail.example.com", "192.0.2.20")]),
            change(WRAP - 1, 0),
            change(0, 1),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", payload)
    check("wraparound replay returns 200", status == 200, str(body))
    check("final serial wrapped to 1", body.get("final_serial") == 1, str(body.get("final_serial")))
    check("all three changes applied", body.get("changes_applied") == 3)
    digest = body.get("sha256", "")
    check("sha256 digest present", len(digest) == 64 and all(c in "0123456789abcdef" for c in digest))

    records = body.get("records", [])
    keys = [(r["name"], r["type"]) for r in records]
    type_rank = {"SOA": 0, "A": 1, "AAAA": 2, "CNAME": 3, "TXT": 4}
    check("records are canonically sorted", keys == sorted(keys, key=lambda k: (k[0], type_rank[k[1]])))
    check("soa is at apex only", all(
        not (r["type"] == "SOA" and r["name"] != "example.com") for r in records
    ))
    check("added record visible", any(
        r["name"] == "mail.example.com" and r.get("address") == "192.0.2.20" for r in records
    ))

    # Replaying the identical payload yields the identical digest.
    status, body2 = request("POST", "/api/dns/ixfr/replay", payload)
    check("digest is deterministic", status == 200 and body2.get("sha256") == digest)

    # --- Illegal log: serial does not advance in change 2 -------------------
    bad = {
        "start": [soa(WRAP - 2), a("example.com", "192.0.2.1")],
        "changes": [
            change(WRAP - 2, WRAP - 1),
            change(WRAP - 1, WRAP - 1),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad)
    check("illegal log rejected with 422", status == 422, str(body))
    error = body.get("error", {})
    check("stable error code", error.get("code") == "SERIAL_NOT_ADVANCED", str(error))
    check("error locates the change (2)", error.get("change") == 2, str(error))
    check("error names the violated rule", bool(error.get("rule")))
    check("no partial snapshot leaked", set(body.keys()) == {"error"}, str(body.keys()))

    # --- Illegal log: delete misses an existing record ----------------------
    bad_delete = {
        "start": [soa(WRAP - 2)],
        "changes": [change(WRAP - 2, WRAP - 1, deletes=[a("ghost.example.com", "192.0.2.66")])],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad_delete)
    error = body.get("error", {})
    check("missing delete rejected", status == 422 and error.get("code") == "DELETE_NOT_FOUND", str(body))
    check("missing delete located to record 1", error.get("record") == 1)

    # --- Continuity checks: critical hosts resolve at every snapshot --------
    cont_start = [
        soa(100),
        a("example.com", "192.0.2.1"),
        aaaa("example.com", "2001:db8::1"),
        a("ns1.example.com", "192.0.2.10"),
        aaaa("ns1.example.com", "2001:db8::a"),
        cname("www.example.com", "example.com"),
    ]
    cont_payload = {
        "start": cont_start,
        "changes": [
            change(100, 101, adds=[a("example.com", "192.0.2.2")]),
            change(101, 102, adds=[aaaa("example.com", "2001:db8::2")]),
        ],
        "continuityChecks": [
            continuity_check("web", "www.example.com", "A", "AAAA"),
            continuity_check("ns", "ns1.example.com", "A"),
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", cont_payload)
    check("continuity replay returns 200", status == 200, str(body))
    entries = body.get("continuityChecks", [])
    check("continuity results in input order", [e.get("id") for e in entries] == ["web", "ns"])
    web = entries[0]
    check("cname chain reaches canonical terminal", web.get("canonicalName") == "example.com")
    check(
        "addresses present per family and stably sorted",
        web.get("addresses") == {
            "A": ["192.0.2.1", "192.0.2.2"],
            "AAAA": ["2001:db8::1", "2001:db8::2"],
        },
        str(web.get("addresses")),
    )
    check("digest and records unaffected by checks", "records" in body and len(body.get("sha256", "")) == 64)

    # A host healthy at start and finish but briefly lost mid-flight is rejected.
    flaky_payload = {
        "start": cont_start,
        "changes": [
            change(100, 101, adds=[a("mail.example.com", "192.0.2.20")]),
            change(
                101,
                102,
                deletes=[
                    a("example.com", "192.0.2.1"),
                ],
            ),
            change(102, 103, adds=[a("example.com", "192.0.2.1")]),
        ],
        "continuityChecks": [continuity_check("web", "www.example.com", "A")],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", flaky_payload)
    check("intermediate continuity loss rejected with 422", status == 422, str(body))
    error = body.get("error", {})
    check("continuity error code stable", error.get("code") == "CONTINUITY_CHECK_FAILED", str(error))
    check("continuity error names the check id", error.get("check") == "web")
    check("continuity error locates the middle change (2)", error.get("change") == 2)
    check("continuity error gives the reason", error.get("reason") == "missing_required_address", str(error))
    check("no partial replay results leaked", set(body.keys()) == {"error"}, str(body.keys()))

    # A failing check at the starting snapshot reports change 0.
    bad_start_payload = {
        "start": cont_start,
        "changes": [change(100, 101)],
        "continuityChecks": [continuity_check("ghost", "ghost.example.com", "A")],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", bad_start_payload)
    error = body.get("error", {})
    check("start-snapshot failure is change 0", status == 422 and error.get("change") == 0, str(body))
    check("start-snapshot failure is a broken chain", error.get("reason") == "cname_chain_broken", str(error))

    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
