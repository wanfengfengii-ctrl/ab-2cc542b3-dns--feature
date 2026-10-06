#!/usr/bin/env python3
"""One-shot API smoke test used by the Compose ``verify`` service.

It exercises the running API over HTTP only:

1. health endpoint,
2. a successful replay that crosses the 32-bit serial boundary (wraparound),
3. deterministic digest and canonical ordering,
4. an illegal log that must be rejected with a stable, change-located error
   code and must never leak a partial snapshot,
5. continuity checks: a guarded replay that stays resolvable at every
   snapshot, and one that briefly loses a required address mid-rollout and
   must be rejected with the stable continuity error — again with no
   records, digest or partial replay result.

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


def cname(name: str, target: str, ttl: int = 300) -> dict:
    return {"name": name, "type": "CNAME", "ttl": ttl, "target": target}


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

    # --- Continuity checks: guarded replay stays resolvable -----------------
    guarded = {
        "start": [
            soa(WRAP - 2),
            a("example.com", "192.0.2.1"),
            cname("www.example.com", "example.com"),
        ],
        "changes": [
            change(WRAP - 2, WRAP - 1, adds=[a("example.com", "192.0.2.2")]),
            change(WRAP - 1, 0),
        ],
        "continuityChecks": [
            {"id": "web", "name": "www.example.com", "requiredTypes": ["A"]},
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", guarded)
    check("continuity replay returns 200", status == 200, str(body))
    results = body.get("continuity")
    check("continuity results present in input order",
          isinstance(results, list) and [r.get("id") for r in results] == ["web"], str(body))
    entry = results[0] if isinstance(results, list) and results else {}
    check("continuity terminal is the canonical chain endpoint",
          entry.get("terminal") == "example.com", str(entry))
    check("continuity addresses stably sorted",
          entry.get("addresses", {}).get("A") == ["192.0.2.1", "192.0.2.2"], str(entry))
    check("legacy fields intact alongside continuity",
          body.get("final_serial") == 0 and len(body.get("sha256", "")) == 64, str(body))

    # --- Continuity failure: an intermediate snapshot loses the address -----
    transient_loss = {
        "start": [
            soa(WRAP - 2),
            a("example.com", "192.0.2.1"),
            cname("www.example.com", "example.com"),
        ],
        "changes": [
            change(WRAP - 2, WRAP - 1),
            change(WRAP - 1, 0, deletes=[a("example.com", "192.0.2.1")]),
            change(0, 1, adds=[a("example.com", "192.0.2.3")]),
        ],
        "continuityChecks": [
            {"id": "web", "name": "www.example.com", "requiredTypes": ["A"]},
        ],
    }
    status, body = request("POST", "/api/dns/ixfr/replay", transient_loss)
    check("transient resolution loss rejected with 422", status == 422, str(body))
    error = body.get("error", {})
    check("stable continuity error code", error.get("code") == "CONTINUITY_CHECK_FAILED", str(error))
    check("error carries the check id", error.get("check") == "web", str(error))
    check("error locates the failing change (2)", error.get("change") == 2, str(error))
    check("error names the failure reason", error.get("rule") == "missing_required_type", str(error))
    check("no records, digest or partial replay leaked", set(body.keys()) == {"error"}, str(body.keys()))

    print("ALL SMOKE CHECKS PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except urllib.error.URLError as exc:
        print(f"FAIL: API unreachable at {BASE_URL}: {exc}")
        sys.exit(1)
