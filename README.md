# Authoritative DNS — Offline IXFR Replay

Apply an incremental zone change log (IXFR) **offline, before promotion to
production**. The whole ordered set of changes is validated and applied to a
private copy first; any invalid change rejects the entire replay with a stable,
change-located error code and **no partial snapshot is ever returned**.

## Request

`POST /api/dns/ixfr/replay`

```json
{
  "start": [ <RR>, ... ],
  "changes": [
    { "deletes": [ <RR>, ... ], "adds": [ <RR>, ... ] }
  ],
  "continuityChecks": [
    { "id": "web", "name": "www.example.com", "requiredTypes": ["A", "AAAA"] }
  ]
}
```

* `start`: starting zone records — `SOA`, `A`, `AAAA`, `CNAME`, `TXT` — and must
  contain exactly one SOA.
* `changes`: **1–64** ordered changes; total records across the request
  (start + every delete/add) must not exceed **5000**.
* `continuityChecks` *(optional)*: **1–32** critical hosts that must resolve at
  the starting snapshot and after **every** complete change. Each entry has a
  unique non-empty `id`, a zone `name`, and a non-empty `requiredTypes` list
  limited to `A` / `AAAA`. When omitted, the original contract is unchanged.

Record shape:

| Type  | Fields |
|-------|--------|
| SOA   | `name, ttl, mname, rname, serial, refresh, retry, expire, minimum` |
| A     | `name, ttl, address` (IPv4) |
| AAAA  | `name, ttl, address` (IPv6, compressed form accepted) |
| CNAME | `name, ttl, target` |
| TXT   | `name, ttl, text` |

## Enforced rules

1. Every change **starts by deleting the current SOA** (matching its serial)
   and **ends with a single unique new SOA**.
2. The new serial must **strictly advance per RFC 1982 32-bit serial
   arithmetic**, including wraparound (`2^32-2 → 2^32-1 → 0 → 1`).
3. Every delete must hit an **existing, identical RR** (name/type/TTL/rdata).
4. Every add must be new — no duplicate of an existing RR or of another add in
   the same change.
5. Records of one RRset must share a **single TTL** (change a TTL by deleting
   the old RRset members and re-adding them in one change).
6. A **CNAME cannot coexist with any other data** at the same owner name, and
   there cannot be two distinct CNAME targets at one name.
7. The apex always holds **exactly one SOA**; SOAs never move off the apex.
8. Zone and record names are **case-insensitively normalized** (canonical
   lowercase; a single trailing dot is accepted as absolute form).

### Continuity semantics (when `continuityChecks` is present)

For each check, at the starting snapshot and after every complete change, the
engine walks from the normalized `name` along the **unique CNAME chain** until
it reaches the terminal owner name, then requires:

* the chain has no **loop**, no **broken/dangling** link, and never leaves the
  zone (**out-of-zone** terminal),
* the terminal name lives inside the zone apex, and
* the terminal holds at least one record of **every** required address family
  (`A` and/or `AAAA`).

A check failure at the start (`change: 0`) or at any intermediate change
rejects the whole replay — a log that is correct only in the final snapshot is
not publishable.

## Response

`200 OK`

```json
{
  "apex": "example.com",
  "final_serial": 1,
  "changes_applied": 3,
  "records": [ { "name": "...", "type": "...", "ttl": 300, ... } ],
  "sha256": "<sha-256 of the canonical, stably ordered snapshot>",
  "continuityChecks": [
    {
      "id": "web",
      "canonicalName": "example.com",
      "addresses": {
        "A": ["192.0.2.1", "192.0.2.2"],
        "AAAA": ["2001:db8::1"]
      }
    }
  ]
}
```

The `continuityChecks` array is present only when requested, appears in the
same order as the request, and reports the final canonical chain terminal plus
one stably sorted address list per required family. It never alters
`records`, `sha256`, `final_serial` or `changes_applied`.

`422 Unprocessable Entity` for an unpublishable log:

```json
{
  "error": {
    "code": "DELETE_NOT_FOUND",
    "rule": "delete_must_hit_existing_record",
    "change": 1,
    "record": 1,
    "message": "..."
  }
}
```

For a continuity failure the error additionally carries `check` (the failing
check id), `reason` (one of `cname_chain_loop`, `cname_chain_broken`,
`cname_chain_outside_zone`, `cname_target_not_unique`,
`missing_required_address`) and the failing snapshot in `change` (`0` = start,
otherwise the 1-based change). No records, digest or partial replay result is
ever returned.

```json
{
  "error": {
    "code": "CONTINUITY_CHECK_FAILED",
    "rule": "continuity_check_must_hold_at_every_snapshot",
    "change": 2,
    "check": "web",
    "reason": "missing_required_address",
    "message": "..."
  }
}
```

`change` is 1-based (`0` denotes the starting zone); `record` locates the
offending entry within that change's delete/add sequence (0-based).

### Stable error codes

| Code | Meaning |
|------|---------|
| `REQUEST_MALFORMED` / `REQUEST_LIMIT` | Bad envelope, or >5000 records / >64 changes |
| `INVALID_RECORD` | Malformed field, bad address/name, unsupported type |
| `INITIAL_SOA_MISSING` / `INITIAL_SOA_MULTIPLE` | Starting zone SOA invariants |
| `CHANGE_MUST_START_WITH_SOA` | First delete is not the current SOA |
| `CHANGE_MUST_END_WITH_SOA` | Last add is not a new SOA |
| `UNEXPECTED_SOA` | Extra/misplaced SOA inside a change |
| `SOA_NOT_AT_APEX` / `SOA_NOT_UNIQUE` | Apex SOA invariants |
| `SERIAL_NOT_ADVANCED` | RFC 1982 serial not strictly forward |
| `DELETE_NOT_FOUND` | Delete misses an existing RR (incl. TTL mismatch) |
| `RECORD_DUPLICATE` | Add duplicates existing/same-change RR |
| `TTL_MISMATCH` | RRset members carry different TTLs |
| `CNAME_CONFLICT` | CNAME coexists with other data |
| `NAME_OUTSIDE_ZONE` | Record owner is outside the zone apex |
| `CONTINUITY_CHECK_FAILED` | A critical host does not resolve (CNAME loop/broken/out-of-zone chain or missing required address family) at the start (`change: 0`) or after some change; payload includes `check` and `reason` |

## Running with Docker

```bash
# Host port is configurable (default 8080):
HOST_PORT=9090 docker compose up --build -d api
curl -s http://localhost:9090/healthz
```

### One-shot verification

The `verify` service runs the build check, the full test suite, and an HTTP
smoke test against the live API — including a serial-wraparound replay and
continuity-check success/failure scenarios — then exits and reports the
verdict via its exit code:

```bash
docker compose up --build verify
docker inspect --format '{{.State.ExitCode}}' $(docker compose ps -q verify)
# 0 = all checks passed
```

## Local development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python -m pytest
uvicorn app.api:app --reload
```
