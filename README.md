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
* `continuityChecks` *(optional)*: **1–32** checks, each with a unique `id`,
  an in-zone `name`, and a non-empty `requiredTypes` subset of `A`/`AAAA`.
  When omitted, the request/response contract is unchanged.

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

## Continuity checks

Critical hosts must stay resolvable at **every** version of an incremental
rollout — a final snapshot that resolves is not enough if an intermediate
version briefly goes dark. With `continuityChecks` present, each check is
re-resolved at the starting snapshot and after every fully applied change:

1. From the normalized check `name`, follow the unique CNAME chain (the
   engine guarantees at most one CNAME target per owner).
2. The chain terminal must still be **inside the zone**.
3. The terminal must hold **every** required address type (`A`/`AAAA`).

CNAME loops, broken chains (dangling targets or a deleted checked name),
out-of-zone endpoints, and missing address families all reject the entire
replay — no records, digest, or partial replay result is returned:

```json
{
  "error": {
    "code": "CONTINUITY_CHECK_FAILED",
    "rule": "missing_required_type",
    "check": "web",
    "change": 2,
    "message": "check 'web': chain terminal example.com has no A record"
  }
}
```

`change` is the 1-based change whose snapshot broke the check (`0` = the
starting zone); `rule` is one of `cname_chain_loop`, `cname_chain_broken`,
`chain_terminal_outside_zone`, `missing_required_type`.

On success the response gains a `continuity` array — in check input order —
with the final canonical chain terminal and each required address family's
stably sorted addresses. Record ordering, digest, and serial results are
identical to an unchecked replay of the same log:

```json
{
  "continuity": [
    {
      "id": "web",
      "terminal": "example.com",
      "addresses": { "A": ["192.0.2.1"], "AAAA": ["2001:db8::1"] }
    }
  ]
}
```

## Response

`200 OK`

```json
{
  "apex": "example.com",
  "final_serial": 1,
  "changes_applied": 3,
  "records": [ { "name": "...", "type": "...", "ttl": 300, ... } ],
  "sha256": "<sha-256 of the canonical, stably ordered snapshot>"
}
```

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
| `CONTINUITY_CHECK_FAILED` | A continuity check broke at the start or an intermediate snapshot (carries `check` id and `change`) |

## Running with Docker

```bash
# Host port is configurable (default 8080):
HOST_PORT=9090 docker compose up --build -d api
curl -s http://localhost:9090/healthz
```

### One-shot verification

The `verify` service runs the build check, the full test suite, and an HTTP
smoke test against the live API — including a serial-wraparound replay — then
exits and reports the verdict via its exit code:

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
