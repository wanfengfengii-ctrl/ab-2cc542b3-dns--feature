"""HTTP layer for the offline IXFR replay service."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from .engine import MAX_CHANGES, MAX_CHECKS, MAX_RECORDS, ReplayError, replay

logger = logging.getLogger("ixfr")

app = FastAPI(
    title="Authoritative DNS IXFR Replay",
    version="1.0.0",
    description=(
        "Offline replay of incremental zone logs before promotion to "
        "production. Either the whole ordered change set applies or none of "
        "it does."
    ),
)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/dns/ixfr/limits")
async def limits() -> dict[str, int]:
    return {
        "max_changes": MAX_CHANGES,
        "max_records": MAX_RECORDS,
        "max_checks": MAX_CHECKS,
    }


@app.post("/api/dns/ixfr/replay")
async def replay_endpoint(request: Request) -> JSONResponse:
    try:
        payload: Any = await request.json()
    except ValueError:
        return JSONResponse(
            status_code=400,
            content={
                "error": {
                    "code": "REQUEST_MALFORMED",
                    "rule": "payload_must_be_json",
                    "change": 0,
                    "message": "request body is not valid JSON",
                }
            },
        )

    try:
        result = replay(payload)
    except ReplayError as exc:
        # Validation failures are 4xx: the submitted log is unpublishable.
        # Only the stable error payload is ever returned — no partial zone.
        logger.info("replay rejected: %s at change %s", exc.code, exc.change)
        return JSONResponse(status_code=422, content={"error": exc.to_payload()})

    return JSONResponse(status_code=200, content=result)
