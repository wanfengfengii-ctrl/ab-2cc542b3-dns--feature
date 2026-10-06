#!/usr/bin/env bash
# One-shot verification entry point for the Compose "verify" service.
# Runs unit tests, a build/syntax check, then the HTTP smoke test (which
# includes 32-bit serial wraparound) against the running API. Reports the
# overall conclusion via its exit code and then exits.
set -euo pipefail

echo "==> [1/3] Build check (byte-compile)"
python -m compileall -q app tests scripts

echo "==> [2/3] Unit / API test suite"
python -m pytest

echo "==> [3/3] HTTP smoke test against ${API_BASE_URL}"
python scripts/smoke.py

echo "==> VERIFY OK"
