#!/usr/bin/env bash
# Run the whole test suite: backend, then frontend.
set -euo pipefail
cd "$(dirname "$0")/.."

PY=".venv/bin/python"
[ -x "$PY" ] || PY="python3"

echo "==> Backend (pytest)"
$PY -m pytest backend/tests -q "$@"

echo
echo "==> Frontend (node --test)"
node --test "frontend/tests/*.test.mjs"

echo
echo "All suites passed."
