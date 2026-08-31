#!/usr/bin/env bash
# Start the application. One process serves both the API and the browser client.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -d .venv ]; then
  echo "Creating a virtual environment..."
  python3 -m venv .venv
  ./.venv/bin/pip install -q --upgrade pip
  ./.venv/bin/pip install -q -r backend/requirements.txt
fi

export SFE_HOST="${SFE_HOST:-127.0.0.1}"
export SFE_PORT="${SFE_PORT:-8000}"

echo "Serving on http://${SFE_HOST}:${SFE_PORT}"
exec ./.venv/bin/python backend/run.py
