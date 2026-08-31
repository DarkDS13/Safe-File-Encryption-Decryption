#!/usr/bin/env python3
"""Development server launcher: `python backend/run.py`."""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=os.environ.get("SFE_HOST", "127.0.0.1"),
        port=int(os.environ.get("SFE_PORT", "8000")),
        reload=os.environ.get("SFE_RELOAD", "0") == "1",
    )
