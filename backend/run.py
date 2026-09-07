#!/usr/bin/env python3
"""Server launcher.

Works unchanged for local development and for a hosted deployment.  Hosting
platforms (Render, Fly, Railway, Heroku) inject the port to listen on as
`PORT`, so that is honoured ahead of the project's own `SFE_PORT`.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import uvicorn  # noqa: E402


def main() -> None:
    # PORT is the platform convention; SFE_PORT is ours; 8000 is the default.
    port = int(os.environ.get("PORT") or os.environ.get("SFE_PORT") or 8000)

    # A container has to listen on every interface to be reachable from
    # outside it; a local run should stay on the loopback address.
    default_host = "0.0.0.0" if os.environ.get("PORT") else "127.0.0.1"  # noqa: S104

    uvicorn.run(
        "app.main:app",
        host=os.environ.get("SFE_HOST", default_host),
        port=port,
        reload=os.environ.get("SFE_RELOAD", "0") == "1",
        # TLS is terminated by the platform's proxy, so the real client address
        # and scheme arrive in X-Forwarded-* headers.  Without this uvicorn
        # would report every request as coming from the proxy itself, and the
        # per-IP rate limit would treat all users as one caller.
        proxy_headers=True,
        forwarded_allow_ips=os.environ.get("SFE_FORWARDED_ALLOW_IPS", "*"),
        access_log=os.environ.get("SFE_ACCESS_LOG", "1") == "1",
    )


if __name__ == "__main__":
    main()
