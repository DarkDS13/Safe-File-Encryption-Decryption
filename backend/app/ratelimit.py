"""Per-account (and per-IP, before sign-in) fixed-window rate limiting.

An in-process counter is the right size for this deployment.  A multi-process
deployment would move the same interface onto Redis without changing callers.
"""
from __future__ import annotations

import threading
import time

from fastapi import HTTPException, Request, status

from .config import settings


class RateLimiter:
    def __init__(self, limit: int, window_seconds: int) -> None:
        self.limit = limit
        self.window = window_seconds
        self._hits: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def check(self, key: str) -> tuple[bool, int, int]:
        """Return (allowed, remaining, retry_after_seconds)."""
        now = time.monotonic()
        cutoff = now - self.window
        with self._lock:
            hits = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(hits) >= self.limit:
                self._hits[key] = hits
                retry_after = max(1, int(self.window - (now - hits[0])))
                return False, 0, retry_after
            hits.append(now)
            self._hits[key] = hits
            return True, self.limit - len(hits), 0

    def reset(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._hits.clear()
            else:
                self._hits.pop(key, None)


api_limiter = RateLimiter(settings.RATE_LIMIT_REQUESTS, settings.RATE_LIMIT_WINDOW_SECONDS)
login_limiter = RateLimiter(settings.LOGIN_RATE_LIMIT, settings.RATE_LIMIT_WINDOW_SECONDS)


def identity(request: Request) -> str:
    """Prefer the bearer token so a limit follows the account, not the network."""
    auth = request.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return "tok:" + auth[7:][:64]
    return "ip:" + (request.client.host if request.client else "unknown")


def enforce(limiter: RateLimiter, key: str) -> None:
    allowed, _remaining, retry_after = limiter.check(key)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many requests. Please wait a moment and try again.",
            headers={"Retry-After": str(retry_after)},
        )
