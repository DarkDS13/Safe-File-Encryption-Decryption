"""Audit logging helper.

Every write goes through here so there is exactly one place to be sure that no
key material, passphrase, or plaintext is ever recorded (C.5 / NF.3).
"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import Request
from sqlalchemy.orm import Session

from .models import AuditLog, User

logger = logging.getLogger("sfe.audit")

# Anything whose key looks like one of these is dropped before the detail blob
# is serialised, no matter which call site supplied it.
_FORBIDDEN_KEY_PARTS = (
    "password",
    "passphrase",
    "secret",
    "key",
    "token",
    "plaintext",
    "salt",
    "nonce",
    "iv",
)


def _scrub(detail: dict[str, Any] | None) -> str:
    if not detail:
        return ""
    clean: dict[str, Any] = {}
    for key, value in detail.items():
        lowered = key.lower()
        if any(part in lowered for part in _FORBIDDEN_KEY_PARTS):
            clean[key] = "[redacted]"
        elif isinstance(value, (str, int, float, bool)) or value is None:
            clean[key] = value
        else:
            clean[key] = str(value)
    return json.dumps(clean, sort_keys=True)


def client_ip(request: Request | None) -> str:
    if request is None:
        return ""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.client.host if request.client else "")[:64]


def record(
    db: Session,
    *,
    action: str,
    user: User | None = None,
    actor_email: str | None = None,
    outcome: str = "success",
    detail: dict[str, Any] | None = None,
    request: Request | None = None,
    commit: bool = True,
) -> AuditLog:
    entry = AuditLog(
        user_id=user.id if user else None,
        actor_email=(actor_email or (user.email if user else "anonymous"))[:255],
        action=action[:64],
        outcome=outcome[:16],
        detail=_scrub(detail),
        ip_address=client_ip(request),
    )
    db.add(entry)
    if commit:
        db.commit()
    logger.info("audit action=%s outcome=%s actor=%s", entry.action, entry.outcome, entry.actor_email)
    return entry
