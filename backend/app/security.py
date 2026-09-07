"""Password hashing, token issue, and the request-authorisation dependencies.

The account password handled here is completely separate from the passphrase
used to encrypt files.  The passphrase never reaches this process.
"""
from __future__ import annotations

import base64
import hashlib
import re
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from .config import settings
from .database import get_db
from .models import Role, User

_bearer = HTTPBearer(auto_error=False)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# --------------------------------------------------------------------------
# passwords
# --------------------------------------------------------------------------
# bcrypt only reads the first 72 bytes of a password and refuses anything
# longer.  Pre-hashing with SHA-256 gives a fixed-length input, so a long
# passphrase keeps all of its entropy instead of being truncated or rejected.
# The digest is base64-encoded because bcrypt stops at the first NUL byte.
def _prepare(password: str) -> bytes:
    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return base64.b64encode(digest)


def hash_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=settings.BCRYPT_ROUNDS)
    return bcrypt.hashpw(_prepare(password), salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_prepare(password), password_hash.encode("utf-8"))
    except ValueError:
        # Malformed stored hash: treat as a failed check rather than a crash.
        return False


def password_problem(password: str) -> str | None:
    """Return a plain-language reason the password is unacceptable (NF.8)."""
    if len(password) < settings.MIN_PASSWORD_LENGTH:
        return f"Password must be at least {settings.MIN_PASSWORD_LENGTH} characters long."
    if not re.search(r"[A-Za-z]", password):
        return "Password must contain at least one letter."
    if not re.search(r"\d", password):
        return "Password must contain at least one digit."
    return None


# --------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------
def create_access_token(user: User) -> tuple[str, int]:
    expires_in = settings.TOKEN_TTL_MINUTES * 60
    now = datetime.now(timezone.utc)
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=expires_in)).timestamp()),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expires_in


def decode_token(token: str) -> dict:
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


# --------------------------------------------------------------------------
# dependencies
# --------------------------------------------------------------------------
_UNAUTHENTICATED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Your session has expired or is invalid. Please sign in again.",
    headers={"WWW-Authenticate": "Bearer"},
)


def current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None or not credentials.credentials:
        raise _UNAUTHENTICATED
    try:
        payload = decode_token(credentials.credentials)
    except jwt.PyJWTError:
        raise _UNAUTHENTICATED from None

    user = db.get(User, payload.get("sub", ""))
    if user is None:
        raise _UNAUTHENTICATED
    if user.is_suspended:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been suspended. Contact an administrator.",
        )
    # Stash it so the audit middleware can name the actor without a second query.
    request.state.user = user
    return user


def current_admin(user: User = Depends(current_user)) -> User:
    """Role is checked here, on the server.  Hiding a button is not access control (F.12)."""
    if user.role != Role.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator privileges are required for this action.",
        )
    return user
