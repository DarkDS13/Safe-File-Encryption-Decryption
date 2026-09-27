"""0.1 Authentication & Session Management (F.12)."""
from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..database import get_db
from ..models import Role, User, utcnow
from ..ratelimit import enforce, identity, login_limiter
from ..schemas import LoginRequest, RegisterRequest, TokenResponse, UserOut
from ..security import (
    EMAIL_RE,
    create_access_token,
    current_user,
    hash_password,
    needs_rehash,
    password_problem,
    verify_password,
)

logger = logging.getLogger("sfe.auth")

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    enforce(login_limiter, identity(request))

    if not EMAIL_RE.match(payload.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That does not look like an email address. Use the form name@example.com.",
        )
    problem = password_problem(payload.password)
    if problem:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=problem)

    existing = db.scalar(select(User).where(User.email == payload.email))
    if existing is not None:
        audit.record(
            db,
            action="auth.register",
            actor_email=payload.email,
            outcome="failure",
            detail={"reason": "email_taken"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with that email already exists. Sign in instead.",
        )

    # The very first account to register becomes the administrator, so a fresh
    # deployment is usable without a manual database edit.
    first_account = db.scalar(select(func.count()).select_from(User)) == 0

    user = User(
        email=payload.email,
        display_name=payload.display_name.strip() or payload.email.split("@")[0],
        password_hash=hash_password(payload.password),
        role=Role.ADMIN if first_account else Role.USER,
        last_login_at=utcnow(),
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    audit.record(
        db, action="auth.register", user=user, detail={"role": user.role}, request=request
    )
    token, expires_in = create_access_token(user)
    return TokenResponse(access_token=token, expires_in=expires_in, user=UserOut.model_validate(user))


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    enforce(login_limiter, identity(request))

    user = db.scalar(select(User).where(User.email == payload.email))

    # Same rejection whether the account is unknown or the password is wrong,
    # so the endpoint cannot be used to enumerate accounts.
    if user is None or not verify_password(payload.password, user.password_hash):
        audit.record(
            db,
            action="auth.login",
            user=user,
            actor_email=payload.email,
            outcome="failure",
            detail={"reason": "invalid_credentials"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Email or password is incorrect.",
        )

    if user.is_suspended:
        audit.record(
            db,
            action="auth.login",
            user=user,
            outcome="failure",
            detail={"reason": "suspended"},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been suspended. Contact an administrator.",
        )

    # Upgrade a hash still stored under the pre-2.0 scheme, now that the
    # password has been proven correct.  Silent, and happens once per account.
    if needs_rehash(payload.password, user.password_hash):
        user.password_hash = hash_password(payload.password)
        logger.info("upgraded stored password hash for %s", user.email)

    user.last_login_at = utcnow()
    db.commit()
    db.refresh(user)

    audit.record(db, action="auth.login", user=user, request=request)
    token, expires_in = create_access_token(user)
    return TokenResponse(access_token=token, expires_in=expires_in, user=UserOut.model_validate(user))


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(current_user)):
    return UserOut.model_validate(user)
