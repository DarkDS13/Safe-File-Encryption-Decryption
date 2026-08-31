"""0.7 System Administration (F.13).

Nothing here can reveal file content: the server holds no key material, so
there is no administrative path to a user's plaintext even in principle.
"""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, storage
from ..database import get_db
from ..models import AuditLog, Container, Operation, Role, User, utcnow
from ..ratelimit import api_limiter, enforce, identity
from ..schemas import (
    AuditOut,
    AuditPage,
    PageMeta,
    PurgeResult,
    SystemStats,
    UserOut,
    UserPage,
)
from ..security import current_admin

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users", response_model=UserPage)
def list_users(
    request: Request,
    q: str | None = Query(None, max_length=255),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    enforce(api_limiter, identity(request))

    stmt = select(User)
    count_stmt = select(func.count()).select_from(User)
    if q:
        pattern = f"%{q.strip().lower()}%"
        stmt = stmt.where(User.email.like(pattern))
        count_stmt = count_stmt.where(User.email.like(pattern))

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(User.created_at.desc()).limit(limit).offset(offset)
    ).all()
    return UserPage(
        items=[UserOut.model_validate(r) for r in rows],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


def _set_suspended(
    db: Session, request: Request, admin: User, user_id: str, suspended: bool
) -> UserOut:
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such account.")
    if user.id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="You cannot suspend your own administrator account.",
        )

    user.is_suspended = suspended
    db.commit()
    db.refresh(user)

    audit.record(
        db,
        action="admin.suspend" if suspended else "admin.reinstate",
        user=admin,
        detail={"target_user_id": user.id, "target_email": user.email},
        request=request,
    )
    return UserOut.model_validate(user)


@router.post("/users/{user_id}/suspend", response_model=UserOut)
def suspend_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    enforce(api_limiter, identity(request))
    return _set_suspended(db, request, admin, user_id, True)


@router.post("/users/{user_id}/reinstate", response_model=UserOut)
def reinstate_user(
    user_id: str,
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    enforce(api_limiter, identity(request))
    return _set_suspended(db, request, admin, user_id, False)


@router.get("/audit", response_model=AuditPage)
def read_audit_log(
    request: Request,
    action: str | None = Query(None, max_length=64),
    outcome: str | None = Query(None, pattern="^(success|failure)$"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    enforce(api_limiter, identity(request))

    stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action)
        count_stmt = count_stmt.where(AuditLog.action == action)
    if outcome:
        stmt = stmt.where(AuditLog.outcome == outcome)
        count_stmt = count_stmt.where(AuditLog.outcome == outcome)

    total = db.scalar(count_stmt) or 0
    rows = db.scalars(
        stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)
    ).all()
    return AuditPage(
        items=[AuditOut.model_validate(r) for r in rows],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.get("/stats", response_model=SystemStats)
def system_stats(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    enforce(api_limiter, identity(request))

    now = utcnow()
    live = Container.is_deleted == False  # noqa: E712

    def count(model, condition=None) -> int:
        stmt = select(func.count()).select_from(model)
        if condition is not None:
            stmt = stmt.where(condition)
        return db.scalar(stmt) or 0

    def total_bytes(kind: str) -> int:
        return int(
            db.scalar(
                select(func.coalesce(func.sum(Operation.input_size), 0)).where(
                    (Operation.kind == kind) & (Operation.status == "success")
                )
            )
            or 0
        )

    operations_total = count(Operation)
    succeeded = count(Operation, Operation.status == "success")
    avg_ms = float(
        db.scalar(select(func.coalesce(func.avg(Operation.duration_ms), 0.0))) or 0.0
    )
    processed = int(
        db.scalar(
            select(func.coalesce(func.sum(Operation.input_size), 0)).where(
                Operation.status == "success"
            )
        )
        or 0
    )
    total_ms = float(
        db.scalar(
            select(func.coalesce(func.sum(Operation.duration_ms), 0.0)).where(
                Operation.status == "success"
            )
        )
        or 0.0
    )
    throughput = (processed / (1024 * 1024)) / (total_ms / 1000) if total_ms > 0 else 0.0

    return SystemStats(
        users_total=count(User),
        users_active=count(User, User.is_suspended == False),  # noqa: E712
        users_suspended=count(User, User.is_suspended == True),  # noqa: E712
        containers_total=count(Container, live),
        containers_expired=count(Container, live & (Container.expires_at <= now)),
        stored_bytes=storage.disk_usage_bytes(),
        operations_total=operations_total,
        operations_succeeded=succeeded,
        operations_failed=operations_total - succeeded,
        bytes_encrypted=total_bytes("encrypt"),
        bytes_decrypted=total_bytes("decrypt"),
        average_duration_ms=round(avg_ms, 2),
        average_throughput_mbps=round(throughput, 2),
        operations_last_24h=count(Operation, Operation.created_at >= now - timedelta(hours=24)),
    )


@router.post("/purge", response_model=PurgeResult)
def purge_expired(
    request: Request,
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    """Remove containers whose retention period has passed (F.11, F.13)."""
    enforce(api_limiter, identity(request))

    now = utcnow()
    expired = db.scalars(
        select(Container).where(
            (Container.is_deleted == False) & (Container.expires_at <= now)  # noqa: E712
        )
    ).all()

    freed = 0
    for container in expired:
        if storage.exists(container.storage_path):
            freed += container.size_bytes
        storage.delete(container.storage_path)
        container.is_deleted = True
        container.deleted_at = now
    db.commit()

    audit.record(
        db,
        action="admin.purge",
        user=admin,
        detail={"purged": len(expired), "freed_bytes": freed},
        request=request,
    )
    return PurgeResult(purged=len(expired), freed_bytes=freed)


@router.get("/containers")
def list_all_containers(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    admin: User = Depends(current_admin),
):
    """Container metadata across all accounts.

    Filenames, sizes and timestamps only — there is no endpoint, here or
    anywhere, that returns container bytes belonging to another account.
    """
    enforce(api_limiter, identity(request))

    live = Container.is_deleted == False  # noqa: E712
    total = db.scalar(select(func.count()).select_from(Container).where(live)) or 0
    rows = db.execute(
        select(Container, User.email)
        .join(User, User.id == Container.owner_id)
        .where(live)
        .order_by(Container.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return {
        "items": [
            {
                "id": c.id,
                "filename": c.filename,
                "owner_email": email,
                "size_bytes": c.size_bytes,
                "algorithm": c.algorithm,
                "created_at": c.created_at,
                "expires_at": c.expires_at,
                "is_expired": c.is_expired,
            }
            for c, email in rows
        ],
        "meta": {"total": total, "limit": limit, "offset": offset},
    }
