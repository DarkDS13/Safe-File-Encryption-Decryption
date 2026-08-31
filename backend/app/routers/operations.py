"""0.6 Metrics & Audit Logging (F.10, F.14) — the user-facing half."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit
from ..database import get_db
from ..models import Operation, User
from ..ratelimit import api_limiter, enforce, identity
from ..schemas import OperationCreate, OperationOut, OperationPage, PageMeta
from ..security import current_user

router = APIRouter(prefix="/api/operations", tags=["operations"])


@router.post("", response_model=OperationOut, status_code=status.HTTP_201_CREATED)
def record_operation(
    payload: OperationCreate,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Store the metrics the browser measured for one completed operation.

    The operation itself happened in the browser, so these figures are reported
    rather than measured here.  Failures are recorded too — an audit log that
    only contains successes is not an audit log (F.14).
    """
    enforce(api_limiter, identity(request))

    operation = Operation(
        user_id=user.id,
        container_id=payload.container_id,
        kind=payload.kind,
        status=payload.status,
        algorithm=payload.algorithm,
        kdf=payload.kdf,
        filename=payload.filename[:255],
        file_type=payload.file_type[:32],
        input_size=payload.input_size,
        output_size=payload.output_size,
        duration_ms=payload.duration_ms,
        peak_memory_bytes=payload.peak_memory_bytes,
        segment_count=payload.segment_count,
        error_code=payload.error_code,
    )
    db.add(operation)
    db.commit()
    db.refresh(operation)

    audit.record(
        db,
        action=f"operation.{payload.kind}",
        user=user,
        outcome=payload.status,
        detail={
            "operation_id": operation.id,
            "algorithm": payload.algorithm,
            "input_size": payload.input_size,
            "duration_ms": round(payload.duration_ms, 2),
            "error_code": payload.error_code,
        },
        request=request,
    )
    return OperationOut.model_validate(operation)


@router.get("", response_model=OperationPage)
def my_operations(
    request: Request,
    kind: str | None = Query(None, pattern="^(encrypt|decrypt)$"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Return the caller's own history and nothing else."""
    enforce(api_limiter, identity(request))

    condition = Operation.user_id == user.id
    if kind:
        condition = condition & (Operation.kind == kind)

    total = db.scalar(select(func.count()).select_from(Operation).where(condition)) or 0
    rows = db.scalars(
        select(Operation)
        .where(condition)
        .order_by(Operation.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return OperationPage(
        items=[OperationOut.model_validate(r) for r in rows],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.get("/summary")
def my_summary(
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """Aggregate figures for the caller's own dashboard."""
    enforce(api_limiter, identity(request))

    base = select(Operation).where(Operation.user_id == user.id).subquery()
    row = db.execute(
        select(
            func.count(base.c.id),
            func.coalesce(func.sum(base.c.input_size), 0),
            func.coalesce(func.avg(base.c.duration_ms), 0.0),
        )
    ).one()
    succeeded = db.scalar(
        select(func.count())
        .select_from(Operation)
        .where((Operation.user_id == user.id) & (Operation.status == "success"))
    ) or 0
    total, total_bytes, avg_ms = row
    return {
        "operations_total": total or 0,
        "operations_succeeded": succeeded,
        "operations_failed": (total or 0) - succeeded,
        "bytes_processed": int(total_bytes or 0),
        "average_duration_ms": round(float(avg_ms or 0.0), 2),
    }
