"""0.4 Container Storage & Retrieval (F.7, F.11).

The server accepts finished containers, stores them against the owning
account, and hands them back on request.  It never inspects the bytes, and it
could not decrypt them if it wanted to.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile, status
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .. import audit, storage
from ..config import settings
from ..database import get_db
from ..models import Container, User, utcnow
from ..ratelimit import api_limiter, enforce, identity
from ..schemas import ContainerOut, ContainerPage, PageMeta, SimpleMessage
from ..security import current_user

router = APIRouter(prefix="/api/containers", tags=["containers"])

MAGIC = b"ENCV"
HEADER_SIZE = 104


def _out(container: Container) -> ContainerOut:
    data = ContainerOut.model_validate(container)
    data.is_expired = container.is_expired
    return data


def _owned_or_403(db: Session, container_id: str, user: User, request: Request) -> Container:
    """Fetch a container the caller is entitled to.

    A container belonging to someone else returns 403, not 404, and the attempt
    is logged (NF.7).  Hiding the existence of the row would be a smaller
    signal, but the requirement asks for the refusal to be explicit.
    """
    container = db.get(Container, container_id)
    if container is None or container.is_deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such file.")
    if container.owner_id != user.id and not user.is_admin:
        audit.record(
            db,
            action="container.access_denied",
            user=user,
            outcome="failure",
            detail={"container_id": container_id, "owner_id": container.owner_id},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This file belongs to another account.",
        )
    return container


@router.post("", response_model=ContainerOut, status_code=status.HTTP_201_CREATED)
def upload_container(
    request: Request,
    file: UploadFile = File(...),
    algorithm: str = Form("AES-256-GCM"),
    kdf: str = Form("Argon2id"),
    segment_count: int = Form(0),
    plaintext_size: int = Form(0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    enforce(api_limiter, identity(request))

    # A cheap structural check.  It confirms the client sent a container of the
    # expected shape; it says nothing about whether the contents are valid,
    # because only the holder of the passphrase can know that.
    head = file.file.read(HEADER_SIZE)
    if len(head) < HEADER_SIZE or not head.startswith(MAGIC):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="That file is not a container produced by this application.",
        )
    file.file.seek(0)

    container = Container(
        owner_id=user.id,
        filename=(file.filename or "container.enc")[:255],
        size_bytes=0,
        storage_path="",
        container_sha256="",
        algorithm=algorithm[:32],
        kdf=kdf[:32],
        segment_count=max(0, segment_count),
        plaintext_size=max(0, plaintext_size),
        expires_at=Container.default_expiry(),
    )
    # The id is needed to choose a path, so generate the row first.
    db.add(container)
    db.flush()

    try:
        path, size, sha = storage.save_stream(container.id, file.file)
    except storage.UploadTooLarge as exc:
        db.rollback()
        audit.record(
            db,
            action="container.upload",
            user=user,
            outcome="failure",
            detail={"reason": "too_large", "limit": exc.limit},
            request=request,
        )
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE,
            detail=f"That file is larger than the {exc.limit // (1024 * 1024)} MB limit.",
        ) from None
    except OSError:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="The file could not be stored. Please try again.",
        ) from None

    container.storage_path = path
    container.size_bytes = size
    container.container_sha256 = sha
    db.commit()
    db.refresh(container)

    audit.record(
        db,
        action="container.upload",
        user=user,
        detail={"container_id": container.id, "size_bytes": size},
        request=request,
    )
    return _out(container)


@router.get("", response_model=ContainerPage)
def list_containers(
    request: Request,
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    """List the caller's own containers, newest first."""
    enforce(api_limiter, identity(request))

    condition = (Container.owner_id == user.id) & (Container.is_deleted == False)  # noqa: E712
    total = db.scalar(select(func.count()).select_from(Container).where(condition)) or 0
    rows = db.scalars(
        select(Container)
        .where(condition)
        .order_by(Container.created_at.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ContainerPage(
        items=[_out(row) for row in rows],
        meta=PageMeta(total=total, limit=limit, offset=offset),
    )


@router.get("/{container_id}", response_model=ContainerOut)
def get_container(
    container_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    enforce(api_limiter, identity(request))
    return _out(_owned_or_403(db, container_id, user, request))


@router.get("/{container_id}/download")
def download_container(
    container_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    enforce(api_limiter, identity(request))
    container = _owned_or_403(db, container_id, user, request)

    if container.is_expired:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="This file passed its retention period and has been removed.",
        )
    if not storage.exists(container.storage_path):
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail="The stored copy of this file is no longer available.",
        )

    audit.record(
        db,
        action="container.download",
        user=user,
        detail={"container_id": container.id},
        request=request,
    )
    return StreamingResponse(
        storage.open_stream(container.storage_path),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition": f'attachment; filename="{container.filename}"',
            "Content-Length": str(container.size_bytes),
            "X-Container-Sha256": container.container_sha256,
        },
    )


@router.delete("/{container_id}", response_model=SimpleMessage)
def delete_container(
    container_id: str,
    request: Request,
    db: Session = Depends(get_db),
    user: User = Depends(current_user),
):
    enforce(api_limiter, identity(request))
    container = _owned_or_403(db, container_id, user, request)

    storage.delete(container.storage_path)
    container.is_deleted = True
    container.deleted_at = utcnow()
    db.commit()

    audit.record(
        db,
        action="container.delete",
        user=user,
        detail={"container_id": container.id},
        request=request,
    )
    return SimpleMessage(message="The file and its stored copy have been removed.")
