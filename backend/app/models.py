"""ORM models.

Note what is deliberately absent: there is no column anywhere in this file for
a key, a passphrase, or derived key material (C.6 / NF.3).  The server stores
opaque containers and metadata about operations, nothing more.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .config import settings
from .database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return uuid.uuid4().hex


class Role:
    USER = "user"
    ADMIN = "admin"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    display_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default=Role.USER)
    is_suspended: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    containers: Mapped[list["Container"]] = relationship(
        back_populates="owner", cascade="all, delete-orphan"
    )
    operations: Mapped[list["Operation"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )

    @property
    def is_admin(self) -> bool:
        return self.role == Role.ADMIN


class Container(Base):
    """An encrypted artefact.  The server never inspects the bytes."""

    __tablename__ = "containers"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    owner_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    storage_path: Mapped[str] = mapped_column(String(512), nullable=False)
    container_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # Descriptive header fields echoed by the client purely so the history view
    # can show them.  They are not trusted and are never used to decrypt.
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="AES-256-GCM")
    kdf: Mapped[str] = mapped_column(String(32), nullable=False, default="Argon2id")
    segment_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    plaintext_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_deleted: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    deleted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    owner: Mapped[User] = relationship(back_populates="containers")

    @staticmethod
    def default_expiry() -> datetime:
        return utcnow() + timedelta(days=settings.RETENTION_DAYS)

    @property
    def is_expired(self) -> bool:
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires <= utcnow()


class Operation(Base):
    """One encrypt/decrypt/transfer event, with its metrics (F.10)."""

    __tablename__ = "operations"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True, nullable=False
    )
    container_id: Mapped[str | None] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(16), nullable=False)          # encrypt|decrypt
    algorithm: Mapped[str] = mapped_column(String(32), nullable=False, default="AES-256-GCM")
    kdf: Mapped[str] = mapped_column(String(32), nullable=False, default="Argon2id")
    filename: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    file_type: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    input_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    output_size: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    duration_ms: Mapped[float] = mapped_column(nullable=False, default=0.0)
    peak_memory_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    segment_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    error_code: Mapped[str | None] = mapped_column(String(64))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)

    user: Mapped[User] = relationship(back_populates="operations")


class AuditLog(Base):
    """Append-only record of everything that happened (C.5 / F.14)."""

    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[str | None] = mapped_column(String(32), index=True)
    actor_email: Mapped[str] = mapped_column(String(255), nullable=False, default="anonymous")
    action: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    outcome: Mapped[str] = mapped_column(String(16), nullable=False, default="success")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow, index=True)


Index("ix_operations_user_created", Operation.user_id, Operation.created_at)
Index("ix_containers_owner_created", Container.owner_id, Container.created_at)
