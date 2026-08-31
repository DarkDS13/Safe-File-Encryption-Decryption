"""Request and response bodies.

No schema in this file has a field for a key or a passphrase, and none ever
will: the server has no use for either (NF.3).
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class RegisterRequest(BaseModel):
    email: str = Field(min_length=3, max_length=255)
    password: str = Field(min_length=1, max_length=256)
    display_name: str = Field(default="", max_length=120)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class LoginRequest(BaseModel):
    email: str = Field(max_length=255)
    password: str = Field(max_length=256)

    @field_validator("email")
    @classmethod
    def normalise_email(cls, value: str) -> str:
        return value.strip().lower()


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    display_name: str
    role: str
    is_suspended: bool
    created_at: datetime
    last_login_at: datetime | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserOut


class ContainerOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    filename: str
    size_bytes: int
    algorithm: str
    kdf: str
    segment_count: int
    plaintext_size: int
    container_sha256: str
    created_at: datetime
    expires_at: datetime
    is_expired: bool = False


class OperationCreate(BaseModel):
    """Metrics reported by the browser once an operation finishes (F.10)."""

    kind: Literal["encrypt", "decrypt"]
    status: Literal["success", "failure"] = "success"
    algorithm: str = Field(default="AES-256-GCM", max_length=32)
    kdf: str = Field(default="Argon2id", max_length=32)
    filename: str = Field(default="", max_length=255)
    file_type: str = Field(default="", max_length=32)
    input_size: int = Field(default=0, ge=0)
    output_size: int = Field(default=0, ge=0)
    duration_ms: float = Field(default=0.0, ge=0)
    peak_memory_bytes: int = Field(default=0, ge=0)
    segment_count: int = Field(default=0, ge=0)
    error_code: str | None = Field(default=None, max_length=64)
    container_id: str | None = Field(default=None, max_length=32)


class OperationOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    kind: str
    status: str
    algorithm: str
    kdf: str
    filename: str
    file_type: str
    input_size: int
    output_size: int
    duration_ms: float
    peak_memory_bytes: int
    segment_count: int
    error_code: str | None
    container_id: str | None
    created_at: datetime


class AuditOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: str | None
    actor_email: str
    action: str
    outcome: str
    detail: str
    ip_address: str
    created_at: datetime


class PageMeta(BaseModel):
    total: int
    limit: int
    offset: int


class ContainerPage(BaseModel):
    items: list[ContainerOut]
    meta: PageMeta


class OperationPage(BaseModel):
    items: list[OperationOut]
    meta: PageMeta


class AuditPage(BaseModel):
    items: list[AuditOut]
    meta: PageMeta


class UserPage(BaseModel):
    items: list[UserOut]
    meta: PageMeta


class SystemStats(BaseModel):
    users_total: int
    users_active: int
    users_suspended: int
    containers_total: int
    containers_expired: int
    stored_bytes: int
    operations_total: int
    operations_succeeded: int
    operations_failed: int
    bytes_encrypted: int
    bytes_decrypted: int
    average_duration_ms: float
    average_throughput_mbps: float
    operations_last_24h: int


class PurgeResult(BaseModel):
    purged: int
    freed_bytes: int


class SimpleMessage(BaseModel):
    message: str


class ClientConfig(BaseModel):
    """Everything the browser needs to configure itself, served from one place."""

    app_name: str
    version: str
    max_upload_bytes: int
    segment_size: int
    inline_threshold_bytes: int
    retention_days: int
    allowed_extensions: list[str]
    allowed_mime_types: list[str]
    argon2_memory_kib: int
    argon2_iterations: int
    argon2_parallelism: int
    pbkdf2_iterations: int
    min_password_length: int
