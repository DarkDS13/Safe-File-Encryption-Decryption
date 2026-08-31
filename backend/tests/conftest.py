"""Shared fixtures.

Each test module gets its own database and storage directory, so tests do not
interfere with one another or with a running development server.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Configuration is read at import time, so the environment has to be set before
# anything from `app` is imported.
_TMP = tempfile.mkdtemp(prefix="sfe-tests-")
os.environ.setdefault("SFE_DATA_DIR", _TMP)
os.environ.setdefault("SFE_SECRET_KEY", "test-secret-key-not-for-production")
os.environ.setdefault("SFE_BCRYPT_ROUNDS", "4")        # keep the suite quick
os.environ.setdefault("SFE_RATE_LIMIT_REQUESTS", "10000")
os.environ.setdefault("SFE_LOGIN_RATE_LIMIT", "10000")
os.environ.setdefault("SFE_ADMIN_EMAIL", "root@example.com")
os.environ.setdefault("SFE_ADMIN_PASSWORD", "RootPass123")

from fastapi.testclient import TestClient  # noqa: E402

from app.config import settings  # noqa: E402
from app.database import Base, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.ratelimit import api_limiter, login_limiter  # noqa: E402


@pytest.fixture()
def client():
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    api_limiter.reset()
    login_limiter.reset()
    with TestClient(app) as test_client:
        yield test_client


def auth_headers(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin(client):
    """The bootstrap administrator created at startup."""
    response = client.post(
        "/api/auth/login",
        json={"email": settings.ADMIN_EMAIL, "password": settings.ADMIN_PASSWORD},
    )
    assert response.status_code == 200, response.text
    data = response.json()
    return {"token": data["access_token"], "user": data["user"], "headers": auth_headers(data["access_token"])}


@pytest.fixture()
def user(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "alice@example.com", "password": "Alice12345", "display_name": "Alice"},
    )
    assert response.status_code == 201, response.text
    data = response.json()
    return {"token": data["access_token"], "user": data["user"], "headers": auth_headers(data["access_token"])}


@pytest.fixture()
def other_user(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "bob@example.com", "password": "Bob1234567", "display_name": "Bob"},
    )
    assert response.status_code == 201, response.text
    data = response.json()
    return {"token": data["access_token"], "user": data["user"], "headers": auth_headers(data["access_token"])}


def make_container(size: int = 4096) -> bytes:
    """A byte string shaped like a real container: 104-byte header, then body.

    The server only checks the magic bytes and the header length, because it
    cannot and must not interpret the rest.
    """
    header = bytearray(104)
    header[0:4] = b"ENCV"
    header[4] = 2      # format version
    header[5] = 1      # Argon2id
    header[6] = 1      # AES-256-GCM
    return bytes(header) + os.urandom(size)
