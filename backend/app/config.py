"""Runtime configuration.

Every value can be overridden with an environment variable so the same source
runs unchanged on Windows and Linux (NF.1).
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ[name])
    except (KeyError, ValueError):
        return default


class Settings:
    # --- identity -------------------------------------------------------
    APP_NAME = "Secure File Encryption and Decryption System"
    APP_VERSION = "1.0.0"

    # --- storage --------------------------------------------------------
    DATA_DIR = Path(os.environ.get("SFE_DATA_DIR", BASE_DIR / "data"))
    STORAGE_DIR = DATA_DIR / "containers"
    DATABASE_URL = os.environ.get("SFE_DATABASE_URL", f"sqlite:///{DATA_DIR / 'app.db'}")

    # --- auth -----------------------------------------------------------
    # A generated secret means tokens do not survive a restart, which is safe
    # by default.  Set SFE_SECRET_KEY in deployment to keep sessions alive.
    SECRET_KEY = os.environ.get("SFE_SECRET_KEY", secrets.token_urlsafe(48))
    JWT_ALGORITHM = "HS256"
    TOKEN_TTL_MINUTES = _int("SFE_TOKEN_TTL_MINUTES", 720)
    BCRYPT_ROUNDS = _int("SFE_BCRYPT_ROUNDS", 12)
    MIN_PASSWORD_LENGTH = 8

    # --- limits (SRS 3.4 Design Constraints) ----------------------------
    MAX_UPLOAD_BYTES = _int("SFE_MAX_UPLOAD_BYTES", 50 * 1024 * 1024)  # 50 MB
    SEGMENT_SIZE = _int("SFE_SEGMENT_SIZE", 1024 * 1024)               # 1 MiB
    INLINE_THRESHOLD_BYTES = _int("SFE_INLINE_THRESHOLD", 8 * 1024 * 1024)
    RETENTION_DAYS = _int("SFE_RETENTION_DAYS", 7)
    CHUNK_SIZE = 1024 * 1024

    # Accepted plaintext inputs (F.1).  Enforced in the browser; the server
    # only ever sees opaque containers.
    ALLOWED_EXTENSIONS = ["txt", "png", "jpg", "jpeg", "pdf"]
    ALLOWED_MIME_TYPES = [
        "text/plain",
        "image/png",
        "image/jpeg",
        "application/pdf",
    ]

    # --- client-side KDF parameters (design doc 2.2) --------------------
    ARGON2_MEMORY_KIB = _int("SFE_ARGON2_MEMORY_KIB", 65536)  # 64 MiB
    ARGON2_ITERATIONS = _int("SFE_ARGON2_ITERATIONS", 3)
    ARGON2_PARALLELISM = _int("SFE_ARGON2_PARALLELISM", 1)
    PBKDF2_ITERATIONS = _int("SFE_PBKDF2_ITERATIONS", 210000)

    # --- rate limiting (3.2.4) ------------------------------------------
    RATE_LIMIT_REQUESTS = _int("SFE_RATE_LIMIT_REQUESTS", 120)
    RATE_LIMIT_WINDOW_SECONDS = _int("SFE_RATE_LIMIT_WINDOW", 60)
    LOGIN_RATE_LIMIT = _int("SFE_LOGIN_RATE_LIMIT", 10)

    # --- bootstrap administrator ----------------------------------------
    ADMIN_EMAIL = os.environ.get("SFE_ADMIN_EMAIL", "admin@example.com")
    ADMIN_PASSWORD = os.environ.get("SFE_ADMIN_PASSWORD", "Admin@12345")

    CORS_ORIGINS = [
        o for o in os.environ.get("SFE_CORS_ORIGINS", "").split(",") if o
    ]


settings = Settings()
settings.DATA_DIR.mkdir(parents=True, exist_ok=True)
settings.STORAGE_DIR.mkdir(parents=True, exist_ok=True)
