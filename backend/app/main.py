"""Application entrypoint.

Mounts the JSON API and serves the browser client from the same origin, so a
single `uvicorn` process is the whole deployment.
"""
from __future__ import annotations

import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select
from starlette.exceptions import HTTPException as StarletteHTTPException

from . import audit
from .config import BASE_DIR, settings
from .database import SessionLocal, init_db
from .models import Role, User
from .routers import admin, auth, containers, operations
from .schemas import ClientConfig
from .security import hash_password

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
logger = logging.getLogger("sfe")

FRONTEND_DIR = BASE_DIR / "frontend"

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Zero-knowledge file encryption. Files are encrypted and decrypted in "
        "the browser with AES-256-GCM under an Argon2id-derived key; this "
        "server stores opaque containers and never sees a key or a passphrase."
    ),
)

if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Content-Disposition", "X-Container-Sha256"],
    )


# --------------------------------------------------------------------------
# lifecycle
# --------------------------------------------------------------------------
def seed_admin() -> None:
    """Create the bootstrap administrator if no account exists yet."""
    with SessionLocal() as db:
        if db.scalar(select(User).limit(1)) is not None:
            return
        db.add(
            User(
                email=settings.ADMIN_EMAIL.lower(),
                display_name="Administrator",
                password_hash=hash_password(settings.ADMIN_PASSWORD),
                role=Role.ADMIN,
            )
        )
        db.commit()
        logger.info("Created bootstrap administrator %s", settings.ADMIN_EMAIL)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    seed_admin()
    logger.info("%s %s ready", settings.APP_NAME, settings.APP_VERSION)
    yield


app.router.lifespan_context = lifespan


# --------------------------------------------------------------------------
# middleware
# --------------------------------------------------------------------------
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    started = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - started) * 1000
    response.headers["X-Response-Time-Ms"] = f"{elapsed_ms:.2f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    # 'wasm-unsafe-eval' is here because the key-derivation worker instantiates
    # a WebAssembly module; nothing else in the client needs it.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
        "connect-src 'self'; worker-src 'self' blob:; frame-ancestors 'none'"
    )
    return response


# --------------------------------------------------------------------------
# error handling — plain language, no internals (NF.8, NF.9)
# --------------------------------------------------------------------------
@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request: Request, exc: StarletteHTTPException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"status": exc.status_code, "message": exc.detail}},
        headers=getattr(exc, "headers", None),
    )


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError):
    first = exc.errors()[0] if exc.errors() else {}
    field = ".".join(str(p) for p in first.get("loc", [])[1:]) or "request"
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={
            "error": {
                "status": 422,
                "message": f"The field '{field}' is missing or invalid.",
                "field": field,
            }
        },
    )


@app.exception_handler(Exception)
def unhandled_exception_handler(request: Request, exc: Exception):
    """A malformed request must not take the server down (NF.9)."""
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    try:
        with SessionLocal() as db:
            audit.record(
                db,
                action="server.error",
                outcome="failure",
                detail={"path": request.url.path, "type": type(exc).__name__},
                request=request,
            )
    except Exception:  # pragma: no cover - never let logging mask the response
        logger.exception("Failed to write audit entry for unhandled error")
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "status": 500,
                "message": "Something went wrong on the server. Please try again.",
            }
        },
    )


# --------------------------------------------------------------------------
# routes
# --------------------------------------------------------------------------
app.include_router(auth.router)
app.include_router(containers.router)
app.include_router(operations.router)
app.include_router(admin.router)


@app.get("/api/health", tags=["meta"])
def health():
    return {"status": "ok", "version": settings.APP_VERSION}


@app.get("/api/config", response_model=ClientConfig, tags=["meta"])
def client_config():
    """Limits and KDF parameters, so the browser has one source of truth."""
    return ClientConfig(
        app_name=settings.APP_NAME,
        version=settings.APP_VERSION,
        max_upload_bytes=settings.MAX_UPLOAD_BYTES,
        segment_size=settings.SEGMENT_SIZE,
        inline_threshold_bytes=settings.INLINE_THRESHOLD_BYTES,
        retention_days=settings.RETENTION_DAYS,
        allowed_extensions=settings.ALLOWED_EXTENSIONS,
        allowed_mime_types=settings.ALLOWED_MIME_TYPES,
        argon2_memory_kib=settings.ARGON2_MEMORY_KIB,
        argon2_iterations=settings.ARGON2_ITERATIONS,
        argon2_parallelism=settings.ARGON2_PARALLELISM,
        pbkdf2_iterations=settings.PBKDF2_ITERATIONS,
        min_password_length=settings.MIN_PASSWORD_LENGTH,
    )


# --------------------------------------------------------------------------
# static client
# --------------------------------------------------------------------------
if FRONTEND_DIR.is_dir():
    app.mount("/js", StaticFiles(directory=FRONTEND_DIR / "js"), name="js")
    app.mount("/css", StaticFiles(directory=FRONTEND_DIR / "css"), name="css")

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(FRONTEND_DIR / "index.html")

    @app.get("/admin", include_in_schema=False)
    def admin_page():
        return FileResponse(FRONTEND_DIR / "admin.html")
