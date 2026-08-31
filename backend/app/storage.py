"""Filesystem storage for encrypted containers.

Containers are written outside the database (3.2.3) and are opaque to this
process.  Writes stream in fixed-size chunks so resident memory stays flat no
matter how large the upload is (C.4 / NF.5).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from pathlib import Path
from typing import BinaryIO, Iterator

from .config import settings


class UploadTooLarge(Exception):
    def __init__(self, limit: int) -> None:
        super().__init__(f"upload exceeds {limit} bytes")
        self.limit = limit


def _path_for(container_id: str) -> Path:
    # Two levels of fan-out keeps directory listings small.
    sub = settings.STORAGE_DIR / container_id[:2] / container_id[2:4]
    sub.mkdir(parents=True, exist_ok=True)
    return sub / f"{container_id}.enc"


def save_stream(container_id: str, source: BinaryIO) -> tuple[str, int, str]:
    """Stream `source` to disk.

    Returns (relative_path, size_bytes, sha256_hex).  A partial write is
    removed rather than left behind (NF.9): the bytes land in a temporary file
    first and are only moved into place once the whole body has arrived.
    """
    target = _path_for(container_id)
    digest = hashlib.sha256()
    size = 0
    tmp_fd, tmp_name = tempfile.mkstemp(dir=str(target.parent), suffix=".part")
    try:
        with os.fdopen(tmp_fd, "wb") as tmp:
            while True:
                chunk = source.read(settings.CHUNK_SIZE)
                if not chunk:
                    break
                size += len(chunk)
                if size > settings.MAX_UPLOAD_BYTES:
                    raise UploadTooLarge(settings.MAX_UPLOAD_BYTES)
                digest.update(chunk)
                tmp.write(chunk)
        shutil.move(tmp_name, target)
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return str(target.relative_to(settings.DATA_DIR)), size, digest.hexdigest()


def open_stream(relative_path: str) -> Iterator[bytes]:
    absolute = resolve(relative_path)
    with absolute.open("rb") as handle:
        while True:
            chunk = handle.read(settings.CHUNK_SIZE)
            if not chunk:
                break
            yield chunk


def resolve(relative_path: str) -> Path:
    """Resolve a stored path, refusing anything that escapes the data directory."""
    root = settings.DATA_DIR.resolve()
    absolute = (root / relative_path).resolve()
    if not absolute.is_relative_to(root):
        raise ValueError("resolved path escapes the storage root")
    return absolute


def delete(relative_path: str) -> bool:
    try:
        absolute = resolve(relative_path)
    except ValueError:
        return False
    if absolute.exists():
        absolute.unlink()
        return True
    return False


def exists(relative_path: str) -> bool:
    try:
        return resolve(relative_path).exists()
    except ValueError:
        return False


def disk_usage_bytes() -> int:
    total = 0
    for path in settings.STORAGE_DIR.rglob("*.enc"):
        try:
            total += path.stat().st_size
        except OSError:
            continue
    return total
