"""Unit tests for the storage layer (module 0.4).

These call `storage` directly rather than through HTTP, so they are unit tests
of the file handling itself: chunking, digests, cleanup, and path safety.
"""
from __future__ import annotations

import io
import os

import pytest

from app import storage
from app.config import settings


def test_save_stream_returns_size_and_digest():
    import hashlib

    payload = os.urandom(5000)
    path, size, digest = storage.save_stream("aabbccdd" + "0" * 24, io.BytesIO(payload))

    assert size == len(payload)
    assert digest == hashlib.sha256(payload).hexdigest()
    assert storage.exists(path)


def test_saved_bytes_are_byte_identical_when_read_back():
    payload = os.urandom(300_000)
    path, _, _ = storage.save_stream("bb" + "1" * 30, io.BytesIO(payload))
    assert b"".join(storage.open_stream(path)) == payload


def test_a_file_larger_than_one_chunk_is_written_correctly():
    """Exercises the chunk loop boundary rather than a single read."""
    payload = os.urandom(settings.CHUNK_SIZE * 2 + 137)
    path, size, _ = storage.save_stream("cc" + "2" * 30, io.BytesIO(payload))
    assert size == len(payload)
    assert b"".join(storage.open_stream(path)) == payload


def test_an_oversize_stream_is_refused_and_leaves_nothing_behind(monkeypatch):
    """NF.9: an interrupted write must not leave a partial file."""
    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 4096)
    with pytest.raises(storage.UploadTooLarge):
        storage.save_stream("dd" + "3" * 30, io.BytesIO(os.urandom(20_000)))

    leftovers = list(settings.STORAGE_DIR.rglob("*.part"))
    assert leftovers == [], f"temporary files were left behind: {leftovers}"


def test_a_failing_source_leaves_nothing_behind():
    class Exploding(io.RawIOBase):
        def read(self, _size=-1):
            raise OSError("simulated disk failure")

    with pytest.raises(OSError):
        storage.save_stream("ee" + "4" * 30, Exploding())

    assert list(settings.STORAGE_DIR.rglob("*.part")) == []


@pytest.mark.parametrize(
    "hostile",
    [
        "../../../etc/passwd",
        "..%2F..%2Fetc/passwd",
        "containers/../../../../etc/passwd",
        "/etc/passwd",
    ],
)
def test_paths_that_escape_the_storage_root_are_refused(hostile):
    """Defence in depth: paths are database-generated, but the guard must hold."""
    try:
        resolved = storage.resolve(hostile)
    except ValueError:
        return   # refused, which is the desired outcome
    # If it resolved at all, it must still be inside the data directory.
    assert resolved.is_relative_to(settings.DATA_DIR.resolve())


def test_delete_removes_the_file_and_is_safe_to_repeat():
    path, _, _ = storage.save_stream("ff" + "5" * 30, io.BytesIO(b"hello"))
    assert storage.delete(path) is True
    assert storage.exists(path) is False
    assert storage.delete(path) is False      # second delete is a no-op, not an error


def test_containers_are_spread_across_subdirectories():
    """Two levels of fan-out keep directory listings small."""
    container_id = "ab" + "cd" + "9" * 28
    path, _, _ = storage.save_stream(container_id, io.BytesIO(b"x"))
    assert "ab/cd" in path.replace(os.sep, "/")
