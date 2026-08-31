"""0.4 Container Storage & Retrieval (F.7, F.11) and the isolation rule (NF.7)."""
from __future__ import annotations

import os

from tests.conftest import make_container


def upload(client, headers, data=None, filename="secret.txt.enc"):
    payload = data if data is not None else make_container()
    return client.post(
        "/api/containers",
        headers=headers,
        files={"file": (filename, payload, "application/octet-stream")},
        data={
            "algorithm": "AES-256-GCM",
            "kdf": "Argon2id",
            "segment_count": "1",
            "plaintext_size": "4000",
        },
    )


def test_upload_stores_the_container(client, user):
    response = upload(client, user["headers"])
    assert response.status_code == 201
    body = response.json()
    assert body["filename"] == "secret.txt.enc"
    assert body["size_bytes"] == 104 + 4096
    assert body["algorithm"] == "AES-256-GCM"
    assert len(body["container_sha256"]) == 64


def test_upload_rejects_a_file_that_is_not_a_container(client, user):
    response = upload(client, user["headers"], data=b"just some plain bytes, not a container")
    assert response.status_code == 400
    assert "not a container" in response.json()["error"]["message"].lower()


def test_upload_rejects_a_truncated_header(client, user):
    response = upload(client, user["headers"], data=b"ENCV" + os.urandom(20))
    assert response.status_code == 400


def test_upload_requires_authentication(client):
    response = client.post(
        "/api/containers",
        files={"file": ("x.enc", make_container(), "application/octet-stream")},
    )
    assert response.status_code == 401


def test_stored_bytes_are_byte_identical_on_download(client, user):
    payload = make_container(8192)
    created = upload(client, user["headers"], data=payload).json()
    response = client.get(f"/api/containers/{created['id']}/download", headers=user["headers"])
    assert response.status_code == 200
    assert response.content == payload


def test_listing_shows_only_your_own_containers(client, user, other_user):
    upload(client, user["headers"], filename="alice.enc")
    upload(client, other_user["headers"], filename="bob.enc")

    alice = client.get("/api/containers", headers=user["headers"]).json()
    bob = client.get("/api/containers", headers=other_user["headers"]).json()

    assert [item["filename"] for item in alice["items"]] == ["alice.enc"]
    assert [item["filename"] for item in bob["items"]] == ["bob.enc"]


def test_another_users_container_returns_403_not_404(client, user, other_user):
    """NF.7 asks for 403 specifically, so the refusal is explicit and logged."""
    created = upload(client, user["headers"]).json()
    response = client.get(f"/api/containers/{created['id']}", headers=other_user["headers"])
    assert response.status_code == 403


def test_downloading_another_users_container_is_refused(client, user, other_user):
    created = upload(client, user["headers"]).json()
    response = client.get(
        f"/api/containers/{created['id']}/download", headers=other_user["headers"]
    )
    assert response.status_code == 403


def test_deleting_another_users_container_is_refused(client, user, other_user):
    created = upload(client, user["headers"]).json()
    response = client.delete(f"/api/containers/{created['id']}", headers=other_user["headers"])
    assert response.status_code == 403
    # and the owner can still fetch it
    assert client.get(f"/api/containers/{created['id']}", headers=user["headers"]).status_code == 200


def test_refused_access_is_written_to_the_audit_log(client, admin, user, other_user):
    created = upload(client, user["headers"]).json()
    client.get(f"/api/containers/{created['id']}", headers=other_user["headers"])

    log = client.get("/api/admin/audit", headers=admin["headers"]).json()
    actions = [entry["action"] for entry in log["items"]]
    assert "container.access_denied" in actions


def test_delete_removes_the_stored_bytes(client, user):
    from app import storage
    from app.database import SessionLocal
    from app.models import Container

    created = upload(client, user["headers"]).json()
    with SessionLocal() as db:
        path = db.get(Container, created["id"]).storage_path
    assert storage.exists(path)

    response = client.delete(f"/api/containers/{created['id']}", headers=user["headers"])
    assert response.status_code == 200
    assert not storage.exists(path)

    listing = client.get("/api/containers", headers=user["headers"]).json()
    assert listing["meta"]["total"] == 0


def test_oversize_upload_is_rejected(client, user, monkeypatch):
    from app import storage
    from app.config import settings

    monkeypatch.setattr(settings, "MAX_UPLOAD_BYTES", 2048)
    response = upload(client, user["headers"], data=make_container(8192))
    assert response.status_code == 413
    assert "limit" in response.json()["error"]["message"].lower()
    # NF.9: a rejected upload must not leave a partial file behind.
    leftovers = list(settings.STORAGE_DIR.rglob("*.part"))
    assert leftovers == []


def test_missing_container_returns_404(client, user):
    assert client.get("/api/containers/deadbeef", headers=user["headers"]).status_code == 404
