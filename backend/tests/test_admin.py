"""0.7 System Administration (F.13) and the audit log's confidentiality rules."""
from __future__ import annotations

from datetime import timedelta

from tests.conftest import make_container


def upload(client, headers, filename="x.enc"):
    return client.post(
        "/api/containers",
        headers=headers,
        files={"file": (filename, make_container(), "application/octet-stream")},
        data={"algorithm": "AES-256-GCM", "kdf": "Argon2id",
              "segment_count": "1", "plaintext_size": "4000"},
    ).json()


# --------------------------------------------------------------------------
# role enforcement
# --------------------------------------------------------------------------
def test_every_admin_endpoint_refuses_an_ordinary_user(client, user):
    paths = [
        ("get", "/api/admin/users"),
        ("get", "/api/admin/audit"),
        ("get", "/api/admin/stats"),
        ("get", "/api/admin/containers"),
        ("post", "/api/admin/purge"),
    ]
    for method, path in paths:
        response = getattr(client, method)(path, headers=user["headers"])
        assert response.status_code == 403, f"{method} {path} was not refused"


def test_admin_endpoints_require_a_token(client):
    assert client.get("/api/admin/users").status_code == 401


# --------------------------------------------------------------------------
# accounts
# --------------------------------------------------------------------------
def test_admin_can_list_and_filter_accounts(client, admin, user, other_user):
    everyone = client.get("/api/admin/users", headers=admin["headers"]).json()
    assert everyone["meta"]["total"] == 3

    filtered = client.get("/api/admin/users?q=alice", headers=admin["headers"]).json()
    assert [item["email"] for item in filtered["items"]] == ["alice@example.com"]


def test_admin_can_suspend_and_reinstate(client, admin, user):
    user_id = user["user"]["id"]
    suspended = client.post(f"/api/admin/users/{user_id}/suspend", headers=admin["headers"])
    assert suspended.status_code == 200
    assert suspended.json()["is_suspended"] is True

    reinstated = client.post(f"/api/admin/users/{user_id}/reinstate", headers=admin["headers"])
    assert reinstated.json()["is_suspended"] is False
    assert client.get("/api/auth/me", headers=user["headers"]).status_code == 200


def test_admin_cannot_suspend_themselves(client, admin):
    response = client.post(
        f"/api/admin/users/{admin['user']['id']}/suspend", headers=admin["headers"]
    )
    assert response.status_code == 400


def test_suspending_an_unknown_account_returns_404(client, admin):
    assert client.post("/api/admin/users/nope/suspend", headers=admin["headers"]).status_code == 404


# --------------------------------------------------------------------------
# audit log
# --------------------------------------------------------------------------
def test_audit_log_records_logins_and_uploads(client, admin, user):
    upload(client, user["headers"])
    log = client.get("/api/admin/audit", headers=admin["headers"]).json()
    actions = {entry["action"] for entry in log["items"]}
    assert {"auth.register", "auth.login", "container.upload"} <= actions


def test_audit_log_can_be_filtered_by_outcome(client, admin, user):
    client.post("/api/auth/login", json={"email": "alice@example.com", "password": "Nope12345"})
    failures = client.get("/api/admin/audit?outcome=failure", headers=admin["headers"]).json()
    assert failures["meta"]["total"] >= 1
    assert all(entry["outcome"] == "failure" for entry in failures["items"])


def test_audit_log_never_records_key_material(client, admin, user):
    """C.5 / NF.3: the redaction is enforced centrally, so try to defeat it."""
    from app import audit
    from app.database import SessionLocal

    with SessionLocal() as db:
        audit.record(
            db,
            action="test.entry",
            detail={
                "passphrase": "correct horse battery staple",
                "derived_key": "deadbeefdeadbeef",
                "session_token": "abc.def.ghi",
                "plaintext_sample": "the quick brown fox",
                "salt": "0011223344556677",
                "filename": "safe-to-log.pdf",
                "size_bytes": 1234,
            },
        )

    log = client.get("/api/admin/audit?limit=500", headers=admin["headers"])
    assert "correct horse battery staple" not in log.text
    assert "deadbeefdeadbeef" not in log.text
    assert "abc.def.ghi" not in log.text
    assert "the quick brown fox" not in log.text
    assert "0011223344556677" not in log.text
    # Fields that are safe to keep are still there.
    assert "safe-to-log.pdf" in log.text
    assert "1234" in log.text


# --------------------------------------------------------------------------
# statistics and maintenance
# --------------------------------------------------------------------------
def test_stats_report_accounts_containers_and_throughput(client, admin, user):
    upload(client, user["headers"])
    client.post(
        "/api/operations",
        headers=user["headers"],
        json={"kind": "encrypt", "status": "success", "input_size": 2 * 1024 * 1024,
              "duration_ms": 1000, "filename": "a.pdf"},
    )

    stats = client.get("/api/admin/stats", headers=admin["headers"]).json()
    assert stats["users_total"] == 2
    assert stats["containers_total"] == 1
    assert stats["stored_bytes"] > 0
    assert stats["operations_total"] == 1
    assert stats["bytes_encrypted"] == 2 * 1024 * 1024
    assert stats["average_throughput_mbps"] == 2.0


def test_admin_container_listing_shows_metadata_but_no_contents(client, admin, user):
    created = upload(client, user["headers"], filename="private.pdf.enc")
    listing = client.get("/api/admin/containers", headers=admin["headers"]).json()

    assert listing["items"][0]["filename"] == "private.pdf.enc"
    assert listing["items"][0]["owner_email"] == "alice@example.com"
    # No field anywhere in the response carries container bytes.
    assert "storage_path" not in listing["items"][0]
    assert created["id"] == listing["items"][0]["id"]


def test_purge_removes_only_expired_containers(client, admin, user):
    from app import storage
    from app.database import SessionLocal
    from app.models import Container, utcnow

    live = upload(client, user["headers"], filename="live.enc")
    stale = upload(client, user["headers"], filename="stale.enc")

    with SessionLocal() as db:
        row = db.get(Container, stale["id"])
        row.expires_at = utcnow() - timedelta(days=1)
        stale_path = row.storage_path
        db.commit()

    result = client.post("/api/admin/purge", headers=admin["headers"]).json()
    assert result["purged"] == 1
    assert result["freed_bytes"] > 0
    assert not storage.exists(stale_path)

    remaining = client.get("/api/containers", headers=user["headers"]).json()
    assert [item["filename"] for item in remaining["items"]] == ["live.enc"]
    assert remaining["items"][0]["id"] == live["id"]


def test_purge_with_nothing_expired_is_a_no_op(client, admin, user):
    upload(client, user["headers"])
    result = client.post("/api/admin/purge", headers=admin["headers"]).json()
    assert result == {"purged": 0, "freed_bytes": 0}
