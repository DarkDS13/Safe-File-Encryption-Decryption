"""0.6 Metrics & Audit Logging (F.10, F.14)."""
from __future__ import annotations


def record(client, headers, **overrides):
    payload = {
        "kind": "encrypt",
        "status": "success",
        "algorithm": "AES-256-GCM",
        "kdf": "Argon2id",
        "filename": "report.pdf",
        "file_type": "pdf",
        "input_size": 10 * 1024 * 1024,
        "output_size": 10 * 1024 * 1024 + 264,
        "duration_ms": 1450.5,
        "peak_memory_bytes": 96 * 1024 * 1024,
        "segment_count": 10,
    }
    payload.update(overrides)
    return client.post("/api/operations", headers=headers, json=payload)


def test_recording_an_operation_stores_every_metric(client, user):
    response = record(client, user["headers"])
    assert response.status_code == 201
    body = response.json()
    assert body["duration_ms"] == 1450.5
    assert body["peak_memory_bytes"] == 96 * 1024 * 1024
    assert body["input_size"] == 10 * 1024 * 1024
    assert body["segment_count"] == 10


def test_failures_are_recorded_too(client, user):
    response = record(client, user["headers"], kind="decrypt", status="failure",
                      error_code="decryption_failed")
    assert response.status_code == 201
    assert response.json()["status"] == "failure"
    assert response.json()["error_code"] == "decryption_failed"


def test_history_shows_only_your_own_operations(client, user, other_user):
    record(client, user["headers"], filename="alice.pdf")
    record(client, other_user["headers"], filename="bob.pdf")

    alice = client.get("/api/operations", headers=user["headers"]).json()
    assert [item["filename"] for item in alice["items"]] == ["alice.pdf"]
    assert alice["meta"]["total"] == 1


def test_history_can_be_filtered_by_kind(client, user):
    record(client, user["headers"], kind="encrypt")
    record(client, user["headers"], kind="decrypt")
    encrypts = client.get("/api/operations?kind=encrypt", headers=user["headers"]).json()
    assert encrypts["meta"]["total"] == 1
    assert encrypts["items"][0]["kind"] == "encrypt"


def test_summary_aggregates_the_users_own_figures(client, user, other_user):
    record(client, user["headers"], input_size=1000, duration_ms=100)
    record(client, user["headers"], input_size=3000, duration_ms=300, status="failure",
           error_code="integrity_failed")
    record(client, other_user["headers"], input_size=999999, duration_ms=9999)

    summary = client.get("/api/operations/summary", headers=user["headers"]).json()
    assert summary["operations_total"] == 2
    assert summary["operations_succeeded"] == 1
    assert summary["operations_failed"] == 1
    assert summary["bytes_processed"] == 4000
    assert summary["average_duration_ms"] == 200.0


def test_an_invalid_kind_is_rejected(client, user):
    response = record(client, user["headers"], kind="obliterate")
    assert response.status_code == 422


def test_recording_requires_authentication(client):
    assert record(client, {}).status_code == 401


def test_no_endpoint_accepts_or_echoes_key_material(client, user):
    """NF.3: an operation record must not become a place to smuggle a key."""
    response = client.post(
        "/api/operations",
        headers=user["headers"],
        json={
            "kind": "encrypt",
            "passphrase": "hunter2",
            "key": "0123456789abcdef",
            "filename": "x.txt",
        },
    )
    assert response.status_code == 201
    assert "hunter2" not in response.text
    assert "0123456789abcdef" not in response.text
