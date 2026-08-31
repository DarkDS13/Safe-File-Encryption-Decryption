"""0.1 Authentication & Session Management (F.12)."""
from __future__ import annotations

from app.config import settings


def test_register_returns_token_and_user(client):
    response = client.post(
        "/api/auth/register",
        json={"email": "New@Example.com", "password": "Secret123", "display_name": "New"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["token_type"] == "bearer"
    assert body["user"]["email"] == "new@example.com"   # normalised
    assert body["user"]["role"] == "user"
    # The response must never carry anything password-shaped.
    assert "password" not in response.text
    assert "hash" not in response.text


def test_register_rejects_weak_password(client):
    response = client.post(
        "/api/auth/register", json={"email": "weak@example.com", "password": "short"}
    )
    assert response.status_code == 400
    assert "8 characters" in response.json()["error"]["message"]


def test_register_rejects_password_without_digit(client):
    response = client.post(
        "/api/auth/register", json={"email": "weak2@example.com", "password": "onlyletters"}
    )
    assert response.status_code == 400
    assert "digit" in response.json()["error"]["message"]


def test_register_rejects_malformed_email(client):
    response = client.post(
        "/api/auth/register", json={"email": "not-an-email", "password": "Secret123"}
    )
    assert response.status_code == 400


def test_duplicate_registration_is_refused(client, user):
    response = client.post(
        "/api/auth/register", json={"email": "alice@example.com", "password": "Another123"}
    )
    assert response.status_code == 409


def test_login_succeeds_with_correct_credentials(client, user):
    response = client.post(
        "/api/auth/login", json={"email": "alice@example.com", "password": "Alice12345"}
    )
    assert response.status_code == 200
    assert response.json()["user"]["email"] == "alice@example.com"


def test_login_failure_does_not_reveal_whether_account_exists(client, user):
    unknown = client.post(
        "/api/auth/login", json={"email": "nobody@example.com", "password": "Whatever123"}
    )
    wrong_password = client.post(
        "/api/auth/login", json={"email": "alice@example.com", "password": "WrongPass123"}
    )
    assert unknown.status_code == wrong_password.status_code == 401
    assert unknown.json()["error"]["message"] == wrong_password.json()["error"]["message"]


def test_me_requires_a_token(client):
    assert client.get("/api/auth/me").status_code == 401


def test_me_rejects_a_forged_token(client):
    response = client.get("/api/auth/me", headers={"Authorization": "Bearer not.a.token"})
    assert response.status_code == 401


def test_password_is_stored_only_as_a_bcrypt_hash(client, user):
    from sqlalchemy import select

    from app.database import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        stored = db.scalar(select(User).where(User.email == "alice@example.com"))
        assert stored.password_hash.startswith("$2")      # bcrypt marker
        assert "Alice12345" not in stored.password_hash


def test_suspended_account_cannot_sign_in(client, admin, user):
    client.post(f"/api/admin/users/{user['user']['id']}/suspend", headers=admin["headers"])
    response = client.post(
        "/api/auth/login", json={"email": "alice@example.com", "password": "Alice12345"}
    )
    assert response.status_code == 403


def test_suspended_account_token_stops_working(client, admin, user):
    assert client.get("/api/auth/me", headers=user["headers"]).status_code == 200
    client.post(f"/api/admin/users/{user['user']['id']}/suspend", headers=admin["headers"])
    # An already-issued token must stop working too, or suspension is cosmetic.
    assert client.get("/api/auth/me", headers=user["headers"]).status_code == 403


def test_bootstrap_admin_exists_and_has_admin_role(client, admin):
    assert admin["user"]["role"] == "admin"
    assert admin["user"]["email"] == settings.ADMIN_EMAIL
