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


def test_a_very_long_password_is_accepted_and_verifies(client):
    """bcrypt caps at 72 bytes; a long passphrase must not crash or truncate."""
    long_password = "correct-horse-battery-staple-" * 5 + "9"   # 146 characters
    created = client.post(
        "/api/auth/register", json={"email": "long@example.com", "password": long_password}
    )
    assert created.status_code == 201

    ok = client.post(
        "/api/auth/login", json={"email": "long@example.com", "password": long_password}
    )
    assert ok.status_code == 200


def test_long_passwords_are_not_truncated_to_72_bytes(client):
    """Two passwords sharing their first 72 bytes must not be interchangeable."""
    base = "x" * 80
    client.post("/api/auth/register", json={"email": "t@example.com", "password": base + "aaa1"})
    wrong = client.post(
        "/api/auth/login", json={"email": "t@example.com", "password": base + "bbb1"}
    )
    assert wrong.status_code == 401


# --------------------------------------------------------------------------
# token handling (F.12)
# --------------------------------------------------------------------------
def test_token_carries_subject_role_and_expiry(client, user):
    from app.security import decode_token

    claims = decode_token(user["token"])
    assert claims["sub"] == user["user"]["id"]
    assert claims["role"] == "user"
    assert claims["exp"] > claims["iat"]
    # Nothing password-shaped is ever put in a token; the payload is only
    # base64, so anything in it is readable by the holder.
    assert "password" not in claims
    assert "passphrase" not in claims


def test_an_expired_token_is_refused(client, user):
    import time

    import jwt

    from app.config import settings

    expired = jwt.encode(
        {"sub": user["user"]["id"], "role": "user", "exp": int(time.time()) - 60},
        settings.SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM,
    )
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {expired}"})
    assert response.status_code == 401


def test_a_token_signed_with_the_wrong_key_is_refused(client, user):
    import time

    import jwt

    forged = jwt.encode(
        {"sub": user["user"]["id"], "role": "admin", "exp": int(time.time()) + 600},
        "not-the-server-secret",
        algorithm="HS256",
    )
    assert client.get("/api/auth/me", headers={"Authorization": f"Bearer {forged}"}).status_code == 401


def test_editing_the_role_claim_does_not_grant_admin(client, user):
    """The payload is readable but not modifiable: editing it breaks the signature."""
    import base64
    import json

    header, payload, signature = user["token"].split(".")
    body = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    body["role"] = "admin"
    tampered = base64.urlsafe_b64encode(json.dumps(body).encode()).decode().rstrip("=")

    response = client.get(
        "/api/admin/stats", headers={"Authorization": f"Bearer {header}.{tampered}.{signature}"}
    )
    assert response.status_code == 401


def test_an_alg_none_token_is_refused(client, user):
    """The classic JWT downgrade: PyJWT must not accept an unsigned token."""
    import base64
    import json

    header = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip("=")
    body = base64.urlsafe_b64encode(
        json.dumps({"sub": user["user"]["id"], "role": "admin"}).encode()
    ).decode().rstrip("=")

    response = client.get(
        "/api/admin/stats", headers={"Authorization": f"Bearer {header}.{body}."}
    )
    assert response.status_code == 401


def test_a_token_for_a_deleted_account_is_refused(client, user):
    """The role is re-read from the database, so a stale token cannot be used."""
    from app.database import SessionLocal
    from app.models import User

    with SessionLocal() as db:
        db.delete(db.get(User, user["user"]["id"]))
        db.commit()

    assert client.get("/api/auth/me", headers=user["headers"]).status_code == 401


def test_a_malformed_authorization_header_is_refused(client):
    for header in ["", "Bearer", "Bearer ", "Basic abc123", "Bearer not.a.jwt"]:
        response = client.get("/api/auth/me", headers={"Authorization": header})
        assert response.status_code == 401, f"{header!r} was not refused"
