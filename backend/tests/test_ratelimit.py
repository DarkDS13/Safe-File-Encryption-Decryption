"""Rate limiting (SRS 3.2.4: "rate limits are applied per account")."""
from __future__ import annotations

import pytest

from app.ratelimit import RateLimiter, api_limiter, login_limiter


@pytest.fixture(autouse=True)
def _tight_limits(monkeypatch):
    """Shrink the limits so the behaviour is reachable in a test.

    conftest sets them very high so the rest of the suite is not throttled;
    these tests need them small, and reset afterwards.
    """
    monkeypatch.setattr(login_limiter, "limit", 4)
    monkeypatch.setattr(api_limiter, "limit", 5)
    login_limiter.reset()
    api_limiter.reset()
    yield
    login_limiter.reset()
    api_limiter.reset()


# --------------------------------------------------------------------------
# the limiter itself
# --------------------------------------------------------------------------
def test_limiter_allows_up_to_the_limit_then_refuses():
    limiter = RateLimiter(limit=3, window_seconds=60)
    assert [limiter.check("k")[0] for _ in range(5)] == [True, True, True, False, False]


def test_limiter_reports_remaining_and_retry_after():
    limiter = RateLimiter(limit=2, window_seconds=30)
    assert limiter.check("k")[1] == 1
    assert limiter.check("k")[1] == 0
    allowed, remaining, retry_after = limiter.check("k")
    assert allowed is False
    assert remaining == 0
    assert 0 < retry_after <= 30


def test_limiter_keeps_separate_buckets_per_key():
    limiter = RateLimiter(limit=1, window_seconds=60)
    assert limiter.check("alice")[0] is True
    assert limiter.check("bob")[0] is True       # bob is unaffected by alice
    assert limiter.check("alice")[0] is False


def test_limiter_forgets_hits_once_the_window_passes():
    limiter = RateLimiter(limit=1, window_seconds=0)   # everything is already stale
    assert limiter.check("k")[0] is True
    assert limiter.check("k")[0] is True


# --------------------------------------------------------------------------
# login and registration
# --------------------------------------------------------------------------
def test_repeated_failed_logins_are_throttled(client, user):
    codes = [
        client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "Wrong12345"}
        ).status_code
        for _ in range(6)
    ]
    assert 429 in codes, "brute-forcing the password must eventually be refused"
    assert codes[0] == 401, "the first attempt should be a normal rejection"


def test_a_throttled_response_says_when_to_retry(client, user):
    last = None
    for _ in range(8):
        last = client.post(
            "/api/auth/login", json={"email": "alice@example.com", "password": "Wrong12345"}
        )
    assert last.status_code == 429
    assert int(last.headers["retry-after"]) >= 1
    assert "Too many requests" in last.json()["error"]["message"]


def test_registration_shares_the_login_limit(client):
    """Both are unauthenticated and both are expensive, so they share a budget."""
    codes = [
        client.post(
            "/api/auth/register",
            json={"email": f"user{i}@example.com", "password": "Abcd12345"},
        ).status_code
        for i in range(6)
    ]
    assert 429 in codes


# --------------------------------------------------------------------------
# authenticated endpoints
# --------------------------------------------------------------------------
def test_api_calls_are_throttled_per_account(client, user):
    codes = [
        client.get("/api/containers", headers=user["headers"]).status_code for _ in range(8)
    ]
    assert codes[0] == 200
    assert 429 in codes


def test_one_account_being_throttled_does_not_affect_another(client, user, other_user):
    for _ in range(8):
        client.get("/api/containers", headers=user["headers"])
    assert client.get("/api/containers", headers=user["headers"]).status_code == 429
    # Bob has his own bucket and is unaffected.
    assert client.get("/api/containers", headers=other_user["headers"]).status_code == 200


def test_signing_in_again_does_not_reset_the_limit(client, user):
    """The bucket follows the account, not the token.

    If it were keyed on the token string, a user could sign in again for a fresh
    token and walk around the limit.
    """
    for _ in range(8):
        client.get("/api/containers", headers=user["headers"])
    assert client.get("/api/containers", headers=user["headers"]).status_code == 429

    fresh = client.post(
        "/api/auth/login", json={"email": "alice@example.com", "password": "Alice12345"}
    ).json()["access_token"]
    assert fresh is not None
    still_limited = client.get(
        "/api/containers", headers={"Authorization": f"Bearer {fresh}"}
    )
    assert still_limited.status_code == 429, "a new token must not open a new bucket"
