"""Concurrency (NF.6: "at least fifty simultaneous users without failed requests").

These drive the real application through its threadpool, so they exercise the
SQLite WAL configuration and the rate limiter's lock rather than mocking them.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from app.ratelimit import api_limiter, login_limiter

from .conftest import auth_headers, make_container

USER_COUNT = 50


def _register(client, index: int) -> dict[str, str]:
    response = client.post(
        "/api/auth/register",
        json={"email": f"user{index}@example.com", "password": f"Passw0rd{index:03d}"},
    )
    assert response.status_code == 201, response.text
    return auth_headers(response.json()["access_token"])


def test_fifty_accounts_can_register_concurrently(client):
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda i: _register(client, i), range(USER_COUNT)))

    assert len(results) == USER_COUNT
    listing = client.get(
        "/api/admin/users?limit=200",
        headers=_admin_headers(client),
    )
    # 50 registrations plus the bootstrap administrator.
    assert listing.json()["meta"]["total"] == USER_COUNT + 1


def _admin_headers(client) -> dict[str, str]:
    from app.config import settings

    response = client.post(
        "/api/auth/login",
        json={"email": settings.ADMIN_EMAIL, "password": settings.ADMIN_PASSWORD},
    )
    return auth_headers(response.json()["access_token"])


def test_fifty_users_uploading_at_once_all_succeed(client):
    """The core NF.6 claim: fifty simultaneous uploads, zero failures."""
    headers = [_register(client, i) for i in range(USER_COUNT)]
    payloads = {i: make_container(16 * 1024) for i in range(USER_COUNT)}

    def upload(index: int):
        return client.post(
            "/api/containers",
            headers=headers[index],
            files={"file": (f"f{index}.enc", payloads[index], "application/octet-stream")},
        )

    with ThreadPoolExecutor(max_workers=25) as pool:
        responses = list(pool.map(upload, range(USER_COUNT)))

    statuses = [r.status_code for r in responses]
    assert statuses.count(201) == USER_COUNT, f"failures: {[s for s in statuses if s != 201]}"

    # Every upload must be retrievable and byte-identical: concurrent writes
    # must not have interleaved into each other's files.
    for index, response in enumerate(responses):
        container_id = response.json()["id"]
        downloaded = client.get(
            f"/api/containers/{container_id}/download", headers=headers[index]
        )
        assert downloaded.content == payloads[index], f"container {index} was corrupted"


def test_concurrent_uploads_stay_isolated_between_accounts(client):
    """Under load, no account may end up seeing another account's file."""
    headers = [_register(client, i) for i in range(20)]

    def upload(index: int):
        return client.post(
            "/api/containers",
            headers=headers[index],
            files={"file": (f"f{index}.enc", make_container(2048), "application/octet-stream")},
        )

    with ThreadPoolExecutor(max_workers=20) as pool:
        list(pool.map(upload, range(20)))

    for index in range(20):
        listing = client.get("/api/containers", headers=headers[index]).json()
        assert listing["meta"]["total"] == 1, "an account saw a file that was not its own"


def test_concurrent_reads_and_writes_do_not_block_each_other(client, user):
    """SQLite is in WAL mode so a writer must not lock out readers (C.4)."""
    def work(index: int) -> int:
        if index % 2 == 0:
            return client.post(
                "/api/containers",
                headers=user["headers"],
                files={"file": (f"w{index}.enc", make_container(8192), "application/octet-stream")},
            ).status_code
        return client.get("/api/containers", headers=user["headers"]).status_code

    with ThreadPoolExecutor(max_workers=12) as pool:
        statuses = list(pool.map(work, range(40)))

    assert all(status in (200, 201) for status in statuses), sorted(set(statuses))


def test_the_rate_limiter_counts_correctly_under_concurrency(client, user):
    """The limiter's lock must stop two threads slipping past the same slot."""
    api_limiter.reset()
    login_limiter.reset()
    original = api_limiter.limit
    api_limiter.limit = 20
    try:
        with ThreadPoolExecutor(max_workers=16) as pool:
            statuses = list(
                pool.map(
                    lambda _: client.get("/api/containers", headers=user["headers"]).status_code,
                    range(60),
                )
            )
        allowed = statuses.count(200)
        # Exactly the limit should get through — no more, no fewer.
        assert allowed == 20, f"limiter let {allowed} through with a limit of 20"
        assert statuses.count(429) == 40
    finally:
        api_limiter.limit = original
        api_limiter.reset()
