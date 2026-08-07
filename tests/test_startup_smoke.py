"""Startup smoke test.

`conftest.py` already imports `app.main` at collection time -- if
`app/main.py`'s module-level bootstrap (`create_all()` ->
`assert_schema_matches_models()` -> `create_admin()` -> ...) raises, every
test in the suite fails to collect, not just these. These tests exist to
name that path explicitly and assert the service is actually reachable and
functional afterwards -- this is the exact sequence that crash-looped in
production on 2026-08-06 (see docs/MIGRATIONS.md): the container never
reached a state where it could serve `/health` at all.
"""

import os


def test_app_starts_and_serves_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_app_starts_and_serves_metrics(client):
    resp = client.get("/metrics")
    assert resp.status_code == 200


def test_bootstrap_admin_can_log_in_after_startup(client):
    """End-to-end confirmation that startup bootstrap (create_admin())
    actually produced a working, logged-in-able admin account -- not just
    that the process didn't crash."""
    resp = client.post(
        "/auth/login",
        json={"email": "admin@omnibioai", "password": os.environ["ADMIN_BOOTSTRAP_PASSWORD"]},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert "access_token" in body
