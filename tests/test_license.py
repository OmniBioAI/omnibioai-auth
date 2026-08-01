import os
import uuid

import pytest


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def admin_token(client):
    resp = client.post(
        "/auth/login",
        json={"email": "admin@omnibioai", "password": os.environ["ADMIN_BOOTSTRAP_PASSWORD"]},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def admin_headers(admin_token):
    return _auth_header(admin_token)


def _unique_email():
    return f"license-{uuid.uuid4().hex[:8]}@omnibioai.test"


# ── Generate (admin) ─────────────────────────────────────────────────────────

def test_generate_missing_token_rejected(client):
    resp = client.post(
        "/license/generate",
        json={"email": _unique_email(), "plan": "beta"},
    )
    assert resp.status_code == 401


def test_generate_requires_admin_permission(client, auth_tokens):
    resp = client.post(
        "/license/generate",
        json={"email": _unique_email(), "plan": "beta"},
        headers=_auth_header(auth_tokens["access_token"]),
    )
    assert resp.status_code == 403


def test_generate_license(client, admin_headers):
    email = _unique_email()
    resp = client.post(
        "/license/generate",
        json={"email": email, "plan": "beta", "expires_days": 30, "max_uses": 1},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["key"].startswith("OMNI-")
    assert len(data["key"]) == 24  # OMNI- + 4 groups of 4 + 3 dashes
    assert data["email"] == email
    assert data["expires_at"] is not None


# ── Validate ──────────────────────────────────────────────────────────────────

def test_validate_success_issues_tokens(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "plan": "pro"},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    resp = client.post(
        "/license/validate",
        json={"key": key, "email": email, "platform": "web"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user_info"]["email"] == email


def test_validate_response_is_electron_compatible_superset(client, admin_headers):
    """Phase 1 PR3: /license/validate must remain a strict superset of
    today's response shape, AND already carry the tier/expiry/days_remaining
    fields omnibioai-studio's LicenseGate.jsx reads -- currently from the
    separate license_server.py, but matching field names now so the
    eventual Electron cutover (Phase 1 PR4) onto this endpoint is a pure
    URL change, not a response-shape migration too."""
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "plan": "pro", "expires_days": 30},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    resp = client.post("/license/validate", json={"key": key, "email": email, "platform": "web"})
    assert resp.status_code == 200
    data = resp.json()

    # Existing fields, unchanged shape -- an old client reading only these
    # keeps working exactly as before.
    assert data["valid"] is True
    assert isinstance(data["access_token"], str)
    assert isinstance(data["refresh_token"], str)
    assert data["token_type"] == "bearer"
    assert data["user_info"]["email"] == email

    # New fields.
    assert data["tier"] == "pro"
    assert data["days_remaining"] is not None and data["days_remaining"] <= 30
    assert data["expiry"] is not None
    # org_id is None here -- this test user has no org membership (no
    # backfill has run in this test DB) -- a valid, expected state, not a
    # bug, exercised explicitly rather than left unchecked.
    assert data["org_id"] is None


def test_validate_unknown_key(client):
    resp = client.post(
        "/license/validate",
        json={"key": "OMNI-0000-0000-0000-0000", "email": "nobody@test.com", "platform": "web"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["reason"] == "invalid_key"


def test_validate_wrong_email(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate", json={"email": email}, headers=admin_headers
    )
    key = gen.json()["key"]

    resp = client.post(
        "/license/validate",
        json={"key": key, "email": "someone-else@test.com", "platform": "web"},
    )
    assert resp.status_code == 200
    assert resp.json()["reason"] == "email_mismatch"


def test_validate_exhausted_after_max_uses(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "max_uses": 1},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    first = client.post(
        "/license/validate", json={"key": key, "email": email, "platform": "web"}
    )
    assert first.json()["valid"] is True

    second = client.post(
        "/license/validate", json={"key": key, "email": email, "platform": "web"}
    )
    assert second.json()["valid"] is False
    assert second.json()["reason"] == "usage_exhausted"


def test_validate_platform_mismatch(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "platform": "desktop"},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    resp = client.post(
        "/license/validate", json={"key": key, "email": email, "platform": "web"}
    )
    assert resp.json()["valid"] is False
    assert resp.json()["reason"] == "platform_mismatch"


# ── Validate: Electron key-only path (Phase 1 PR4) ─────────────────────────────


def test_validate_without_email_uses_license_email(client, admin_headers):
    """The Electron client (LicenseGate.jsx) never collects an email --
    omitting it entirely must still succeed, using the license's own
    stored email for the resulting user, not reject as a mismatch."""
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "plan": "pro", "platform": "desktop"},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    resp = client.post(
        "/license/validate", json={"key": key, "platform": "desktop"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["user_info"]["email"] == email


def test_validate_binds_machine_id_on_first_use(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "platform": "desktop", "max_uses": 5},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    first = client.post(
        "/license/validate",
        json={"key": key, "platform": "desktop", "machine_id": "machine-a"},
    )
    assert first.json()["valid"] is True

    # A second call from a *different* machine still succeeds -- binding is
    # informational (first-use pinning), not an enforced device limit.
    second = client.post(
        "/license/validate",
        json={"key": key, "platform": "desktop", "machine_id": "machine-b"},
    )
    assert second.json()["valid"] is True


# ── Pull-token (Phase 1 PR4) ─────────────────────────────────────────────────


def test_pull_token_returns_ghcr_credential(client, admin_headers, monkeypatch):
    from app.core.config import settings

    monkeypatch.setattr(settings, "GHCR_PULL_TOKEN", "test-ghcr-token")

    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "platform": "desktop"},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    resp = client.post(
        "/license/pull-token", json={"key": key, "machine_id": "machine-a"}
    )
    assert resp.status_code == 200
    assert resp.json()["ghcr_token"] == "test-ghcr-token"


def test_pull_token_does_not_consume_a_use(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate",
        json={"email": email, "platform": "desktop", "max_uses": 1},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    for _ in range(3):
        resp = client.post("/license/pull-token", json={"key": key})
        assert resp.status_code == 200

    # max_uses=1 is still untouched -- pull-token is a read-only validity
    # check, not a consumption action (that's /validate's job).
    validate = client.post(
        "/license/validate", json={"key": key, "platform": "desktop"}
    )
    assert validate.json()["valid"] is True


def test_pull_token_unknown_key_returns_404(client):
    resp = client.post(
        "/license/pull-token", json={"key": "OMNI-0000-0000-0000-0000"}
    )
    assert resp.status_code == 404


def test_pull_token_revoked_key_returns_403(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate", json={"email": email, "platform": "desktop"}, headers=admin_headers
    )
    key = gen.json()["key"]
    client.post("/license/revoke", json={"key": key}, headers=admin_headers)

    resp = client.post("/license/pull-token", json={"key": key})
    assert resp.status_code == 403


# ── Status ────────────────────────────────────────────────────────────────────

def test_status_after_validate(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate", json={"email": email, "plan": "beta"}, headers=admin_headers
    )
    key = gen.json()["key"]

    validate = client.post(
        "/license/validate", json={"key": key, "email": email, "platform": "web"}
    )
    token = validate.json()["access_token"]

    resp = client.get("/license/status", headers=_auth_header(token))
    assert resp.status_code == 200
    data = resp.json()
    assert data["key"] == key
    assert data["usage_count"] == 1
    assert data["revoked"] is False


def test_status_no_license_returns_404(client, admin_headers):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": "Password123!"})
    login = client.post("/auth/login", json={"email": email, "password": "Password123!"})
    token = login.json()["access_token"]

    resp = client.get("/license/status", headers=_auth_header(token))
    assert resp.status_code == 404


# ── Revoke (admin) ───────────────────────────────────────────────────────────

def test_revoke_license(client, admin_headers):
    email = _unique_email()
    gen = client.post(
        "/license/generate", json={"email": email}, headers=admin_headers
    )
    key = gen.json()["key"]

    resp = client.post("/license/revoke", json={"key": key}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["success"] is True

    validate = client.post(
        "/license/validate", json={"key": key, "email": email, "platform": "web"}
    )
    assert validate.json()["valid"] is False
    assert validate.json()["reason"] == "revoked"


def test_revoke_missing_token_rejected(client):
    resp = client.post("/license/revoke", json={"key": "OMNI-0000-0000-0000-0000"})
    assert resp.status_code == 401


def test_revoke_requires_admin_permission(client, auth_tokens):
    resp = client.post(
        "/license/revoke",
        json={"key": "OMNI-0000-0000-0000-0000"},
        headers=_auth_header(auth_tokens["access_token"]),
    )
    assert resp.status_code == 403


def test_revoke_unknown_key_returns_404(client, admin_headers):
    resp = client.post(
        "/license/revoke", json={"key": "OMNI-ZZZZ-ZZZZ-ZZZZ-ZZZZ"}, headers=admin_headers
    )
    assert resp.status_code == 404
