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
