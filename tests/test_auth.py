"""Core /auth endpoint contract: registration (including duplicates), login
success and failure, token validation, refresh-token rotation, and logout
revocation of access and refresh tokens.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import pytest


# ── Register ──────────────────────────────────────────────────────────────────

def test_register_new_user(client):
    """Registering a new email returns 200 with the message "User created"."""
    resp = client.post(
        "/auth/register",
        json={"email": "newuser@test.com", "password": "Password123!"},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "User created"


def test_register_duplicate_user(client):
    """Registering an email that already exists returns 400 with an "already exists" detail."""
    client.post(
        "/auth/register",
        json={"email": "dup@test.com", "password": "Password123!"},
    )
    resp = client.post(
        "/auth/register",
        json={"email": "dup@test.com", "password": "Password123!"},
    )
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"]


# ── Login ─────────────────────────────────────────────────────────────────────

def test_login_success(client, registered_user):
    """Login with valid credentials returns 200 with an access token, a refresh token and token_type
    "bearer".
    """
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"


def test_login_wrong_password(client, registered_user):
    """Login with a wrong password returns 401."""
    resp = client.post(
        "/auth/login",
        json={"email": registered_user["email"], "password": "wrongpassword"},
    )
    assert resp.status_code == 401


def test_login_unknown_email(client):
    """Login for an email that is not registered returns 401."""
    resp = client.post(
        "/auth/login",
        json={"email": "nobody@test.com", "password": "password"},
    )
    assert resp.status_code == 401


def test_login_missing_fields(client):
    """Login with an empty JSON body is rejected with 422 validation error."""
    resp = client.post("/auth/login", json={})
    assert resp.status_code == 422


# ── Validate ──────────────────────────────────────────────────────────────────

def test_validate_valid_token(client, auth_tokens):
    """/auth/validate reports valid=true and includes user_id and email for a freshly issued access
    token.
    """
    resp = client.post("/auth/validate", json={"token": auth_tokens["access_token"]})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert "user_id" in data
    assert "email" in data


def test_validate_invalid_token(client):
    """/auth/validate reports valid=false for a malformed token string."""
    resp = client.post("/auth/validate", json={"token": "not.a.valid.token"})
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


def test_validate_empty_token(client):
    """/auth/validate reports valid=false for an empty token."""
    resp = client.post("/auth/validate", json={"token": ""})
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


def test_validate_missing_token_key(client):
    """/auth/validate reports valid=false, not an error, when the request body has no token key."""
    # req.get("token") returns None → decode raises → {"valid": False}
    resp = client.post("/auth/validate", json={})
    assert resp.status_code == 200
    assert resp.json()["valid"] is False


# ── Refresh ───────────────────────────────────────────────────────────────────

def test_refresh_valid_token(client, auth_tokens):
    """Refreshing with a valid refresh token returns 200 with a new access token and a different,
    rotated refresh token.
    """
    resp = client.post(
        "/auth/refresh",
        json={"refresh_token": auth_tokens["refresh_token"]},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    # PR0.2: rotation -- the old "echoes back the same refresh token"
    # behavior is deliberately removed. A successful refresh must return a
    # *different* refresh token; the old one becomes single-use (see
    # tests/test_refresh_rotation.py for reuse-detection coverage).
    assert data["refresh_token"] != auth_tokens["refresh_token"]


def test_refresh_invalid_token(client):
    """Refreshing with an invalid refresh token returns 401."""
    resp = client.post(
        "/auth/refresh",
        json={"refresh_token": "invalid.token.here"},
    )
    assert resp.status_code == 401


# ── Logout ────────────────────────────────────────────────────────────────────

def test_logout(client, auth_tokens):
    """Logging out with a valid refresh token returns 200 with the message "Logged out"."""
    resp = client.post(
        "/auth/logout",
        json={"refresh_token": auth_tokens["refresh_token"]},
    )
    assert resp.status_code == 200
    assert resp.json()["message"] == "Logged out"


def test_access_token_revoked_after_logout(client, registered_user):
    """Access token must be invalid immediately after logout."""
    login_resp = client.post("/auth/login", json=registered_user)
    tokens = login_resp.json()

    valid_resp = client.post("/auth/validate", json={"token": tokens["access_token"]})
    assert valid_resp.json()["valid"] is True

    client.post("/auth/logout", json={
        "refresh_token": tokens["refresh_token"],
        "access_token": tokens["access_token"],
    })

    invalid_resp = client.post("/auth/validate", json={"token": tokens["access_token"]})
    assert invalid_resp.json()["valid"] is False


def test_refresh_fails_after_logout(client, registered_user):
    """Refresh token must be invalid after logout."""
    login_resp = client.post("/auth/login", json=registered_user)
    tokens = login_resp.json()

    client.post("/auth/logout", json={
        "refresh_token": tokens["refresh_token"],
        "access_token": tokens["access_token"],
    })

    refresh_resp = client.post(
        "/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
    assert refresh_resp.status_code == 401


def test_logout_without_access_token_still_works(client, registered_user):
    """Logout must work even if access_token is not provided."""
    login_resp = client.post("/auth/login", json=registered_user)
    tokens = login_resp.json()

    resp = client.post("/auth/logout", json={
        "refresh_token": tokens["refresh_token"],
    })
    assert resp.status_code == 200
    assert resp.json()["message"] == "Logged out"
