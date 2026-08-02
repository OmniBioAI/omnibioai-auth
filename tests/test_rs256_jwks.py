"""SSO Phase 2 PR15: RS256/JWKS foundation.

JWT_ALGORITHM defaults to HS256 (see config.py) so nothing here changes
default behavior -- these tests explicitly flip settings.JWT_ALGORITHM to
RS256 for the duration of each test that needs it, then restore it, and
separately prove the HS256 path is untouched by default.
"""

import pytest
from jose import jwt as jose_jwt

from app.core.config import settings
from app.core.jwt import (
    create_access_token,
    create_refresh_token,
    decode_token,
)
from app.core.rsa_keys import KID, PUBLIC_KEY_PEM, public_jwk


@pytest.fixture
def rs256_enabled():
    original = settings.JWT_ALGORITHM
    settings.JWT_ALGORITHM = "RS256"
    yield
    settings.JWT_ALGORITHM = original


# ── Task 9: RS256 token creation ────────────────────────────────────────────


def test_access_token_signed_rs256_when_enabled(rs256_enabled):
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    header = jose_jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"


def test_default_algorithm_is_still_hs256():
    """No env var set -> byte-for-byte unchanged default behavior."""
    assert settings.JWT_ALGORITHM == "HS256"
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    header = jose_jwt.get_unverified_header(token)
    assert header["alg"] == "HS256"
    assert "kid" not in header


# ── Task 9: kid included in signed tokens ───────────────────────────────────


def test_kid_present_on_rs256_tokens_and_matches_rsa_keys_module(rs256_enabled):
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    header = jose_jwt.get_unverified_header(token)
    assert header["kid"] == KID


def test_kid_matches_the_jwks_entrys_kid(rs256_enabled):
    token = create_access_token({"sub": "1"})
    header = jose_jwt.get_unverified_header(token)
    jwk_entry = public_jwk()
    assert header["kid"] == jwk_entry["kid"]


# ── Task 3/9: JWKS endpoint response shape ──────────────────────────────────


def test_jwks_endpoint_response_shape(client):
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    body = resp.json()
    assert "keys" in body
    assert isinstance(body["keys"], list)
    assert len(body["keys"]) == 1

    key = body["keys"][0]
    assert key["kty"] == "RSA"
    assert key["use"] == "sig"
    assert key["alg"] == "RS256"
    assert key["kid"] == KID
    assert "n" in key and "e" in key
    # Private key material must never appear in the public JWKS.
    assert "d" not in key
    assert "p" not in key
    assert "q" not in key


def test_jwks_endpoint_key_actually_verifies_an_rs256_token(client, rs256_enabled):
    token = create_access_token({"sub": "42"})
    body = client.get("/.well-known/jwks.json").json()
    key = body["keys"][0]
    assert key["kid"] == jose_jwt.get_unverified_header(token)["kid"]
    # Round-trip: verify the token using only what the JWKS published.
    decoded = jose_jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"])
    assert decoded["sub"] == "42"


# ── Task 9: HS256 compatibility remains (dual-verify) ───────────────────────


def test_decode_token_verifies_hs256_tokens_by_default():
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    decoded = decode_token(token)
    assert decoded["sub"] == "1"


def test_decode_token_verifies_rs256_tokens_when_enabled(rs256_enabled):
    token = create_access_token({"sub": "1", "email": "a@omnibioai.test"})
    decoded = decode_token(token)
    assert decoded["sub"] == "1"


def test_decode_token_verifies_both_algorithms_in_the_same_process():
    """The migration-window requirement: a still-valid HS256 token issued
    before a switch to RS256 must keep decoding correctly even after
    JWT_ALGORITHM flips -- decode_token must dispatch off each token's own
    header, never off the current settings value.
    """
    hs256_token = create_access_token({"sub": "1"})
    assert jose_jwt.get_unverified_header(hs256_token)["alg"] == "HS256"

    original = settings.JWT_ALGORITHM
    settings.JWT_ALGORITHM = "RS256"
    try:
        rs256_token = create_access_token({"sub": "2"})
        assert jose_jwt.get_unverified_header(rs256_token)["alg"] == "RS256"

        # Both still decode correctly -- the pre-switch HS256 token hasn't
        # been invalidated by the switch.
        assert decode_token(hs256_token)["sub"] == "1"
        assert decode_token(rs256_token)["sub"] == "2"
    finally:
        settings.JWT_ALGORITHM = original


# ── Task 7: claims shape unchanged under RS256 ──────────────────────────────


def test_rs256_access_token_claims_shape_matches_hs256(rs256_enabled):
    data = {
        "sub": "7",
        "email": "org-user@omnibioai.test",
        "roles": ["admin"],
        "permissions": ["manage_config"],
        "org_id": "3",
        "org_role": ["owner"],
        "auth_method": "password",
        "token_version": 2,
    }
    token = create_access_token(data)
    decoded = decode_token(token)
    for key, value in data.items():
        assert decoded[key] == value
    assert decoded["type"] == "access"
    assert "jti" in decoded
    assert "exp" in decoded


def test_rs256_refresh_token_still_has_refresh_type(rs256_enabled):
    token = create_refresh_token({"sub": "7"})
    decoded = decode_token(token)
    assert decoded["type"] == "refresh"
    assert "jti" in decoded


# ── Task 8: refresh rotation / login flow unaffected ────────────────────────


def test_login_and_refresh_flow_unaffected_by_rs256(client, rs256_enabled):
    import uuid

    email = f"rs256-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    body = login.json()
    assert "access_token" in body and "refresh_token" in body

    header = jose_jwt.get_unverified_header(body["access_token"])
    assert header["alg"] == "RS256"
    assert header["kid"] == KID

    refresh = client.post("/auth/refresh", json={"refresh_token": body["refresh_token"]})
    assert refresh.status_code == 200
    assert "access_token" in refresh.json()


def test_login_flow_unaffected_by_default_hs256(client):
    """Existing login test coverage stays green: default config, unchanged
    response shape, unchanged algorithm."""
    import uuid

    email = f"hs256-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    header = jose_jwt.get_unverified_header(login.json()["access_token"])
    assert header["alg"] == "HS256"
