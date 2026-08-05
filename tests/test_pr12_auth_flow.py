"""PR12 SS1 Authentication Flow Validation.

User -> Auth Service (OIDC/OAuth2) -> JWT token -> API Gateway -> Backend
Services. This exercises the omnibioai-auth end of that chain over real
HTTP routes (not unit-level decode_token calls, which are already covered
by test_jwt_iss_aud.py / test_rs256_jwks.py / test_token_revocation.py) --
GET /me is the canonical protected route (Depends(get_current_user),
app/api/routes_identity.py), the same dependency every other authenticated
route in this service uses.
"""
import time
import uuid

from jose import jwt as jose_jwt

from app.core.config import settings


def _unique_user():
    return {
        "email": f"pr12-{uuid.uuid4().hex[:8]}@omnibioai.test",
        "password": "TestPassword123!",
    }


# ---------------------------------------------------------------------------
# valid login succeeds
# ---------------------------------------------------------------------------

def test_valid_login_succeeds(client):
    creds = _unique_user()
    assert client.post("/auth/register", json=creds).status_code == 200

    resp = client.post("/auth/login", json=creds)

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# JWT issued correctly
# ---------------------------------------------------------------------------

def test_jwt_issued_correctly(client):
    creds = _unique_user()
    client.post("/auth/register", json=creds)

    body = client.post("/auth/login", json=creds).json()

    assert "access_token" in body
    assert "refresh_token" in body
    claims = jose_jwt.get_unverified_claims(body["access_token"])
    assert claims["sub"]
    assert claims["type"] == "access"
    assert claims["iss"] == settings.JWT_ISSUER
    assert claims["aud"] == settings.JWT_AUDIENCE


# ---------------------------------------------------------------------------
# JWT validation succeeds
# ---------------------------------------------------------------------------

def test_jwt_validation_succeeds_on_protected_route(client):
    creds = _unique_user()
    client.post("/auth/register", json=creds)
    token = client.post("/auth/login", json=creds).json()["access_token"]

    resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    assert resp.json()["email"] == creds["email"]


# ---------------------------------------------------------------------------
# expired token rejected
# ---------------------------------------------------------------------------

def test_expired_token_rejected(client):
    expired = jose_jwt.encode(
        {"sub": "1", "email": "x@test.com", "type": "access", "exp": int(time.time()) - 60},
        settings.SECRET_KEY,
        algorithm="HS256",
    )

    resp = client.get("/me", headers={"Authorization": f"Bearer {expired}"})

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# invalid signature rejected
# ---------------------------------------------------------------------------

def test_invalid_signature_rejected(client):
    bad = jose_jwt.encode(
        {"sub": "1", "email": "x@test.com", "type": "access", "exp": int(time.time()) + 3600},
        "definitely-not-the-real-secret",
        algorithm="HS256",
    )

    resp = client.get("/me", headers={"Authorization": f"Bearer {bad}"})

    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# missing token rejected
# ---------------------------------------------------------------------------

def test_missing_token_rejected(client):
    resp = client.get("/me")

    assert resp.status_code == 401


def test_malformed_authorization_header_rejected(client):
    resp = client.get("/me", headers={"Authorization": "NotBearer garbage"})

    assert resp.status_code == 401
