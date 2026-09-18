"""PR12 SS1 Authentication Flow Validation.

User -> Auth Service (OIDC/OAuth2) -> JWT token -> API Gateway -> Backend
Services. This exercises the omnibioai-auth end of that chain over real
HTTP routes (not unit-level decode_token calls, which are already covered
by test_jwt_iss_aud.py / test_rs256_jwks.py / test_token_revocation.py) --
GET /me is the canonical protected route (Depends(get_current_user),
app/api/routes_identity.py), the same dependency every other authenticated
route in this service uses.

Developer: Manish Kumar <manish@omnibioai.org>
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
    """A newly registered user can log in with the same credentials and receives 200."""
    creds = _unique_user()
    assert client.post("/auth/register", json=creds).status_code == 200

    resp = client.post("/auth/login", json=creds)

    assert resp.status_code == 200


# ---------------------------------------------------------------------------
# JWT issued correctly
# ---------------------------------------------------------------------------

def test_jwt_issued_correctly(client):
    """Login returns access and refresh tokens, and the access token carries a subject, type
    "access" and the configured issuer and audience.
    """
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
    """A freshly issued access token is accepted by the protected /me route, which returns the
    user's email.
    """
    creds = _unique_user()
    client.post("/auth/register", json=creds)
    token = client.post("/auth/login", json=creds).json()["access_token"]

    resp = client.get("/me", headers={"Authorization": f"Bearer {token}"})

    assert resp.status_code == 200
    # GET /me returns IdentityOut: {user: CurrentUserOut, global_roles, ...} --
    # email is nested under "user", not top-level.
    assert resp.json()["user"]["email"] == creds["email"]


# ---------------------------------------------------------------------------
# expired token rejected
# ---------------------------------------------------------------------------

def test_expired_token_rejected(client):
    """An expired access token is rejected by /me with 401."""
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
    """A token signed with the wrong key is rejected by /me with 401."""
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
    """/me without a bearer token returns 401."""
    resp = client.get("/me")

    assert resp.status_code == 401


def test_malformed_authorization_header_rejected(client):
    """/me with an Authorization header that is not a Bearer credential returns 401."""
    resp = client.get("/me", headers={"Authorization": "NotBearer garbage"})

    assert resp.status_code == 401
