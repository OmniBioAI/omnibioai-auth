"""Phase 1 PR3: JWT v2 org context (org_id, org_role, auth_method,
token_version), and proof that the existing v1 shape keeps working
unmodified for anything still reading only sub/email/roles/permissions.
"""

import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_access_token, decode_token
from app.services.auth_service import generate_tokens

# Same physical file conftest.py's `client` fixture uses -- see
# tests/test_apikeys.py for why a direct second connection is used rather
# than going through the HTTP layer for parts of this that need a raw db
# session (auth_method isn't observable via any response field, only by
# decoding the token).
_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"jwt-org-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    resp = client.post("/auth/validate", json={"token": access_token})
    return resp.json()["user_id"]


# ── JWT v2: fields present and correct ──────────────────────────────────────


def test_fresh_login_token_has_v2_fields_no_org_membership(client):
    """A freshly registered user with no org membership yet (no backfill
    has run in this test DB) gets org_id=None/org_role=[] -- a valid,
    well-defined state, not an error -- while still getting
    auth_method/token_version and the unchanged existing claims."""
    user = _register_and_login(client)
    decoded = decode_token(user["access_token"])

    assert decoded["token_version"] == 2
    assert decoded["auth_method"] == "password"
    assert decoded["org_id"] is None
    assert decoded["org_role"] == []
    # Existing claims, unchanged.
    assert decoded["sub"] is not None
    assert decoded["email"] == user["email"]
    assert decoded["roles"] == ["user"]
    assert "manage_roles" not in decoded["permissions"]


def test_login_token_reflects_org_membership(client):
    """Once a user belongs to an org (via PR2's org creation, unrelated to
    backfill), a fresh login token carries that org's id and org-scoped
    role names."""
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "JWT Org Context Test", "slug": f"jwt-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()

    # Re-login to get a fresh token issued after the membership exists.
    relogin = client.post("/auth/login", json={"email": owner["email"], "password": owner["password"]})
    decoded = decode_token(relogin.json()["access_token"])

    assert decoded["org_id"] == org["id"]
    assert decoded["org_role"] == ["org_admin"]
    assert decoded["token_version"] == 2


def test_generate_tokens_accepts_license_auth_method(client):
    """Exercises generate_tokens directly with auth_method="license" --
    the same call site routes_license.py uses -- since asserting on it via
    the HTTP response isn't possible (auth_method isn't a response field,
    only a token claim)."""
    db = _DirectSession()
    try:
        from app.db.models import User

        email = f"license-auth-method-{uuid.uuid4().hex[:8]}@omnibioai.test"
        user = User(email=email, hashed_password=None, status="active")
        db.add(user)
        db.commit()
        db.refresh(user)

        access, _ = generate_tokens(db, user, auth_method="license")
    finally:
        db.close()

    decoded = decode_token(access)
    assert decoded["auth_method"] == "license"
    assert decoded["token_version"] == 2


# ── JWT v1 compatibility ─────────────────────────────────────────────────────


def test_v1_shaped_token_still_decodes_and_validates(client):
    """A token with none of PR3's new claims at all -- exactly what every
    token issued before this change looks like, and what's still sitting
    in already-logged-in users' browsers/Electron caches for up to its
    15-minute lifetime after deploy -- must keep working unmodified."""
    v1_payload = {
        "sub": "999999",
        "email": "v1-token@omnibioai.test",
        "roles": ["user"],
        "permissions": [],
    }
    v1_token = create_access_token(v1_payload)
    decoded = decode_token(v1_token)

    # No PR3 claims present at all -- this is the actual shape of a
    # pre-PR3 token, not a partially-populated v2 one.
    assert "org_id" not in decoded
    assert "org_role" not in decoded
    assert "token_version" not in decoded
    assert "auth_method" not in decoded

    # But everything a v1-only consumer reads is still there and correct.
    assert decoded["sub"] == "999999"
    assert decoded["roles"] == ["user"]


def test_auth_validate_defaults_gracefully_for_v1_token(client):
    """/auth/validate is the actual live endpoint other services call --
    confirms it degrades v1 tokens to sensible defaults (schema_version=1,
    org_id=None) instead of erroring on missing claims."""
    user = _register_and_login(client)  # real v2 token from a real user

    # Simulate a v1 token for the SAME real user by re-signing a payload
    # with none of the new claims -- decode_token/validate must not choke
    # on their absence.
    v1_payload = {
        "sub": str(_user_id(client, user["access_token"])),
        "email": user["email"],
        "roles": ["user"],
        "permissions": [],
    }
    v1_token = create_access_token(v1_payload)

    resp = client.post("/auth/validate", json={"token": v1_token})
    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True
    assert data["roles"] == ["user"]
    assert data["org_id"] is None
    assert data["org_role"] == []
    assert data["schema_version"] == 1


def test_auth_validate_reports_schema_version_2_for_fresh_token(client):
    user = _register_and_login(client)
    resp = client.post("/auth/validate", json={"token": user["access_token"]})
    data = resp.json()
    assert data["schema_version"] == 2
    assert data["auth_method"] == "password"


# ── Cross-org isolation: JWT's org_id claim must never be trusted for authz ──


def test_jwt_org_id_claim_does_not_grant_cross_org_access(client):
    """The whole point of get_org_membership doing a live DB lookup
    (app/rbac.py, Phase 1 PR2) instead of trusting a JWT claim is exactly
    this: even though tokens now carry an org_id, hitting a DIFFERENT
    org's endpoints must still require actual membership, looked up fresh,
    every request -- not "whatever org_id happened to be in the token at
    login time." This is the regression this test locks in."""
    owner_a = _register_and_login(client)
    org_a = client.post(
        "/orgs",
        json={"name": "Org A", "slug": f"jwt-iso-a-{uuid.uuid4().hex[:8]}"},
        headers=_auth_header(owner_a["access_token"]),
    ).json()
    # Fresh token so org_a's id is actually the claim under test.
    relogin_a = client.post("/auth/login", json={"email": owner_a["email"], "password": owner_a["password"]})
    token_a = relogin_a.json()["access_token"]
    assert decode_token(token_a)["org_id"] == org_a["id"]

    owner_b = _register_and_login(client)
    org_b = client.post(
        "/orgs",
        json={"name": "Org B", "slug": f"jwt-iso-b-{uuid.uuid4().hex[:8]}"},
        headers=_auth_header(owner_b["access_token"]),
    ).json()

    # Owner A's token (whose OWN org_id claim points at org_a) tries org_b.
    resp = client.get(f"/orgs/{org_b['id']}", headers=_auth_header(token_a))
    assert resp.status_code == 404
