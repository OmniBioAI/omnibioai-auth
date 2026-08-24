import uuid

from app.core.jwt import decode_token
from app.rbac import require_service_scope
from fastapi import HTTPException


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"oauthtoken-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _org_with_client(client, scopes=None):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org = client.post(
        "/orgs",
        json={"name": "Token Test Org", "slug": f"token-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "token-test-client", "scopes": scopes if scopes is not None else ["manage_teams"]},
        headers=headers,
    ).json()
    return org, created  # created has client_id, client_secret, scopes


# ── Happy path ────────────────────────────────────────────────────────────────


def test_client_credentials_issues_token_with_org_and_scopes(client):
    org, oc = _org_with_client(client, scopes=["manage_teams", "manage_org"])

    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] > 0
    assert set(body["scope"].split()) == {"manage_teams", "manage_org"}
    assert "refresh_token" not in body  # RFC 6749 SS4.4.3 -- client_credentials never issues one

    payload = decode_token(body["access_token"])
    assert payload["org_id"] == org["id"]
    assert payload["auth_method"] == "client_credentials"
    assert payload["client_id"] == oc["client_id"]
    assert "sub" not in payload
    assert "email" not in payload
    assert set(payload["scopes"]) == {"manage_teams", "manage_org"}


def test_client_credentials_narrows_scope_on_request(client):
    _, oc = _org_with_client(client, scopes=["manage_teams", "manage_org"])

    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
            "scope": "manage_teams",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["scope"] == "manage_teams"
    payload = decode_token(resp.json()["access_token"])
    assert payload["scopes"] == ["manage_teams"]


def test_client_credentials_rejects_widened_scope_request(client):
    _, oc = _org_with_client(client, scopes=["manage_teams"])

    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
            "scope": "manage_teams manage_org",  # manage_org was never granted
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "invalid_scope"


def test_client_credentials_via_http_basic(client):
    """RFC 6749 SS2.3.1 -- Basic auth is an equally valid way to present
    client_id/client_secret, not just body fields."""
    _, oc = _org_with_client(client)

    resp = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        auth=(oc["client_id"], oc["client_secret"]),
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


# ── Rejections ───────────────────────────────────────────────────────────────


def test_unsupported_grant_type_rejected(client):
    _, oc = _org_with_client(client)
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
        },
    )
    assert resp.status_code == 400
    assert resp.json()["detail"] == "unsupported_grant_type"


def test_wrong_secret_rejected(client):
    _, oc = _org_with_client(client)
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": "not-the-real-secret",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_client"


def test_unknown_client_id_rejected(client):
    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "omni_client_this_was_never_issued",
            "client_secret": "whatever",
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_client"


def test_revoked_client_rejected(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    fresh_org = client.post(
        "/orgs",
        json={"name": "Revoke Token Org", "slug": f"revoke-token-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    created = client.post(
        f"/orgs/{fresh_org['id']}/oauth-clients",
        json={"name": "to-revoke", "scopes": []},
        headers=headers,
    ).json()
    client.delete(f"/orgs/{fresh_org['id']}/oauth-clients/{created['id']}", headers=headers)

    resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": created["client_id"],
            "client_secret": created["client_secret"],
        },
    )
    assert resp.status_code == 401
    assert resp.json()["detail"] == "invalid_client"


def test_missing_credentials_rejected(client):
    resp = client.post("/oauth/token", data={"grant_type": "client_credentials"})
    assert resp.status_code == 400


# ── require_service_scope isolation from user identity ─────────────────────


def test_service_token_rejected_by_get_current_user_dependent_route(client):
    """A client_credentials token has no sub/email -- it must never satisfy
    a route that expects a real user (e.g. /license/status), and must fail
    closed (401/403), never crash or silently resolve to some account."""
    _, oc = _org_with_client(client)
    token_resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
        },
    )
    service_token = token_resp.json()["access_token"]

    resp = client.get("/license/status", headers=_auth_header(service_token))
    assert resp.status_code in (401, 403, 404)


def test_user_token_rejected_by_require_service_scope(client):
    """The inverse: a normal user JWT must not satisfy a service-scope
    check meant for client_credentials tokens."""
    user = _register_and_login(client)
    payload = decode_token(user["access_token"])
    assert payload.get("auth_method") != "client_credentials"

    dependency = require_service_scope("manage_teams")

    class _Creds:
        credentials = user["access_token"]

    try:
        dependency(token=_Creds())
        assert False, "expected require_service_scope to reject a user token"
    except HTTPException as e:
        assert e.status_code == 403


def test_service_token_with_correct_scope_passes_require_service_scope(client):
    _, oc = _org_with_client(client, scopes=["manage_teams"])
    token_resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
        },
    )
    service_token = token_resp.json()["access_token"]

    dependency = require_service_scope("manage_teams")

    class _Creds:
        credentials = service_token

    payload = dependency(token=_Creds())
    assert payload["auth_method"] == "client_credentials"


def test_service_token_missing_scope_rejected_by_require_service_scope(client):
    _, oc = _org_with_client(client, scopes=["manage_teams"])
    token_resp = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": oc["client_id"],
            "client_secret": oc["client_secret"],
        },
    )
    service_token = token_resp.json()["access_token"]

    dependency = require_service_scope("manage_org")  # not granted to this client

    class _Creds:
        credentials = service_token

    try:
        dependency(token=_Creds())
        assert False, "expected require_service_scope to reject an insufficient scope"
    except HTTPException as e:
        assert e.status_code == 403

# ── First-party platform-owner authorization-code flow ───────────────────────


def test_first_party_owner_authorize_returns_opaque_single_use_code(client, monkeypatch):
    from app.api import routes_oauth_token
    from app.core.config import settings
    from app.main import app

    monkeypatch.setattr(settings, "LIMS_SSO_CLIENT_ID", "lims-test-client")
    monkeypatch.setattr(settings, "LIMS_SSO_CLIENT_SECRET", "lims-test-secret")
    monkeypatch.setattr(settings, "LIMS_SSO_REDIRECT_URI", "https://lims.test/sso/callback")
    import fakeredis
    codes = fakeredis.FakeStrictRedis(decode_responses=True)
    monkeypatch.setattr(routes_oauth_token, "_codes", codes)
    owner = _register_and_login(client)
    _grant_platform_admin_for_sso(owner["email"])
    token = client.post("/auth/login", json=owner).json()["access_token"]

    response = client.get(
        "/oauth/authorize",
        params={
            "client_id": "lims-test-client",
            "redirect_uri": "https://lims.test/sso/callback",
            "response_type": "code",
            "state": "state-value-123456",
            "nonce": "nonce-value-123456",
        },
        headers=_auth_header(token),
        follow_redirects=False,
    )
    assert response.status_code == 302
    location = response.headers["location"]
    code = location.split("code=", 1)[1].split("&", 1)[0]
    assert "." not in code  # opaque; no signed JWT in the browser URL
    assert "state=state-value-123456" in location
    assert codes.scan_iter(match="oauth:first-party:*")


def _grant_platform_admin_for_sso(email: str) -> None:
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from app.db.models import Role, User
    db = sessionmaker(bind=create_engine("sqlite:///./test.db"))()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def test_first_party_code_redemption_is_single_use_and_returns_state(client, monkeypatch):
    from app.api import routes_oauth_token
    from app.core.config import settings
    import fakeredis

    monkeypatch.setattr(settings, "LIMS_SSO_CLIENT_ID", "lims-test-client-2")
    monkeypatch.setattr(settings, "LIMS_SSO_CLIENT_SECRET", "lims-test-secret-2")
    monkeypatch.setattr(settings, "LIMS_SSO_REDIRECT_URI", "https://lims.test/sso/callback")
    codes = fakeredis.FakeStrictRedis(decode_responses=True)
    monkeypatch.setattr(routes_oauth_token, "_codes", codes)
    owner = _register_and_login(client)
    _grant_platform_admin_for_sso(owner["email"])
    token = client.post("/auth/login", json=owner).json()["access_token"]
    authorize = client.get(
        "/oauth/authorize",
        params={"client_id": "lims-test-client-2", "redirect_uri": "https://lims.test/sso/callback", "response_type": "code", "state": "state-value-234567"},
        headers=_auth_header(token), follow_redirects=False,
    )
    code = authorize.headers["location"].split("code=", 1)[1].split("&", 1)[0]
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": "https://lims.test/sso/callback"}
    redeemed = client.post("/oauth/token/authorization-code", data=form, auth=("lims-test-client-2", "lims-test-secret-2"))
    assert redeemed.status_code == 200
    assert redeemed.json()["state"] == "state-value-234567"
    assert client.post("/oauth/token/authorization-code", data=form, auth=("lims-test-client-2", "lims-test-secret-2")).status_code == 400
