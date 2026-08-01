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
