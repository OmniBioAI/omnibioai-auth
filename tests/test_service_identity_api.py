"""PR9 (Enterprise IAM Foundation): GET /service/me and
GET /platform/services/{client_id} -- the Service Identity API, unifying
OAuth client scopes and the Permission Registry vocabulary. Mirrors
test_oauth_clients.py's own org/oauth-client fixtures and
test_identity_api.py's own platform-admin fixture.
"""
import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import OAuthClient, Permission, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"svc-identity-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


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


def _grant_platform_admin(email: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _platform_admin(client):
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "Service Identity Org", "slug": f"svc-identity-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _grant_owner_permissions(client, admin_headers, org, permissions):
    """create_oauth_client's existing privilege-escalation guard (unrelated
    to and unmodified by PR9) rejects granting an OAuth client a scope the
    issuing user doesn't personally hold -- org_admin's default permission
    set doesn't include any of PR9's future-registry test scopes
    (dataset.read, model.use, etc.), so tests exercising those must grant
    the org owner an extra role carrying them first, mirroring
    test_organization_role_assignment_api.py's own _make_extra_role
    pattern. Uses a platform admin as the granting caller, not the owner
    acting on themselves -- routes_orgs.py's own self-escalation guard
    would otherwise block an owner from widening their own effective
    permissions, even via a platform-admin-equivalent bypass path."""
    role_name = f"svc-grant-role-{uuid.uuid4().hex[:8]}"
    created = client.post("/roles", json={"name": role_name, "permissions": permissions}, headers=admin_headers)
    assert created.status_code == 201, created.text
    owner_id = _user_id(client, org["owner"]["access_token"])
    platform_admin = _platform_admin(client)
    assigned = client.post(
        f"/orgs/{org['id']}/members/{owner_id}/roles", json={"role": role_name}, headers=platform_admin["headers"],
    )
    assert assigned.status_code == 201, assigned.text


def _create_oauth_client(client, org, scopes, name="test-service"):
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": name, "scopes": scopes},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201, resp.text
    return resp.json()


def _service_token(client, oauth_client, scope=None):
    body = {
        "grant_type": "client_credentials",
        "client_id": oauth_client["client_id"],
        "client_secret": oauth_client["client_secret"],
    }
    if scope:
        body["scope"] = scope
    resp = client.post("/oauth/token", data=body)
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


PERMISSION_METADATA_KEYS = {
    "name", "resource", "action", "scope", "category",
    "description", "legacy", "deprecated", "deprecated_reason",
}


# ── Service token authentication + GET /service/me ──────────────────────────


def test_service_token_can_reach_service_me(client, org):
    oauth_client = _create_oauth_client(client, org, ["manage_org"])
    token = _service_token(client, oauth_client)

    resp = client.get("/service/me", headers=_auth_header(token))
    assert resp.status_code == 200
    body = resp.json()
    assert body["client_id"] == oauth_client["client_id"]
    assert body["organization_id"] == org["id"]
    assert body["permissions"] == ["manage_org"]
    assert body["active"] is True


def test_service_me_reflects_token_scopes_not_full_client_scopes(client, org):
    """/service/me mirrors PR8's /me contract: it reflects *this token's*
    granted scopes, not necessarily the client's full configured set."""
    oauth_client = _create_oauth_client(client, org, ["manage_org", "manage_teams"])
    narrow_token = _service_token(client, oauth_client, scope="manage_org")

    resp = client.get("/service/me", headers=_auth_header(narrow_token))
    assert resp.json()["permissions"] == ["manage_org"]


def test_service_me_missing_token_rejected(client):
    resp = client.get("/service/me")
    assert resp.status_code in (401, 403)


def test_user_jwt_cannot_access_service_me(client):
    """Authorization must be strictly separated by token type: a human
    user JWT is not a service identity."""
    user = _register_and_login(client)
    resp = client.get("/service/me", headers=_auth_header(user["access_token"]))
    assert resp.status_code == 403


def test_service_token_cannot_access_me(client, org):
    """The inverse direction -- a service token must not be able to
    satisfy GET /me (PR8), which already rejects client_credentials
    tokens (Phase 2 PR1); this just confirms that existing behavior still
    holds after PR9."""
    oauth_client = _create_oauth_client(client, org, [])
    token = _service_token(client, oauth_client)
    resp = client.get("/me", headers=_auth_header(token))
    assert resp.status_code == 401


def test_inactive_service_rejected_from_service_me(client, org):
    oauth_client = _create_oauth_client(client, org, ["manage_org"])
    token = _service_token(client, oauth_client)

    revoke = client.delete(
        f"/orgs/{org['id']}/oauth-clients/{oauth_client['id']}", headers=org["owner_headers"],
    )
    assert revoke.status_code == 204

    resp = client.get("/service/me", headers=_auth_header(token))
    assert resp.status_code == 403


# ── Platform service lookup ─────────────────────────────────────────────────


def test_platform_admin_can_look_up_service_by_client_id(client, org, admin_headers):
    _grant_owner_permissions(client, admin_headers, org, ["dataset.read"])
    oauth_client = _create_oauth_client(client, org, ["dataset.read"])
    platform_admin = _platform_admin(client)

    resp = client.get(f"/platform/services/{oauth_client['client_id']}", headers=platform_admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["client_id"] == oauth_client["client_id"]
    assert body["permissions"] == ["dataset.read"]
    assert body["active"] is True


def test_platform_lookup_shows_revoked_client_as_inactive_not_missing(client, org):
    oauth_client = _create_oauth_client(client, org, [])
    client.delete(f"/orgs/{org['id']}/oauth-clients/{oauth_client['id']}", headers=org["owner_headers"])
    platform_admin = _platform_admin(client)

    resp = client.get(f"/platform/services/{oauth_client['client_id']}", headers=platform_admin["headers"])
    assert resp.status_code == 200
    assert resp.json()["active"] is False


def test_platform_lookup_nonexistent_client_404s(client):
    platform_admin = _platform_admin(client)
    resp = client.get("/platform/services/does-not-exist", headers=platform_admin["headers"])
    assert resp.status_code == 404


def test_non_platform_admin_cannot_look_up_service(client, org):
    oauth_client = _create_oauth_client(client, org, [])
    outsider = _register_and_login(client)
    resp = client.get(
        f"/platform/services/{oauth_client['client_id']}", headers=_auth_header(outsider["access_token"]),
    )
    assert resp.status_code == 403


def test_service_token_cannot_access_platform_lookup(client, org):
    oauth_client = _create_oauth_client(client, org, [])
    token = _service_token(client, oauth_client)
    resp = client.get(f"/platform/services/{oauth_client['client_id']}", headers=_auth_header(token))
    assert resp.status_code == 401


# ── Permission expansion ─────────────────────────────────────────────────────


def test_service_me_expand_permissions_true_returns_full_metadata(client, org, admin_headers):
    _grant_owner_permissions(client, admin_headers, org, ["dataset.read"])
    oauth_client = _create_oauth_client(client, org, ["dataset.read"])
    token = _service_token(client, oauth_client)

    resp = client.get("/service/me", params={"expand_permissions": "true"}, headers=_auth_header(token))
    assert resp.status_code == 200
    entry = resp.json()["permissions"][0]
    assert set(entry.keys()) == PERMISSION_METADATA_KEYS
    assert entry["name"] == "dataset.read"
    assert entry["category"] == "dataset"


def test_service_me_expand_permissions_false_is_default(client, org, admin_headers):
    _grant_owner_permissions(client, admin_headers, org, ["dataset.read"])
    oauth_client = _create_oauth_client(client, org, ["dataset.read"])
    token = _service_token(client, oauth_client)

    default = client.get("/service/me", headers=_auth_header(token)).json()
    explicit = client.get(
        "/service/me", params={"expand_permissions": "false"}, headers=_auth_header(token)
    ).json()
    assert default == explicit
    assert default["permissions"] == ["dataset.read"]


def test_platform_lookup_expand_permissions_true(client, org, admin_headers):
    _grant_owner_permissions(client, admin_headers, org, ["model.use"])
    oauth_client = _create_oauth_client(client, org, ["model.use"])
    platform_admin = _platform_admin(client)

    resp = client.get(
        f"/platform/services/{oauth_client['client_id']}",
        params={"expand_permissions": "true"},
        headers=platform_admin["headers"],
    )
    entry = resp.json()["permissions"][0]
    assert entry["name"] == "model.use"
    assert entry["resource"] == "model"


# ── Registry validation on OAuth client creation ─────────────────────────────


def test_create_oauth_client_rejects_unregistered_scope(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "typo-client", "scopes": ["workflow.excute"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    assert "workflow.excute" in resp.json()["detail"]


def test_create_oauth_client_unregistered_scope_suggests_nearest_match(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "typo-client-2", "scopes": ["workflow.excute"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400
    assert "workflow.execute" in resp.json()["detail"]


def test_create_oauth_client_with_random_admin_scope_rejected(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "random-admin-client", "scopes": ["random.admin"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_create_oauth_client_with_registered_scopes_succeeds(client, org, admin_headers):
    _grant_owner_permissions(client, admin_headers, org, ["workflow.execute", "model.use", "dataset.read"])
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "valid-client", "scopes": ["workflow.execute", "model.use", "dataset.read"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    assert set(resp.json()["scopes"]) == {"workflow.execute", "model.use", "dataset.read"}


# ── Registry consistency / drift ─────────────────────────────────────────────


def test_service_identity_permissions_are_all_known_to_registry(client, org, admin_headers):
    from app.core.permission_names import is_known_permission

    _grant_owner_permissions(client, admin_headers, org, ["billing.read", "usage.read"])
    oauth_client = _create_oauth_client(client, org, ["billing.read", "usage.read"])
    token = _service_token(client, oauth_client)

    resp = client.get("/service/me", headers=_auth_header(token))
    for name in resp.json()["permissions"]:
        assert is_known_permission(name)


def test_service_me_500s_on_registry_drift_when_expanded(client, org):
    oauth_client = _create_oauth_client(client, org, ["manage_org"])
    token = _service_token(client, oauth_client)

    db = _DirectSession()
    drifted_name = f"not_in_registry_{uuid.uuid4().hex[:8]}"
    try:
        row = db.query(OAuthClient).filter(OAuthClient.client_id == oauth_client["client_id"]).first()
        row.scopes = list(row.scopes or []) + [drifted_name]
        db.add(Permission(name=drifted_name))
        db.commit()

        # The JWT's own "scopes" claim already includes only what was
        # granted at token-issuance time (manage_org), so a *new* token is
        # needed to pick up the drifted scope now present on the client row.
        token2 = _service_token(client, oauth_client, scope=f"manage_org {drifted_name}")

        resp = client.get(
            "/service/me", params={"expand_permissions": "true"}, headers=_auth_header(token2),
        )
        assert resp.status_code == 500

        resp_default = client.get("/service/me", headers=_auth_header(token2))
        assert resp_default.status_code == 200
        assert drifted_name in resp_default.json()["permissions"]
    finally:
        row = db.query(OAuthClient).filter(OAuthClient.client_id == oauth_client["client_id"]).first()
        row.scopes = [s for s in (row.scopes or []) if s != drifted_name]
        db.commit()
        db.delete(db.query(Permission).filter(Permission.name == drifted_name).first())
        db.commit()
        db.close()


# ── Backward compatibility ───────────────────────────────────────────────────


def test_existing_oauth_token_flow_unaffected(client, org):
    oauth_client = _create_oauth_client(client, org, ["manage_teams"])
    token = _service_token(client, oauth_client)
    validate_style = client.get("/service/me", headers=_auth_header(token))
    assert validate_style.status_code == 200
