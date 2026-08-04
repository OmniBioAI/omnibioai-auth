import uuid

import pytest

from app.services import org_service, role_service


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"oauthclient-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


@pytest.fixture
def org(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "OAuth Client Test Org", "slug": f"oauth-client-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def test_create_oauth_client_returns_secret_once(client, org):
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "CI integration", "scopes": ["manage_teams"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == "CI integration"
    assert data["scopes"] == ["manage_teams"]
    assert data["client_id"].startswith("omni_client_")
    assert len(data["client_secret"]) == 40


def test_create_oauth_client_rejects_scope_caller_does_not_hold(client, org):
    """org_admin holds manage_org/manage_teams/manage_api_keys/
    manage_oauth_clients -- a scope outside that set must be rejected, same
    guard as api_keys."""
    resp = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "Overreaching", "scopes": ["manage_org", "some_permission_nobody_has"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_list_oauth_clients_never_exposes_secret_or_hash(client, org):
    create = client.post(
        f"/orgs/{org['id']}/oauth-clients",
        json={"name": "Listed client", "scopes": []},
        headers=org["owner_headers"],
    )
    secret = create.json()["client_secret"]

    listed = client.get(f"/orgs/{org['id']}/oauth-clients", headers=org["owner_headers"])
    assert listed.status_code == 200
    body = listed.json()
    assert any(c["name"] == "Listed client" for c in body)
    serialized = str(body)
    assert secret not in serialized
    assert "client_secret_hash" not in serialized


def test_revoke_oauth_client(client, org):
    create = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "Revoke me", "scopes": []}, headers=org["owner_headers"]
    )
    client_row_id = create.json()["id"]

    resp = client.delete(f"/orgs/{org['id']}/oauth-clients/{client_row_id}", headers=org["owner_headers"])
    assert resp.status_code == 204

    listed = client.get(f"/orgs/{org['id']}/oauth-clients", headers=org["owner_headers"])
    revoked = next(c for c in listed.json() if c["id"] == client_row_id)
    assert revoked["status"] == "revoked"


def test_missing_token_rejected(client, org):
    resp = client.get(f"/orgs/{org['id']}/oauth-clients")
    assert resp.status_code in (401, 403)


# ── Cross-org isolation ──────────────────────────────────────────────────────


def test_non_member_cannot_list_or_revoke_oauth_clients(client, org):
    create = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "Protected", "scopes": []}, headers=org["owner_headers"]
    )
    client_row_id = create.json()["id"]

    outsider = _register_and_login(client)
    outsider_headers = _auth_header(outsider["access_token"])

    listed = client.get(f"/orgs/{org['id']}/oauth-clients", headers=outsider_headers)
    assert listed.status_code == 404

    revoke = client.delete(f"/orgs/{org['id']}/oauth-clients/{client_row_id}", headers=outsider_headers)
    assert revoke.status_code == 404

    still_listed = client.get(f"/orgs/{org['id']}/oauth-clients", headers=org["owner_headers"])
    assert next(c for c in still_listed.json() if c["id"] == client_row_id)["status"] == "active"


def test_oauth_client_from_org_a_not_reachable_via_org_b(client, org):
    create = client.post(
        f"/orgs/{org['id']}/oauth-clients", json={"name": "Org A client", "scopes": []}, headers=org["owner_headers"]
    )
    client_row_id = create.json()["id"]

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    other_org = client.post(
        "/orgs",
        json={"name": "Org B", "slug": f"org-b-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    ).json()

    resp = client.delete(f"/orgs/{other_org['id']}/oauth-clients/{client_row_id}", headers=other_headers)
    assert resp.status_code == 404


# ── ensure_org_admin_permissions (startup top-up) ───────────────────────────


def test_ensure_org_admin_permissions_tops_up_existing_role_additively(client):
    """Simulates a pre-Phase-2 deployment: an org_admin Role that already
    exists with only the Phase 1 permission set. The startup top-up must
    add manage_oauth_clients without disturbing anything else already on
    the role (including a permission an operator added by hand outside
    ORG_ADMIN_PERMISSIONS entirely)."""
    from app.db.session import SessionLocal
    db = SessionLocal()
    try:
        role = role_service.get_or_create_role(db, org_service.ORG_ADMIN_ROLE, ["manage_org"])
        db.commit()
        # PR4: update_role_permissions now validates against the Permission
        # Registry, so the "operator added something by hand" stand-in must
        # be a registered (if unrelated to ORG_ADMIN_PERMISSIONS) name rather
        # than an arbitrary string.
        role_service.update_role_permissions(db, role, ["manage_org", "workflow.execute"])

        org_service.ensure_org_admin_permissions(db)

        db.refresh(role)
        names = {p.name for p in role.permissions}
        assert "manage_oauth_clients" in names
        assert "workflow.execute" in names  # untouched, not removed
    finally:
        db.close()
