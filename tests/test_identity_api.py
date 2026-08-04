"""PR8 (Enterprise IAM Foundation): GET /me and
GET /platform/users/{user_id}/identity -- the Identity & Effective
Authorization API, the canonical identity projection downstream services
are meant to consume after validating a JWT. Mirrors
test_platform_permissions_api.py's/test_organization_role_assignment_api.py's
own conventions for fixtures and direct-DB test setup.
"""
import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Permission, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"identity-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


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


def _make_org(client, owner):
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs", json={"name": f"Identity Org {uuid.uuid4().hex[:6]}", "slug": f"identity-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "headers": headers}


PERMISSION_METADATA_KEYS = {
    "name", "resource", "action", "scope", "category",
    "description", "legacy", "deprecated", "deprecated_reason",
}


# ── GET /me -- basic shape ───────────────────────────────────────────────────


def test_get_my_identity_returns_user_profile(client):
    user = _register_and_login(client)
    user_id = _user_id(client, user["access_token"])

    resp = client.get("/me", headers=_auth_header(user["access_token"]))
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["id"] == user_id
    assert body["user"]["email"] == user["email"]
    assert body["user"]["status"] == "active"


def test_get_my_identity_new_user_has_baseline_role_no_orgs(client):
    user = _register_and_login(client)
    resp = client.get("/me", headers=_auth_header(user["access_token"]))
    body = resp.json()
    assert {r["name"] for r in body["global_roles"]} == {"user"}
    assert body["global_permissions"] == []
    assert body["organizations"] == []


def test_get_my_identity_missing_token_rejected(client):
    resp = client.get("/me")
    assert resp.status_code in (401, 403)


# ── GET /me -- organizations ─────────────────────────────────────────────────


def test_get_my_identity_single_organization(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    resp = client.get("/me", headers=_auth_header(owner["access_token"]))
    body = resp.json()
    assert len(body["organizations"]) == 1
    org_row = body["organizations"][0]
    assert org_row["organization_id"] == org["id"]
    assert "org_admin" in org_row["roles"]
    assert "manage_org" in org_row["effective_permissions"]


def test_get_my_identity_multiple_organizations(client):
    owner = _register_and_login(client)
    org_a = _make_org(client, owner)
    org_b = _make_org(client, owner)

    resp = client.get("/me", headers=_auth_header(owner["access_token"]))
    body = resp.json()
    org_ids = {o["organization_id"] for o in body["organizations"]}
    assert org_ids == {org_a["id"], org_b["id"]}


def test_get_my_identity_effective_permissions_match_org_service(client):
    """Identity consistency with existing RBAC -- must exactly match
    org_service.permissions_for_membership's own computation, not
    something independently derived."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    resp = client.get("/me", headers=_auth_header(owner["access_token"]))
    org_row = next(o for o in resp.json()["organizations"] if o["organization_id"] == org["id"])

    from app.services import org_service as _org_service
    db = _DirectSession()
    try:
        membership = _org_service.get_membership(db, org["id"], owner_id)
        expected = _org_service.permissions_for_membership(membership)
    finally:
        db.close()
    assert set(org_row["effective_permissions"]) == expected


def test_get_my_identity_global_permissions_match_jwt_claim(client):
    """No new authorization logic -- global_permissions must match exactly
    what auth_service.build_user_claims already put in this user's own
    access token."""
    owner = _register_and_login(client)
    validate = client.post("/auth/validate", json={"token": owner["access_token"]})
    jwt_permissions = set(validate.json().get("permissions", []))

    resp = client.get("/me", headers=_auth_header(owner["access_token"]))
    assert set(resp.json()["global_permissions"]) == jwt_permissions


# ── expand_permissions ────────────────────────────────────────────────────────


def test_get_my_identity_expand_permissions_false_is_default(client):
    owner = _register_and_login(client)
    default = client.get("/me", headers=_auth_header(owner["access_token"])).json()
    explicit_false = client.get(
        "/me", params={"expand_permissions": "false"}, headers=_auth_header(owner["access_token"])
    ).json()
    assert default == explicit_false
    assert all(isinstance(p, str) for p in default["global_permissions"])


def test_get_my_identity_expand_permissions_true_returns_full_metadata(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    resp = client.get("/me", params={"expand_permissions": "true"}, headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 200
    body = resp.json()
    org_row = next(o for o in body["organizations"] if o["organization_id"] == org["id"])
    assert all(isinstance(p, dict) for p in org_row["effective_permissions"])
    manage_org_entry = next(p for p in org_row["effective_permissions"] if p["name"] == "manage_org")
    assert set(manage_org_entry.keys()) == PERMISSION_METADATA_KEYS
    assert manage_org_entry["category"] == "organization"


# ── GET /platform/users/{user_id}/identity ───────────────────────────────────


def test_platform_identity_lookup_matches_me_for_same_user(client):
    owner = _register_and_login(client)
    _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    platform_admin = _platform_admin(client)

    me = client.get("/me", headers=_auth_header(owner["access_token"])).json()
    platform_view = client.get(f"/platform/users/{owner_id}/identity", headers=platform_admin["headers"]).json()
    assert me == platform_view


def test_platform_identity_lookup_nonexistent_user_404s(client):
    platform_admin = _platform_admin(client)
    resp = client.get("/platform/users/999999999/identity", headers=platform_admin["headers"])
    assert resp.status_code == 404


def test_platform_identity_lookup_unauthorized_caller_403s(client):
    owner = _register_and_login(client)
    owner_id = _user_id(client, owner["access_token"])
    outsider = _register_and_login(client)
    resp = client.get(f"/platform/users/{owner_id}/identity", headers=_auth_header(outsider["access_token"]))
    assert resp.status_code == 403


def test_platform_identity_lookup_expand_permissions_true(client):
    owner = _register_and_login(client)
    _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    platform_admin = _platform_admin(client)

    resp = client.get(
        f"/platform/users/{owner_id}/identity",
        params={"expand_permissions": "true"},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200
    org_row = resp.json()["organizations"][0]
    assert all(isinstance(p, dict) for p in org_row["effective_permissions"])


# ── Registry drift -> 500 (single-subject, strict) ──────────────────────────


def test_me_500s_on_registry_drift_when_expanded(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    db = _DirectSession()
    drifted_name = f"not_in_registry_{uuid.uuid4().hex[:8]}"
    try:
        drifted_perm = Permission(name=drifted_name)
        db.add(drifted_perm)
        role_name = f"pr8-drift-role-{uuid.uuid4().hex[:8]}"
        role = Role(name=role_name, permissions=[drifted_perm])
        db.add(role)
        db.commit()

        from app.db.models import OrganizationMembership as _OM
        membership = db.query(_OM).filter(
            _OM.organization_id == org["id"], _OM.user_id == owner_id,
        ).first()
        membership.roles = list(membership.roles) + [role]
        db.commit()

        resp = client.get(
            "/me", params={"expand_permissions": "true"}, headers=_auth_header(owner["access_token"]),
        )
        assert resp.status_code == 500

        # Non-expanded response is unaffected -- it only ever returns names.
        resp_default = client.get("/me", headers=_auth_header(owner["access_token"]))
        assert resp_default.status_code == 200
        assert drifted_name in {
            p for o in resp_default.json()["organizations"] for p in o["effective_permissions"]
        }
    finally:
        from app.db.models import OrganizationMembership as _OM
        membership = db.query(_OM).filter(
            _OM.organization_id == org["id"], _OM.user_id == owner_id,
        ).first()
        membership.roles = [r for r in membership.roles if r.name != role_name]
        db.commit()
        db.delete(db.query(Role).filter(Role.name == role_name).first())
        db.delete(db.query(Permission).filter(Permission.name == drifted_name).first())
        db.commit()
        db.close()


# ── Backward compatibility ───────────────────────────────────────────────────


def test_new_identity_routes_do_not_affect_existing_auth_validate(client):
    owner = _register_and_login(client)
    resp = client.post("/auth/validate", json={"token": owner["access_token"]})
    assert resp.status_code == 200
    assert "user_id" in resp.json()
