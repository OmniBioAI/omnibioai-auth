"""PR7 (Enterprise IAM Foundation): /organizations/{organization_id}/... --
the Organization Role Assignment API, the first consumer of PR4's
Permission Registry, PR5's read API, and PR6's RBAC management layer from
the organization side. Deliberately separate from the legacy
/orgs/{org_id}/... surface (routes_orgs.py, untouched by this PR) --
mirrors test_orgs.py's own fixtures/conventions for org creation and
membership setup.
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


def _unique_slug():
    return f"org7-{uuid.uuid4().hex[:8]}"


def _register_and_login(client, email=None):
    email = email or f"org7-{uuid.uuid4().hex[:8]}@omnibioai.test"
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
        "/orgs", json={"name": f"PR7 Org {uuid.uuid4().hex[:6]}", "slug": _unique_slug()}, headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def _make_extra_role(client, admin_headers, permissions):
    """Creates a role via the legacy /roles endpoint (manage_roles-gated,
    the only place roles are actually created) -- reused here purely as
    test setup, not part of what this PR exercises."""
    name = f"pr7-role-{uuid.uuid4().hex[:8]}"
    resp = client.post("/roles", json={"name": name, "permissions": permissions}, headers=admin_headers)
    assert resp.status_code == 201
    return name


# ── 1. Member role inspection ───────────────────────────────────────────────


def test_get_member_roles_returns_full_permission_metadata(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    resp = client.get(f"/organizations/{org['id']}/members/{owner_id}/roles", headers=org["owner_headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["organization_id"] == org["id"]
    assert body["user_id"] == owner_id
    assert body["email"] == owner["email"]
    role_names = {r["name"] for r in body["roles"]}
    assert "org_admin" in role_names
    org_admin_role = next(r for r in body["roles"] if r["name"] == "org_admin")
    assert {p["name"] for p in org_admin_role["permissions"]} >= {"manage_org", "manage_teams"}
    for perm in org_admin_role["permissions"]:
        assert set(perm.keys()) == {
            "name", "resource", "action", "scope", "category",
            "description", "legacy", "deprecated", "deprecated_reason",
        }


def test_get_member_roles_nonexistent_organization_404s(client):
    owner = _register_and_login(client)
    owner_id = _user_id(client, owner["access_token"])
    resp = client.get(f"/organizations/999999999/members/{owner_id}/roles", headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 404


def test_get_member_roles_nonexistent_member_404s(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    resp = client.get(f"/organizations/{org['id']}/members/999999999/roles", headers=org["owner_headers"])
    assert resp.status_code == 404


def test_get_member_roles_unauthorized_caller_403s(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    outsider = _register_and_login(client)
    resp = client.get(
        f"/organizations/{org['id']}/members/{owner_id}/roles", headers=_auth_header(outsider["access_token"]),
    )
    assert resp.status_code in (403, 404)


def test_platform_admin_can_inspect_any_organization_member_roles(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    platform_admin = _platform_admin(client)

    resp = client.get(f"/organizations/{org['id']}/members/{owner_id}/roles", headers=platform_admin["headers"])
    assert resp.status_code == 200


# ── 2. Assign organization roles (full replace) ─────────────────────────────


def test_assign_roles_replaces_existing_assignment(client, admin_headers):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    member = _register_and_login(client)
    member_id = _user_id(client, member["access_token"])
    client.post(f"/orgs/{org['id']}/invite", json={"email": member["email"]}, headers=org["owner_headers"])

    narrow_role = _make_extra_role(client, admin_headers, ["dataset.read"])

    resp = client.post(
        f"/organizations/{org['id']}/members/{member_id}/roles",
        json={"roles": [narrow_role]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 201
    body = resp.json()
    assert {r["name"] for r in body["roles"]} == {narrow_role}

    # Re-assigning replaces, not appends.
    other_role = _make_extra_role(client, admin_headers, ["model.use"])
    resp2 = client.post(
        f"/organizations/{org['id']}/members/{member_id}/roles",
        json={"roles": [other_role]},
        headers=org["owner_headers"],
    )
    assert resp2.status_code == 201
    assert {r["name"] for r in resp2.json()["roles"]} == {other_role}


def test_assign_nonexistent_role_returns_400(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    resp = client.post(
        f"/organizations/{org['id']}/members/{owner_id}/roles",
        json={"roles": ["does-not-exist-role"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_assign_duplicate_role_in_request_returns_400(client, admin_headers):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    role = _make_extra_role(client, admin_headers, [])

    resp = client.post(
        f"/organizations/{org['id']}/members/{owner_id}/roles",
        json={"roles": [role, role]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_assign_roles_nonexistent_member_404s(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    resp = client.post(
        f"/organizations/{org['id']}/members/999999999/roles",
        json={"roles": []},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 404


def test_assign_roles_transaction_rollback_on_invalid_role(client, admin_headers):
    """A request with one valid + one invalid role name must not partially
    apply -- the member's roles stay exactly as they were before."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    member = _register_and_login(client)
    member_id = _user_id(client, member["access_token"])
    client.post(f"/orgs/{org['id']}/invite", json={"email": member["email"]}, headers=org["owner_headers"])

    role = _make_extra_role(client, admin_headers, [])
    client.post(
        f"/organizations/{org['id']}/members/{member_id}/roles",
        json={"roles": [role]},
        headers=org["owner_headers"],
    )

    resp = client.post(
        f"/organizations/{org['id']}/members/{member_id}/roles",
        json={"roles": [role, "does-not-exist-role"]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400

    unchanged = client.get(f"/organizations/{org['id']}/members/{member_id}/roles", headers=org["owner_headers"])
    assert {r["name"] for r in unchanged.json()["roles"]} == {role}


def test_assign_roles_self_escalation_blocked(client, admin_headers):
    """No accept-invite flow exists in this codebase (an invited member's
    status stays "invited", which fails get_org_membership's active-status
    filter, so they can never act on their own membership) -- mirrors
    test_orgs.py's own test_self_escalation_blocked_on_org_roles pattern:
    use the org owner (always active, org_admin by default) as the
    escalating actor, first narrowing their own roles, then attempting to
    widen back beyond what they currently hold."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    narrow_role = _make_extra_role(client, admin_headers, ["manage_org"])
    narrow = client.post(
        f"/organizations/{org['id']}/members/{owner_id}/roles",
        json={"roles": [narrow_role]},
        headers=org["owner_headers"],
    )
    assert narrow.status_code == 201

    wide_role = _make_extra_role(client, admin_headers, ["manage_org", "billing.manage"])
    resp = client.post(
        f"/organizations/{org['id']}/members/{owner_id}/roles",
        json={"roles": [wide_role]},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 403

    unchanged = client.get(f"/organizations/{org['id']}/members/{owner_id}/roles", headers=org["owner_headers"])
    assert {r["name"] for r in unchanged.json()["roles"]} == {narrow_role}


# ── 3. Remove a single role assignment ──────────────────────────────────────


def test_remove_role_by_name(client, admin_headers):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    member = _register_and_login(client)
    member_id = _user_id(client, member["access_token"])
    client.post(f"/orgs/{org['id']}/invite", json={"email": member["email"]}, headers=org["owner_headers"])

    role = _make_extra_role(client, admin_headers, [])
    client.post(
        f"/organizations/{org['id']}/members/{member_id}/roles",
        json={"roles": [role]},
        headers=org["owner_headers"],
    )

    resp = client.delete(
        f"/organizations/{org['id']}/members/{member_id}/roles/{role}", headers=org["owner_headers"],
    )
    assert resp.status_code == 204

    after = client.get(f"/organizations/{org['id']}/members/{member_id}/roles", headers=org["owner_headers"])
    assert role not in {r["name"] for r in after.json()["roles"]}


def test_remove_nonexistent_role_name_404s(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    resp = client.delete(
        f"/organizations/{org['id']}/members/{owner_id}/roles/does-not-exist-role", headers=org["owner_headers"],
    )
    assert resp.status_code == 404


def test_remove_role_not_assigned_to_member_404s(client, admin_headers):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    role = _make_extra_role(client, admin_headers, [])  # never assigned to owner

    resp = client.delete(
        f"/organizations/{org['id']}/members/{owner_id}/roles/{role}", headers=org["owner_headers"],
    )
    assert resp.status_code == 404


# ── 4. List organization members with roles ─────────────────────────────────


def test_list_members_includes_roles_and_permission_names(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    resp = client.get(f"/organizations/{org['id']}/members", headers=org["owner_headers"])
    assert resp.status_code == 200
    row = resp.json()[0]
    assert set(row.keys()) == {"user_id", "email", "status", "roles", "permissions"}
    assert "org_admin" in row["roles"]
    assert "manage_org" in row["permissions"]
    assert all(isinstance(p, str) for p in row["permissions"])


def test_list_members_expand_permissions_true_returns_full_metadata(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    resp = client.get(
        f"/organizations/{org['id']}/members", params={"expand_permissions": "true"}, headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    row = resp.json()[0]
    assert all(isinstance(p, dict) and "name" in p and "category" in p for p in row["permissions"])


def test_list_members_unauthorized_caller_rejected(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    outsider = _register_and_login(client)
    resp = client.get(f"/organizations/{org['id']}/members", headers=_auth_header(outsider["access_token"]))
    assert resp.status_code in (403, 404)


# ── 5. Effective permissions ─────────────────────────────────────────────────


def test_effective_permissions_combines_all_roles(client, admin_headers):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    member = _register_and_login(client)
    member_id = _user_id(client, member["access_token"])
    client.post(f"/orgs/{org['id']}/invite", json={"email": member["email"]}, headers=org["owner_headers"])

    role_a = _make_extra_role(client, admin_headers, ["dataset.read"])
    role_b = _make_extra_role(client, admin_headers, ["model.use"])
    client.post(
        f"/organizations/{org['id']}/members/{member_id}/roles",
        json={"roles": [role_a, role_b]},
        headers=org["owner_headers"],
    )

    resp = client.get(
        f"/organizations/{org['id']}/members/{member_id}/effective-permissions", headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["organization_id"] == org["id"]
    assert body["user_id"] == member_id
    assert set(body["permission_names"]) == {"dataset.read", "model.use"}
    assert {p["name"] for p in body["permissions"]} == {"dataset.read", "model.use"}
    for p in body["permissions"]:
        assert set(p.keys()) == {
            "name", "resource", "action", "scope", "category",
            "description", "legacy", "deprecated", "deprecated_reason",
        }


def test_effective_permissions_only_exposes_existing_rbac_grant(client, admin_headers):
    """No new authorization logic -- this must exactly match
    org_service.permissions_for_membership's own computation, not
    something independently derived."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    resp = client.get(
        f"/organizations/{org['id']}/members/{owner_id}/effective-permissions", headers=org["owner_headers"],
    )
    from app.services import org_service as _org_service
    db = _DirectSession()
    try:
        membership = _org_service.get_membership(db, org["id"], owner_id)
        expected = _org_service.permissions_for_membership(membership)
    finally:
        db.close()
    assert set(resp.json()["permission_names"]) == expected


def test_effective_permissions_nonexistent_member_404s(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    resp = client.get(f"/organizations/{org['id']}/members/999999999/effective-permissions", headers=org["owner_headers"])
    assert resp.status_code == 404


# ── Registry/database drift -> 500 (single-member-scoped endpoints) ────────


def test_member_roles_500s_on_registry_drift(client):
    owner = _register_and_login(client)
    org = _make_org(client, owner)
    owner_id = _user_id(client, owner["access_token"])

    db = _DirectSession()
    drifted_name = f"not_in_registry_{uuid.uuid4().hex[:8]}"
    try:
        drifted_perm = Permission(name=drifted_name)
        db.add(drifted_perm)
        role_name = f"pr7-drift-role-{uuid.uuid4().hex[:8]}"
        role = Role(name=role_name, permissions=[drifted_perm])
        db.add(role)
        db.commit()

        from app.db.models import OrganizationMembership as _OM
        membership = db.query(_OM).filter(
            _OM.organization_id == org["id"], _OM.user_id == owner_id,
        ).first()
        membership.roles = list(membership.roles) + [role]
        db.commit()

        resp = client.get(f"/organizations/{org['id']}/members/{owner_id}/roles", headers=org["owner_headers"])
        assert resp.status_code == 500

        resp2 = client.get(
            f"/organizations/{org['id']}/members/{owner_id}/effective-permissions", headers=org["owner_headers"],
        )
        assert resp2.status_code == 500
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


def test_list_members_does_not_500_on_unrelated_drift(client):
    """The bulk list must stay available even if some member somewhere has
    a drifted permission (lenient path) -- see routes_organization_roles.py
    ._permission_out_or_none's docstring."""
    owner = _register_and_login(client)
    org = _make_org(client, owner)

    db = _DirectSession()
    drifted_name = f"not_in_registry_{uuid.uuid4().hex[:8]}"
    try:
        drifted_perm = Permission(name=drifted_name)
        db.add(drifted_perm)
        role_name = f"pr7-drift-list-role-{uuid.uuid4().hex[:8]}"
        role = Role(name=role_name, permissions=[drifted_perm])
        db.add(role)
        db.commit()

        from app.db.models import OrganizationMembership as _OM
        owner_id = _user_id(client, owner["access_token"])
        membership = db.query(_OM).filter(
            _OM.organization_id == org["id"], _OM.user_id == owner_id,
        ).first()
        membership.roles = list(membership.roles) + [role]
        db.commit()

        resp = client.get(
            f"/organizations/{org['id']}/members", params={"expand_permissions": "true"}, headers=org["owner_headers"],
        )
        assert resp.status_code == 200
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
