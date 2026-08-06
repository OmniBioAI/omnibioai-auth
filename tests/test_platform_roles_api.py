"""Phase 3 PR3B: /platform/roles, /platform/users/{id}/roles -- platform-
admin global role management. Every route here is gated by
require_permission(MANAGE_ALL_ORGS) only, mirroring
test_platform_users_api.py's own conventions exactly.
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"pr-api-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _grant_platform_admin(email: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None, "ensure_platform_admin_role should have created this at startup"
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _platform_admin(client):
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


def _role_id_by_name(roles_list: list[dict], name: str) -> int:
    return next(r["id"] for r in roles_list if r["name"] == name)


# ── A. Role catalog ──────────────────────────────────────────────────────────


def test_platform_admin_can_list_roles(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/roles", headers=admin["headers"])
    assert resp.status_code == 200
    names = {r["name"] for r in resp.json()}
    assert {"platform_admin", "admin", "user"} <= names
    for r in resp.json():
        assert set(r.keys()) == {"id", "name", "description", "permissions", "organization_id"}


def test_non_platform_admin_cannot_list_roles(client):
    owner = _register_and_login(client)
    resp = client.get("/platform/roles", headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 403


# ── B. Global role assignment ────────────────────────────────────────────────


def test_get_user_roles(client):
    admin = _platform_admin(client)
    admin_id = _user_id(client, admin["access_token"])

    resp = client.get(f"/platform/users/{admin_id}/roles", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert any(a["role"] == "platform_admin" for a in body)
    for a in body:
        assert a["user_id"] == admin_id
        # Not tracked by the underlying user_roles association table --
        # see role_admin.py's UserRoleAssignment docstring.
        assert a["assigned_at"] is None
        assert a["assigned_by"] is None


def test_assign_and_remove_global_role(client):
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    roles_catalog = client.get("/platform/roles", headers=admin["headers"]).json()
    admin_role_id = _role_id_by_name(roles_catalog, "admin")

    assign = client.post(f"/platform/users/{target_id}/roles", json={"role": "admin"}, headers=admin["headers"])
    assert assign.status_code == 201
    assert {a["role"] for a in assign.json()} == {"user", "admin"}

    remove = client.delete(f"/platform/users/{target_id}/roles/{admin_role_id}", headers=admin["headers"])
    assert remove.status_code == 204

    after = client.get(f"/platform/users/{target_id}/roles", headers=admin["headers"])
    assert {a["role"] for a in after.json()} == {"user"}


def test_assign_unknown_role_rejected(client):
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    resp = client.post(
        f"/platform/users/{target_id}/roles", json={"role": "does-not-exist"}, headers=admin["headers"]
    )
    assert resp.status_code == 400


def test_remove_role_not_currently_assigned_returns_404(client):
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    roles_catalog = client.get("/platform/roles", headers=admin["headers"]).json()
    admin_role_id = _role_id_by_name(roles_catalog, "admin")

    resp = client.delete(f"/platform/users/{target_id}/roles/{admin_role_id}", headers=admin["headers"])
    assert resp.status_code == 404


def test_remove_nonexistent_role_id_returns_404(client):
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    resp = client.delete(f"/platform/users/{target_id}/roles/999999999", headers=admin["headers"])
    assert resp.status_code == 404


def test_nonexistent_user_returns_404_for_all_three_routes(client):
    admin = _platform_admin(client)
    assert client.get("/platform/users/999999999/roles", headers=admin["headers"]).status_code == 404
    assert client.post(
        "/platform/users/999999999/roles", json={"role": "user"}, headers=admin["headers"]
    ).status_code == 404
    assert client.delete("/platform/users/999999999/roles/1", headers=admin["headers"]).status_code == 404


# ── C. Authorization ─────────────────────────────────────────────────────────


def test_non_platform_admin_cannot_assign_role(client):
    owner = _register_and_login(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    resp = client.post(
        f"/platform/users/{target_id}/roles", json={"role": "admin"}, headers=_auth_header(owner["access_token"])
    )
    assert resp.status_code == 403


def test_non_platform_admin_cannot_remove_role(client):
    owner = _register_and_login(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    resp = client.delete(
        f"/platform/users/{target_id}/roles/1", headers=_auth_header(owner["access_token"])
    )
    assert resp.status_code == 403


# ── D. Self-escalation guard ─────────────────────────────────────────────────


def test_platform_admin_cannot_grant_self_a_role_with_new_permissions(client):
    """Mirrors routes_roles.py's existing global self-escalation guard,
    applied to this new platform-admin-gated POST path: a platform admin
    holds manage_all_orgs, but assigning themselves "admin" (which carries
    manage_roles/manage_licenses/manage_config/override_sso_enforcement --
    none of which manage_all_orgs implies) must still be blocked."""
    admin = _platform_admin(client)
    admin_id = _user_id(client, admin["access_token"])

    resp = client.post(f"/platform/users/{admin_id}/roles", json={"role": "admin"}, headers=admin["headers"])
    assert resp.status_code == 403

    unchanged = client.get(f"/platform/users/{admin_id}/roles", headers=admin["headers"])
    assert {a["role"] for a in unchanged.json()} == {"user", "platform_admin"}


def test_platform_admin_can_grant_self_a_role_with_no_new_permissions(client):
    admin = _platform_admin(client)
    admin_id = _user_id(client, admin["access_token"])

    # "user" is already held and carries no permissions anyway -- a no-op
    # re-assign, not an escalation.
    resp = client.post(f"/platform/users/{admin_id}/roles", json={"role": "user"}, headers=admin["headers"])
    assert resp.status_code == 201


def test_platform_admin_can_grant_another_user_the_admin_role(client):
    """The self-escalation guard only applies to acting on your own
    account -- granting someone ELSE a wider role is exactly what this
    endpoint is for."""
    admin = _platform_admin(client)
    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    resp = client.post(f"/platform/users/{target_id}/roles", json={"role": "admin"}, headers=admin["headers"])
    assert resp.status_code == 201
    assert "admin" in {a["role"] for a in resp.json()}
