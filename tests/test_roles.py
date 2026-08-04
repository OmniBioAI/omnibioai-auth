import os
import uuid

import pytest


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _user_id(client, tokens):
    resp = client.post("/auth/validate", json={"token": tokens["access_token"]})
    return resp.json()["user_id"]


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


def _unique_name(prefix):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


# ── Role CRUD (admin) ───────────────────────────────────────────────────────────

def test_create_role(client, admin_headers):
    name = _unique_name("role")
    resp = client.post(
        "/roles",
        json={"name": name, "permissions": ["dataset.read"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["name"] == name
    assert data["permissions"] == ["dataset.read"]


def test_create_duplicate_role_returns_409(client, admin_headers):
    name = _unique_name("dup-role")
    client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    resp = client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    assert resp.status_code == 409


def test_list_roles_includes_bootstrap_admin_role(client, admin_headers):
    resp = client.get("/roles", headers=admin_headers)
    assert resp.status_code == 200
    assert any(r["name"] == "admin" for r in resp.json())


def test_get_role_detail(client, admin_headers):
    name = _unique_name("detail-role")
    create = client.post(
        "/roles", json={"name": name, "permissions": ["model.use"]}, headers=admin_headers
    )
    role_id = create.json()["id"]
    resp = client.get(f"/roles/{role_id}", headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["permissions"] == ["model.use"]


def test_get_role_not_found(client, admin_headers):
    resp = client.get("/roles/999999", headers=admin_headers)
    assert resp.status_code == 404


def test_update_role_permissions(client, admin_headers):
    name = _unique_name("update-role")
    create = client.post(
        "/roles", json={"name": name, "permissions": ["dataset.read"]}, headers=admin_headers
    )
    role_id = create.json()["id"]
    resp = client.put(
        f"/roles/{role_id}",
        json={"permissions": ["dataset.read", "model.use"]},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert set(resp.json()["permissions"]) == {"dataset.read", "model.use"}


def test_delete_unused_role(client, admin_headers):
    name = _unique_name("deletable-role")
    create = client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    role_id = create.json()["id"]

    resp = client.delete(f"/roles/{role_id}", headers=admin_headers)
    assert resp.status_code == 204
    assert client.get(f"/roles/{role_id}", headers=admin_headers).status_code == 404


def test_delete_role_in_use_returns_409(client, admin_headers, registered_user):
    name = _unique_name("in-use-role")
    create = client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    role_id = create.json()["id"]

    login = client.post("/auth/login", json=registered_user)
    user_id = _user_id(client, login.json())

    assign = client.put(
        f"/users/{user_id}/roles", json={"roles": [name]}, headers=admin_headers
    )
    assert assign.status_code == 200

    resp = client.delete(f"/roles/{role_id}", headers=admin_headers)
    assert resp.status_code == 409


def test_update_role_unknown_name_leaves_no_role(client, admin_headers):
    resp = client.get("/roles/0", headers=admin_headers)
    assert resp.status_code == 404


# ── Permission Registry validation (PR4) ────────────────────────────────────────

def test_create_role_with_unregistered_permission_returns_400(client, admin_headers):
    resp = client.post(
        "/roles",
        json={"name": _unique_name("bad-perm-role"), "permissions": ["not_a_real_permission"]},
        headers=admin_headers,
    )
    assert resp.status_code == 400


def test_update_role_with_unregistered_permission_returns_400(client, admin_headers):
    name = _unique_name("update-bad-perm-role")
    create = client.post(
        "/roles", json={"name": name, "permissions": ["dataset.read"]}, headers=admin_headers
    )
    role_id = create.json()["id"]

    resp = client.put(
        f"/roles/{role_id}",
        json={"permissions": ["dataset.read", "not_a_real_permission"]},
        headers=admin_headers,
    )
    assert resp.status_code == 400

    # Rejected update must not have partially applied.
    unchanged = client.get(f"/roles/{role_id}", headers=admin_headers)
    assert unchanged.json()["permissions"] == ["dataset.read"]


def test_create_role_with_legacy_permission_still_works(client, admin_headers):
    """Legacy, pre-registry permission names (e.g. manage_org) must remain
    valid forever -- the registry adds a floor, not a rename."""
    resp = client.post(
        "/roles",
        json={"name": _unique_name("legacy-perm-role"), "permissions": ["manage_org"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["permissions"] == ["manage_org"]


def test_create_role_with_future_enterprise_permission_succeeds(client, admin_headers):
    """Reserved future permissions (billing.read etc.) are already assignable
    via role CRUD, even though nothing enforces them yet."""
    resp = client.post(
        "/roles",
        json={"name": _unique_name("future-perm-role"), "permissions": ["billing.read"]},
        headers=admin_headers,
    )
    assert resp.status_code == 201
    assert resp.json()["permissions"] == ["billing.read"]


# ── User role assignment (admin) ────────────────────────────────────────────────

def test_get_user_roles(client, admin_headers, registered_user):
    login = client.post("/auth/login", json=registered_user)
    user_id = _user_id(client, login.json())

    resp = client.get(f"/users/{user_id}/roles", headers=admin_headers)
    assert resp.status_code == 200
    # New signups get the baseline "user" role by default (M1) -- no
    # longer zero roles.
    assert resp.json() == {"user_id": user_id, "roles": ["user"]}


def test_assign_role_to_user(client, admin_headers, registered_user):
    name = _unique_name("assignable-role")
    client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)

    login = client.post("/auth/login", json=registered_user)
    user_id = _user_id(client, login.json())

    resp = client.put(f"/users/{user_id}/roles", json={"roles": [name]}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["roles"] == [name]


def test_assign_unknown_role_returns_400(client, admin_headers, registered_user):
    login = client.post("/auth/login", json=registered_user)
    user_id = _user_id(client, login.json())

    resp = client.put(
        f"/users/{user_id}/roles", json={"roles": ["does-not-exist"]}, headers=admin_headers
    )
    assert resp.status_code == 400


def test_assign_roles_user_not_found(client, admin_headers):
    resp = client.put("/users/999999/roles", json={"roles": []}, headers=admin_headers)
    assert resp.status_code == 404


# ── Negative / non-admin access ──────────────────────────────────────────────────

def test_missing_token_rejected(client):
    resp = client.get("/roles")
    assert resp.status_code in (401, 403)


def test_non_admin_cannot_list_roles(client, auth_tokens):
    resp = client.get("/roles", headers=_auth_header(auth_tokens["access_token"]))
    assert resp.status_code == 403


def test_non_admin_cannot_create_role(client, auth_tokens):
    resp = client.post(
        "/roles",
        json={"name": _unique_name("hacker-role"), "permissions": []},
        headers=_auth_header(auth_tokens["access_token"]),
    )
    assert resp.status_code == 403


def test_non_admin_cannot_delete_role(client, admin_headers, auth_tokens):
    name = _unique_name("protected-role")
    create = client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    role_id = create.json()["id"]

    resp = client.delete(f"/roles/{role_id}", headers=_auth_header(auth_tokens["access_token"]))
    assert resp.status_code == 403


def test_non_admin_cannot_assign_roles(client, auth_tokens):
    resp = client.put(
        "/users/1/roles",
        json={"roles": ["admin"]},
        headers=_auth_header(auth_tokens["access_token"]),
    )
    assert resp.status_code == 403


# ── Self-escalation guard ────────────────────────────────────────────────────────

def test_self_escalation_blocked(client, admin_headers, registered_user):
    """A manage_roles holder cannot grant themselves a role that carries
    permissions they don't already have."""
    base_role = _unique_name("base-role")
    client.post(
        "/roles", json={"name": base_role, "permissions": ["manage_roles"]}, headers=admin_headers
    )

    escalated_role = _unique_name("escalated-role")
    client.post(
        "/roles",
        json={"name": escalated_role, "permissions": ["manage_roles", "marketplace.install"]},
        headers=admin_headers,
    )

    login = client.post("/auth/login", json=registered_user)
    user_id = _user_id(client, login.json())

    # Admin grants the base role (manage_roles only) to the test user.
    assign = client.put(
        f"/users/{user_id}/roles", json={"roles": [base_role]}, headers=admin_headers
    )
    assert assign.status_code == 200

    # The test user logs back in to pick up a token reflecting the new role.
    relogin = client.post("/auth/login", json=registered_user)
    user_headers = _auth_header(relogin.json()["access_token"])

    # The user (who now holds manage_roles) tries to grant themselves the
    # escalated role, which carries an extra permission — must be blocked.
    resp = client.put(
        f"/users/{user_id}/roles", json={"roles": [escalated_role]}, headers=user_headers
    )
    assert resp.status_code == 403

    # Confirm the role assignment was NOT applied.
    check = client.get(f"/users/{user_id}/roles", headers=admin_headers)
    assert check.json()["roles"] == [base_role]


def test_self_role_downgrade_allowed(client, admin_headers, registered_user):
    """Removing/narrowing your own roles is not blocked by the escalation guard."""
    base_role = _unique_name("downgrade-base-role")
    client.post(
        "/roles", json={"name": base_role, "permissions": ["manage_roles"]}, headers=admin_headers
    )

    login = client.post("/auth/login", json=registered_user)
    user_id = _user_id(client, login.json())

    client.put(f"/users/{user_id}/roles", json={"roles": [base_role]}, headers=admin_headers)

    relogin = client.post("/auth/login", json=registered_user)
    user_headers = _auth_header(relogin.json()["access_token"])

    resp = client.put(f"/users/{user_id}/roles", json={"roles": []}, headers=user_headers)
    assert resp.status_code == 200
    assert resp.json()["roles"] == []


def test_manage_roles_holder_can_grant_higher_role_to_others(client, admin_headers, registered_user):
    """The escalation guard only applies to self-modification — a manage_roles
    holder can still grant a higher-privilege role to a different user."""
    granter_role = _unique_name("granter-role")
    client.post(
        "/roles", json={"name": granter_role, "permissions": ["manage_roles"]}, headers=admin_headers
    )

    target_role = _unique_name("other-user-role")
    client.post(
        "/roles",
        json={"name": target_role, "permissions": ["manage_roles", "marketplace.install"]},
        headers=admin_headers,
    )

    granter_login = client.post("/auth/login", json=registered_user)
    granter_id = _user_id(client, granter_login.json())
    client.put(f"/users/{granter_id}/roles", json={"roles": [granter_role]}, headers=admin_headers)

    granter_relogin = client.post("/auth/login", json=registered_user)
    granter_headers = _auth_header(granter_relogin.json()["access_token"])

    other_email = f"other-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": other_email, "password": "TestPassword123!"})
    other_login = client.post(
        "/auth/login", json={"email": other_email, "password": "TestPassword123!"}
    )
    other_id = _user_id(client, other_login.json())

    resp = client.put(
        f"/users/{other_id}/roles", json={"roles": [target_role]}, headers=granter_headers
    )
    assert resp.status_code == 200
    assert resp.json()["roles"] == [target_role]
