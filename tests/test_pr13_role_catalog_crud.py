"""PR13: role catalog CRUD -- POST/PUT/DELETE /platform/roles and
POST/GET/PUT/DELETE /organizations/{organization_id}/roles(/permissions).
Neither surface's mutation endpoints existed before this PR (only read +
user-role-assignment did) -- these are genuinely new API contracts, not
regression tests of existing behavior.
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
    email = email or f"pr13-crud-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


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


def _unique_role_name(prefix="pr13-role"):
    return f"{prefix}-{uuid.uuid4().hex[:8]}"


def _create_org(client, headers, name="PR13 CRUD Org"):
    slug = f"pr13-crud-{uuid.uuid4().hex[:8]}"
    return client.post("/orgs", json={"name": name, "slug": slug}, headers=headers).json()["id"]


# ── Platform-wide role catalog CRUD ─────────────────────────────────────────


def test_platform_admin_creates_edits_deletes_role(client):
    admin = _platform_admin(client)
    name = _unique_role_name()

    create = client.post(
        "/platform/roles", json={"name": name, "permissions": ["dataset.read"], "description": "test role"},
        headers=admin["headers"],
    )
    assert create.status_code == 201
    body = create.json()
    assert body["name"] == name
    assert body["organization_id"] is None
    role_id = body["id"]

    edit = client.put(
        f"/platform/roles/{role_id}", json={"permissions": ["dataset.read", "workflow.read"]},
        headers=admin["headers"],
    )
    assert edit.status_code == 200
    assert {p["name"] for p in edit.json()["permissions"]} == {"dataset.read", "workflow.read"}

    delete = client.delete(f"/platform/roles/{role_id}", headers=admin["headers"])
    assert delete.status_code == 204


def test_create_platform_role_duplicate_name_returns_409(client):
    admin = _platform_admin(client)
    name = _unique_role_name()
    client.post("/platform/roles", json={"name": name, "permissions": []}, headers=admin["headers"])
    dup = client.post("/platform/roles", json={"name": name, "permissions": []}, headers=admin["headers"])
    assert dup.status_code == 409


def test_create_platform_role_unknown_permission_returns_400(client):
    admin = _platform_admin(client)
    resp = client.post(
        "/platform/roles", json={"name": _unique_role_name(), "permissions": ["not.a.real.permission"]},
        headers=admin["headers"],
    )
    assert resp.status_code == 400


def test_delete_platform_role_in_use_returns_409(client):
    admin = _platform_admin(client)
    name = _unique_role_name()
    role_id = client.post("/platform/roles", json={"name": name, "permissions": []}, headers=admin["headers"]).json()["id"]

    target = _register_and_login(client)
    client.post(
        f"/platform/users/{_user_id(client, target['access_token'])}/roles",
        json={"role": name}, headers=admin["headers"],
    )

    delete = client.delete(f"/platform/roles/{role_id}", headers=admin["headers"])
    assert delete.status_code == 409


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def test_platform_role_endpoints_cannot_reach_an_org_custom_role(client):
    admin = _platform_admin(client)
    org_id = _create_org(client, admin["headers"])
    name = _unique_role_name()
    custom_role_id = client.post(
        f"/organizations/{org_id}/roles", json={"name": name, "permissions": ["dataset.read"]},
        headers=admin["headers"],
    ).json()["id"]

    edit = client.put(f"/platform/roles/{custom_role_id}", json={"permissions": []}, headers=admin["headers"])
    assert edit.status_code == 404

    delete = client.delete(f"/platform/roles/{custom_role_id}", headers=admin["headers"])
    assert delete.status_code == 404


def test_non_platform_admin_cannot_create_platform_role(client):
    regular = _register_and_login(client)
    resp = client.post(
        "/platform/roles", json={"name": _unique_role_name(), "permissions": []},
        headers=_auth_header(regular["access_token"]),
    )
    assert resp.status_code == 403


# ── Org-scoped custom role catalog CRUD ─────────────────────────────────────


def test_org_admin_creates_edits_deletes_own_custom_role(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org_id = _create_org(client, headers)
    name = _unique_role_name()

    create = client.post(
        f"/organizations/{org_id}/roles", json={"name": name, "permissions": ["dataset.read"]}, headers=headers,
    )
    assert create.status_code == 201
    body = create.json()
    assert body["organization_id"] == org_id
    role_id = body["id"]

    edit = client.put(
        f"/organizations/{org_id}/roles/{role_id}", json={"permissions": ["dataset.read", "workflow.read"]},
        headers=headers,
    )
    assert edit.status_code == 200

    delete = client.delete(f"/organizations/{org_id}/roles/{role_id}", headers=headers)
    assert delete.status_code == 204


def test_org_scoped_role_list_excludes_other_orgs_custom_roles(client):
    owner_a = _register_and_login(client)
    headers_a = _auth_header(owner_a["access_token"])
    org_a = _create_org(client, headers_a, "Org A")

    owner_b = _register_and_login(client)
    headers_b = _auth_header(owner_b["access_token"])
    org_b = _create_org(client, headers_b, "Org B")

    name_b = _unique_role_name("secret-b")
    client.post(f"/organizations/{org_b}/roles", json={"name": name_b, "permissions": ["dataset.read"]}, headers=headers_b)

    listing = client.get(f"/organizations/{org_a}/roles", headers=headers_a)
    assert listing.status_code == 200
    assert name_b not in {r["name"] for r in listing.json()}


def test_org_scoped_role_permissions_registry_excludes_global_scope(client):
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    org_id = _create_org(client, headers)

    resp = client.get(f"/organizations/{org_id}/permissions", headers=headers)
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert "dataset.read" in names  # BOTH-scope, legal for an org role
    assert "manage_all_orgs" not in names  # GLOBAL-scope, must not be offered


def test_org_admin_cannot_edit_another_orgs_custom_role(client):
    owner_a = _register_and_login(client)
    headers_a = _auth_header(owner_a["access_token"])
    org_a = _create_org(client, headers_a, "Org A2")

    owner_b = _register_and_login(client)
    headers_b = _auth_header(owner_b["access_token"])
    org_b = _create_org(client, headers_b, "Org B2")

    role_id = client.post(
        f"/organizations/{org_b}/roles", json={"name": _unique_role_name(), "permissions": ["dataset.read"]},
        headers=headers_b,
    ).json()["id"]

    edit = client.put(f"/organizations/{org_a}/roles/{role_id}", json={"permissions": []}, headers=headers_a)
    assert edit.status_code == 404
