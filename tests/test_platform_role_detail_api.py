"""PR6 (Enterprise IAM Foundation): GET /platform/roles/{role_name} and
GET /platform/roles?expand_permissions=true -- the RBAC management layer
built on top of PR4's Permission Registry and PR5's read-only registry API.
Gated by require_permission(MANAGE_ALL_ORGS) only, mirroring
test_platform_roles_api.py's own conventions exactly.
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


# Local admin_token/admin_headers fixtures -- not shared via conftest.py in
# this codebase, so every test file that needs the bootstrap admin
# (require_permission(MANAGE_ROLES), used by POST /roles) redeclares its
# own copy, matching test_roles.py/test_orgs.py/test_org_sso.py exactly.
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


def _register_and_login(client, email=None):
    email = email or f"prd-api-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


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


PERMISSION_METADATA_KEYS = {
    "name", "resource", "action", "scope", "category",
    "description", "legacy", "deprecated", "deprecated_reason",
}


# ── Role detail ──────────────────────────────────────────────────────────────


def test_get_role_detail_returns_full_permission_metadata(client, admin_headers):
    admin = _platform_admin(client)
    name = f"detail-role-{uuid.uuid4().hex[:8]}"
    client.post(
        "/roles",
        json={"name": name, "permissions": ["manage_org", "billing.read"], "description": "test role"},
        headers=admin_headers,
    )

    resp = client.get(f"/platform/roles/{name}", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["name"] == name
    assert body["description"] == "test role"
    assert {p["name"] for p in body["permissions"]} == {"manage_org", "billing.read"}
    for perm in body["permissions"]:
        assert set(perm.keys()) == PERMISSION_METADATA_KEYS


def test_get_role_detail_permission_metadata_matches_registry(client, admin_headers):
    from app.core.permission_names import REGISTRY

    admin = _platform_admin(client)
    name = f"detail-match-role-{uuid.uuid4().hex[:8]}"
    client.post("/roles", json={"name": name, "permissions": ["manage_sso"]}, headers=admin_headers)

    resp = client.get(f"/platform/roles/{name}", headers=admin["headers"])
    perm = resp.json()["permissions"][0]
    assert perm == REGISTRY["manage_sso"].as_dict()


def test_get_unknown_role_detail_returns_404(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/roles/does-not-exist-role", headers=admin["headers"])
    assert resp.status_code == 404


def test_non_platform_admin_cannot_get_role_detail(client, admin_headers):
    admin = _platform_admin(client)
    owner = _register_and_login(client)
    name = f"forbidden-detail-role-{uuid.uuid4().hex[:8]}"
    client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)

    resp = client.get(f"/platform/roles/{name}", headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 403


# ── Registry/database drift -> 500 ──────────────────────────────────────────


def test_role_detail_500s_on_registry_drift(client):
    """If a Permission row exists on a role but isn't in the registry (a
    deployment-time drift that PR4's validated create/update paths can no
    longer produce, but a direct DB write still could), the detail endpoint
    must fail loudly (500), not silently drop or mis-render it."""
    admin = _platform_admin(client)
    db = _DirectSession()
    role_name = f"drift-role-{uuid.uuid4().hex[:8]}"
    try:
        drifted_perm = Permission(name=f"not_in_registry_{uuid.uuid4().hex[:8]}")
        db.add(drifted_perm)
        role = Role(name=role_name, permissions=[drifted_perm])
        db.add(role)
        db.commit()

        resp = client.get(f"/platform/roles/{role_name}", headers=admin["headers"])
        assert resp.status_code == 500
    finally:
        # Clean up so this drifted row doesn't trip a later real startup's
        # drift check (app/main.py's assert_no_unregistered_permissions)
        # against this same test.db file.
        db.delete(db.query(Role).filter(Role.name == role_name).first())
        db.delete(db.query(Permission).filter(Permission.name == drifted_perm.name).first())
        db.commit()
        db.close()


# ── Expand permissions on the list endpoint ─────────────────────────────────


def test_list_roles_default_response_unchanged(client):
    """Backward compatibility: no query param behaves exactly like PR3B's
    original lightweight response (permissions as plain name strings)."""
    admin = _platform_admin(client)
    resp = client.get("/platform/roles", headers=admin["headers"])
    assert resp.status_code == 200
    for row in resp.json():
        assert set(row.keys()) == {"id", "name", "description", "permissions", "organization_id"}
        assert all(isinstance(p, str) for p in row["permissions"])


def test_list_roles_expand_permissions_false_matches_default(client):
    admin = _platform_admin(client)
    default = client.get("/platform/roles", headers=admin["headers"]).json()
    explicit_false = client.get(
        "/platform/roles", params={"expand_permissions": "false"}, headers=admin["headers"]
    ).json()
    assert default == explicit_false


def test_list_roles_expand_permissions_true_returns_full_metadata(client, admin_headers):
    admin = _platform_admin(client)
    name = f"expand-role-{uuid.uuid4().hex[:8]}"
    client.post("/roles", json={"name": name, "permissions": ["dataset.read"]}, headers=admin_headers)

    resp = client.get("/platform/roles", params={"expand_permissions": "true"}, headers=admin["headers"])
    assert resp.status_code == 200
    row = next(r for r in resp.json() if r["name"] == name)
    assert set(row.keys()) == {"id", "name", "description", "permissions", "organization_id"}
    assert row["permissions"] == [
        {
            "name": "dataset.read",
            "resource": "dataset",
            "action": "read",
            "scope": "both",
            "category": "dataset",
            "description": "Reserved -- not yet enforced by any route.",
            "legacy": False,
            "deprecated": False,
            "deprecated_reason": None,
        }
    ]


def test_non_platform_admin_cannot_list_roles_expanded(client):
    owner = _register_and_login(client)
    resp = client.get(
        "/platform/roles", params={"expand_permissions": "true"}, headers=_auth_header(owner["access_token"]),
    )
    assert resp.status_code == 403
