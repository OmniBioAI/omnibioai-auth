"""PR13 Finding 2: an Org Admin (manage_org, scoped to their own org) must
never be able to grant a GLOBAL-scope permission (manage_all_orgs,
manage_roles, etc) to another org member -- neither by assigning a
pre-existing role that holds one (e.g. the literal "admin"/"platform_admin"
role, via the legacy /orgs and newer /organizations assignment endpoints),
nor by creating a new custom org role that holds one (see
test_pr13_role_org_scope.py's org-scope tests for the creation-time half).
Every denial must also be audit-logged (ROLE_ASSIGNMENT_DENIED), not just
surfaced as a 400/403 with nothing recorded server-side. A Platform Admin
performing the identical assignment must still succeed.
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"pr13-esc-{uuid.uuid4().hex[:8]}@omnibioai.test"
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


def _create_org(client, headers, name="PR13 Escalation Org"):
    slug = f"pr13-esc-{uuid.uuid4().hex[:8]}"
    return client.post("/orgs", json={"name": name, "slug": slug}, headers=headers).json()["id"]


def _denial_events_for(role_name: str) -> list[AuditEvent]:
    db = _DirectSession()
    try:
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.event_type == "role_assignment_denied")
            .all()
        )
    finally:
        db.close()


# ── Org Admin cannot assign a GLOBAL-permission role to another member ─────


def test_org_admin_cannot_assign_admin_role_to_another_member_via_new_surface(client):
    owner = _register_and_login(client)
    owner_headers = _auth_header(owner["access_token"])
    org_id = _create_org(client, owner_headers)

    other = _register_and_login(client)
    other_id = _user_id(client, other["access_token"])
    client.post(f"/orgs/{org_id}/invite", json={"email": other["email"]}, headers=owner_headers)
    # Activate the invite the same way an accept-flow would -- direct DB
    # write, since accept-invite isn't this test's concern.
    db = _DirectSession()
    try:
        from app.db.models import OrganizationMembership
        m = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == other_id,
        ).first()
        m.status = "active"
        db.commit()
    finally:
        db.close()

    resp = client.post(
        f"/organizations/{org_id}/members/{other_id}/roles", json={"roles": ["admin"]}, headers=owner_headers,
    )
    assert resp.status_code == 403
    assert "Platform Admin" in resp.json()["detail"]


def test_org_admin_cannot_assign_admin_role_via_legacy_surface(client):
    owner = _register_and_login(client)
    owner_headers = _auth_header(owner["access_token"])
    org_id = _create_org(client, owner_headers)

    other = _register_and_login(client)
    other_id = _user_id(client, other["access_token"])
    client.post(f"/orgs/{org_id}/invite", json={"email": other["email"]}, headers=owner_headers)
    db = _DirectSession()
    try:
        from app.db.models import OrganizationMembership
        m = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == other_id,
        ).first()
        m.status = "active"
        db.commit()
    finally:
        db.close()

    resp = client.post(
        f"/orgs/{org_id}/members/{other_id}/roles", json={"role": "platform_admin"}, headers=owner_headers,
    )
    assert resp.status_code == 403

    resp2 = client.put(
        f"/orgs/{org_id}/members/{other_id}/roles", json={"roles": ["platform_admin"]}, headers=owner_headers,
    )
    assert resp2.status_code == 403


def test_denied_assignment_is_audit_logged(client):
    owner = _register_and_login(client)
    owner_headers = _auth_header(owner["access_token"])
    org_id = _create_org(client, owner_headers)

    other = _register_and_login(client)
    other_id = _user_id(client, other["access_token"])
    client.post(f"/orgs/{org_id}/invite", json={"email": other["email"]}, headers=owner_headers)
    db = _DirectSession()
    try:
        from app.db.models import OrganizationMembership
        m = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == other_id,
        ).first()
        m.status = "active"
        db.commit()
    finally:
        db.close()

    before = len(_denial_events_for("admin"))
    resp = client.post(
        f"/organizations/{org_id}/members/{other_id}/roles", json={"roles": ["admin"]}, headers=owner_headers,
    )
    assert resp.status_code == 403
    after = _denial_events_for("admin")
    assert len(after) == before + 1
    event = after[-1]
    assert event.organization_id == org_id
    assert event.target_user_id == other_id
    assert event.event_metadata["role"] == "admin"
    assert "manage_all_orgs" in event.event_metadata["offending_permissions"] or "manage_roles" in event.event_metadata["offending_permissions"]


def test_platform_admin_can_assign_admin_role_to_org_member(client):
    platform_admin = _platform_admin(client)
    org_id = _create_org(client, platform_admin["headers"], name="Platform Admin Assign Org")

    other = _register_and_login(client)
    other_id = _user_id(client, other["access_token"])
    client.post(f"/orgs/{org_id}/invite", json={"email": other["email"]}, headers=platform_admin["headers"])
    db = _DirectSession()
    try:
        from app.db.models import OrganizationMembership
        m = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == org_id, OrganizationMembership.user_id == other_id,
        ).first()
        m.status = "active"
        db.commit()
    finally:
        db.close()

    resp = client.post(
        f"/organizations/{org_id}/members/{other_id}/roles", json={"roles": ["admin"]},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 201
    assert "admin" in resp.json()["roles"][0]["name"] or any(r["name"] == "admin" for r in resp.json()["roles"])


# ── Org Admin cannot create a custom role holding a GLOBAL permission ──────


def test_org_admin_cannot_create_custom_role_with_global_permission_via_api(client):
    owner = _register_and_login(client)
    owner_headers = _auth_header(owner["access_token"])
    org_id = _create_org(client, owner_headers)

    resp = client.post(
        f"/organizations/{org_id}/roles",
        json={"name": f"sneaky-{uuid.uuid4().hex[:6]}", "permissions": ["manage_all_orgs"]},
        headers=owner_headers,
    )
    assert resp.status_code == 400
