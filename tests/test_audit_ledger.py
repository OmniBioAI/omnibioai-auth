"""PR9 (Enterprise IAM Foundation): the persistent IAM audit ledger
(app/db/models.py::AuditEvent, app/services/audit_service.py). Verifies
IAM lifecycle events (login, role, permission, org membership) are
captured with the correct actor/target/organization/before-after state,
and that each RBAC mutation emits exactly one event -- never zero, never
duplicated across the route surfaces that share one service function.
"""
import os
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"audit-{uuid.uuid4().hex[:8]}@omnibioai.test"
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
    """/platform/users/{id}/roles is gated by manage_all_orgs (the
    platform_admin role), a distinct permission from the bootstrap admin
    account's manage_roles -- admin_headers alone can't reach it."""
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


def _org(client, owner):
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs", json={"name": "Audit Ledger Org", "slug": f"audit-org-{uuid.uuid4().hex[:8]}"}, headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


def _events(**filters) -> list[AuditEvent]:
    db = _DirectSession()
    try:
        query = db.query(AuditEvent)
        for key, value in filters.items():
            query = query.filter(getattr(AuditEvent, key) == value)
        rows = query.order_by(AuditEvent.id).all()
        # Detach values into plain dicts before closing the session so
        # callers can assert on them freely.
        return [
            {
                "id": r.id, "event_type": r.event_type, "actor_user_id": r.actor_user_id,
                "target_user_id": r.target_user_id, "organization_id": r.organization_id,
                "resource_type": r.resource_type, "resource_id": r.resource_id,
                "before_state": r.before_state, "after_state": r.after_state,
                "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


# ── Login events ──────────────────────────────────────────────────────────────


def test_login_success_emits_event(client):
    user = _register_and_login(client)
    user_id = _user_id(client, user["access_token"])

    events = _events(event_type="login_success", target_user_id=user_id)
    assert len(events) == 1
    assert events[0]["actor_user_id"] == user_id
    assert events[0]["resource_type"] == "user"
    assert events[0]["metadata"]["email"] == user["email"]


def test_login_failure_wrong_password_emits_event(client):
    user = _register_and_login(client)
    user_id = _user_id(client, user["access_token"])

    client.post("/auth/login", json={"email": user["email"], "password": "WrongPassword!"})

    events = _events(event_type="login_failure", target_user_id=user_id)
    assert len(events) == 1
    assert events[0]["metadata"]["reason"] == "invalid_password"


def test_login_failure_unknown_email_emits_event_with_no_target(client):
    unknown_email = f"unknown-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/login", json={"email": unknown_email, "password": "Whatever123!"})

    events = _events(event_type="login_failure")
    matching = [e for e in events if e["metadata"] and e["metadata"].get("email") == unknown_email]
    assert len(matching) == 1
    assert matching[0]["actor_user_id"] is None
    assert matching[0]["target_user_id"] is None
    assert matching[0]["metadata"]["reason"] == "unknown_user_or_inactive"


# ── Role lifecycle ───────────────────────────────────────────────────────────


def test_create_role_emits_exactly_one_role_created_event(client, admin_headers):
    name = f"audit-role-{uuid.uuid4().hex[:8]}"
    resp = client.post("/roles", json={"name": name, "permissions": ["manage_org"]}, headers=admin_headers)
    role_id = resp.json()["id"]

    events = _events(event_type="role_created", resource_type="role", resource_id=str(role_id))
    assert len(events) == 1
    assert events[0]["after_state"]["name"] == name
    assert events[0]["after_state"]["permissions"] == ["manage_org"]


def test_role_assigned_and_removed_emit_events(client, admin_headers):
    platform_admin = _platform_admin(client)
    platform_admin_id = _user_id(client, platform_admin["access_token"])

    name = f"audit-assign-role-{uuid.uuid4().hex[:8]}"
    role_resp = client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    role_id = role_resp.json()["id"]

    target = _register_and_login(client)
    target_id = _user_id(client, target["access_token"])

    assign = client.post(
        f"/platform/users/{target_id}/roles", json={"role": name}, headers=platform_admin["headers"],
    )
    assert assign.status_code == 201

    assigned_events = _events(event_type="role_assigned", target_user_id=target_id, resource_id=str(role_id))
    assert len(assigned_events) == 1
    assert assigned_events[0]["actor_user_id"] == platform_admin_id
    assert assigned_events[0]["after_state"]["role"] == name

    remove = client.delete(f"/platform/users/{target_id}/roles/{role_id}", headers=platform_admin["headers"])
    assert remove.status_code == 204

    removed_events = _events(event_type="role_removed", target_user_id=target_id, resource_id=str(role_id))
    assert len(removed_events) == 1
    assert removed_events[0]["before_state"]["role"] == name


# ── Permission grant/revoke ──────────────────────────────────────────────────


def test_update_role_permissions_grant_emits_permission_granted_event(client, admin_headers):
    name = f"audit-grant-role-{uuid.uuid4().hex[:8]}"
    create = client.post("/roles", json={"name": name, "permissions": ["manage_org"]}, headers=admin_headers)
    role_id = create.json()["id"]

    update = client.put(
        f"/roles/{role_id}", json={"permissions": ["manage_org", "manage_teams"]}, headers=admin_headers,
    )
    assert update.status_code == 200

    events = _events(event_type="permission_granted", resource_type="role", resource_id=str(role_id))
    assert len(events) == 1
    assert events[0]["before_state"]["permissions"] == ["manage_org"]
    assert events[0]["after_state"]["permissions"] == ["manage_org", "manage_teams"]
    assert events[0]["metadata"]["added"] == ["manage_teams"]
    assert events[0]["metadata"]["removed"] == []


def test_update_role_permissions_revoke_emits_permission_revoked_event(client, admin_headers):
    name = f"audit-revoke-role-{uuid.uuid4().hex[:8]}"
    create = client.post(
        "/roles", json={"name": name, "permissions": ["manage_org", "manage_teams"]}, headers=admin_headers,
    )
    role_id = create.json()["id"]

    update = client.put(f"/roles/{role_id}", json={"permissions": ["manage_org"]}, headers=admin_headers)
    assert update.status_code == 200

    events = _events(event_type="permission_revoked", resource_type="role", resource_id=str(role_id))
    assert len(events) == 1
    assert events[0]["metadata"]["added"] == []
    assert events[0]["metadata"]["removed"] == ["manage_teams"]


def test_update_role_permissions_noop_emits_no_event(client, admin_headers):
    name = f"audit-noop-role-{uuid.uuid4().hex[:8]}"
    create = client.post("/roles", json={"name": name, "permissions": ["manage_org"]}, headers=admin_headers)
    role_id = create.json()["id"]

    update = client.put(f"/roles/{role_id}", json={"permissions": ["manage_org"]}, headers=admin_headers)
    assert update.status_code == 200

    granted = _events(event_type="permission_granted", resource_type="role", resource_id=str(role_id))
    revoked = _events(event_type="permission_revoked", resource_type="role", resource_id=str(role_id))
    assert granted == []
    assert revoked == []


# ── Organization membership changes ─────────────────────────────────────────


def test_invite_member_emits_organization_membership_changed_event(client):
    owner = _register_and_login(client)
    org = _org(client, owner)
    invitee = _register_and_login(client)
    invitee_id = _user_id(client, invitee["access_token"])
    owner_id = _user_id(client, owner["access_token"])

    resp = client.post(f"/orgs/{org['id']}/invite", json={"email": invitee["email"]}, headers=org["owner_headers"])
    assert resp.status_code == 201

    events = _events(
        event_type="organization_membership_changed", organization_id=org["id"], target_user_id=invitee_id,
    )
    assert len(events) == 1
    assert events[0]["actor_user_id"] == owner_id
    assert events[0]["after_state"]["status"] == "invited"
    assert events[0]["metadata"]["reason"] == "invited"


def test_org_member_role_assignment_emits_exactly_one_role_assigned_event(client, admin_headers):
    """PR7's two role-assignment surfaces (/orgs and /organizations) share
    one org_service.set_member_roles call -- must still emit exactly one
    event regardless of which route was used. Uses a platform admin as the
    actor, not the org owner acting on themselves -- routes_orgs.py's
    self-escalation guard would otherwise block widening org_admin's
    default permission set with dataset.read (same interaction
    test_service_identity_api.py's _grant_owner_permissions already hit)."""
    owner = _register_and_login(client)
    org = _org(client, owner)
    owner_id = _user_id(client, owner["access_token"])
    platform_admin = _platform_admin(client)

    role_name = f"audit-org-role-{uuid.uuid4().hex[:8]}"
    client.post("/roles", json={"name": role_name, "permissions": ["dataset.read"]}, headers=admin_headers)

    # PR7's full-replace endpoint.
    resp = client.post(
        f"/organizations/{org['id']}/members/{owner_id}/roles",
        json={"roles": ["org_admin", role_name]},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 201

    events = _events(event_type="role_assigned", organization_id=org["id"], target_user_id=owner_id)
    assert len(events) == 1
    assert set(events[0]["after_state"]["roles"]) == {"org_admin", role_name}


def test_org_member_single_role_add_and_remove_emit_events(client, admin_headers):
    owner = _register_and_login(client)
    org = _org(client, owner)
    member = _register_and_login(client)
    member_id = _user_id(client, member["access_token"])
    owner_id = _user_id(client, owner["access_token"])
    client.post(f"/orgs/{org['id']}/invite", json={"email": member["email"]}, headers=org["owner_headers"])

    role_name = f"audit-single-role-{uuid.uuid4().hex[:8]}"
    role_resp = client.post("/roles", json={"name": role_name, "permissions": []}, headers=admin_headers)
    role_id = role_resp.json()["id"]

    assign = client.post(
        f"/orgs/{org['id']}/members/{member_id}/roles", json={"role": role_name}, headers=org["owner_headers"],
    )
    assert assign.status_code == 201

    assigned = _events(event_type="role_assigned", organization_id=org["id"], target_user_id=member_id)
    assert len(assigned) == 1
    assert assigned[0]["actor_user_id"] == owner_id
    assert assigned[0]["after_state"]["role"] == role_name

    remove = client.delete(
        f"/orgs/{org['id']}/members/{member_id}/roles/{role_id}", headers=org["owner_headers"],
    )
    assert remove.status_code == 204

    removed = _events(event_type="role_removed", organization_id=org["id"], target_user_id=member_id)
    assert len(removed) == 1
    assert removed[0]["before_state"]["role"] == role_name


# ── Resilience: audit failures must not break the real mutation ────────────


def test_audit_write_failure_does_not_break_role_creation(client, admin_headers, monkeypatch):
    """Mirrors omnibioai-security-audit's own AuditLogger "NEVER break core
    system" contract: a broken audit sink must degrade to a missing log
    entry, never a failed mutation. Patches AuditEvent construction itself
    (not log_event -- replacing log_event wholesale would also remove its
    own protective try/except, testing nothing) so log_event's internal
    error handling is what's actually being exercised."""
    from app.services import audit_service

    def _boom(*args, **kwargs):
        raise RuntimeError("simulated audit sink outage")

    monkeypatch.setattr(audit_service, "AuditEvent", _boom)

    name = f"audit-resilience-role-{uuid.uuid4().hex[:8]}"
    resp = client.post("/roles", json={"name": name, "permissions": []}, headers=admin_headers)
    assert resp.status_code == 201

    events = _events(event_type="role_created", resource_type="role")
    matching = [e for e in events if e["after_state"] and e["after_state"].get("name") == name]
    assert matching == []  # the write failed and was swallowed, not silently succeeded
