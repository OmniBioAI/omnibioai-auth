"""Acceptance and authorization tests for the Control Center license API."""
import os
import uuid

import pytest

from app.core.config import settings
from app.db.models import LicenseKey, Organization, OrganizationMembership, User
from app.db.session import SessionLocal
from app.main import app


@pytest.fixture(autouse=True)
def manual_license_configuration(monkeypatch):
    monkeypatch.setattr(settings, "LICENSE_ALLOWED_VALIDITY_DAYS", (30, 90))
    monkeypatch.setattr(settings, "LICENSE_KEY_PEPPER", "unit-test-license-pepper-value-32-bytes")


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _login(client, email, password):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return _auth(response.json()["access_token"])


def _admin(client):
    return _login(client, "admin@omnibioai", os.environ["ADMIN_BOOTSTRAP_PASSWORD"])


def _owner_with_membership(client):
    email = f"manual-{uuid.uuid4().hex[:10]}@omnibioai.test"
    password = "TestPassword123!"
    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        org = db.query(Organization).order_by(Organization.id).first()
        membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[])
        db.add(membership)
        db.commit()
        return email, password, user.id, org.id
    finally:
        db.close()


def _issue(client, headers, email, org_id, **changes):
    payload = {
        "full_name": "Test License Owner", "email": email, "persona": "developer",
        "validity_days": 30, "organization_id": org_id,
        "confirm_role_change": True, "confirm_replace_existing": False,
    }
    payload.update(changes)
    return client.post("/platform/licenses", json=payload,
                       headers={**headers, "Idempotency-Key": uuid.uuid4().hex})


def _dependency_names(dependant):
    names = {getattr(dependant.call, "__qualname__", "")}
    for child in dependant.dependencies:
        names.update(_dependency_names(child))
    return names


def test_platform_license_route_inventory_is_seven_protected_routes():
    routes = [route for route in app.routes if getattr(route, "path", "").startswith("/platform/licenses")]
    assert len(routes) == 7
    for route in routes:
        assert "authorized_license_admin" in _dependency_names(route.dependant)


def test_policy_authorization_and_fail_closed_configuration(client, auth_tokens, monkeypatch):
    assert client.get("/platform/licenses/policy").status_code == 401
    assert client.get("/platform/licenses/policy", headers=_auth(auth_tokens["access_token"])).status_code == 403
    policy = client.get("/platform/licenses/policy", headers=_admin(client))
    assert policy.status_code == 200
    assert policy.json()["validity_days"] == [30, 90]
    assert policy.json()["issuance_enabled"] is True


def test_issue_requires_existing_active_membership_and_only_displays_key_once(client):
    email, password, user_id, org_id = _owner_with_membership(client)
    admin = _admin(client)
    replay_body = {
        "full_name": "Test License Owner", "email": email, "persona": "developer",
        "validity_days": 30, "organization_id": org_id,
        "confirm_role_change": True, "confirm_replace_existing": False,
    }
    idem = uuid.uuid4().hex
    first = client.post("/platform/licenses", json=replay_body, headers={**admin, "Idempotency-Key": idem})
    assert first.status_code == 200, first.text
    key = first.json()["key"]
    assert key and first.json()["idempotent_replay"] is False
    # Reuse the idempotency key explicitly: replay must not return the secret.
    second = client.post("/platform/licenses", json=replay_body, headers={**admin, "Idempotency-Key": idem})
    assert second.status_code == 200 and second.json()["key"] is None
    assert second.json()["idempotent_replay"] is True

    db = SessionLocal()
    try:
        row = db.query(LicenseKey).filter(LicenseKey.id == first.json()["license"]["id"]).one()
        assert row.key is None and row.key_digest and row.key_prefix == key[:9]
        assert row.user_id == user_id
    finally:
        db.close()

    owner_headers = _login(client, email, password)
    activation = client.post("/license/validate", json={"key": key, "email": email}, headers=owner_headers)
    assert activation.status_code == 200 and activation.json()["valid"] is True


def test_unknown_identity_cross_tenant_and_existing_license_require_confirmation(client):
    admin = _admin(client)
    missing = _issue(client, admin, f"missing-{uuid.uuid4().hex}@test", 1)
    assert missing.status_code == 409
    email, _password, _user_id, org_id = _owner_with_membership(client)
    assert _issue(client, admin, email, org_id + 999999).status_code == 404
    assert _issue(client, admin, email, org_id).status_code == 200
    duplicate = _issue(client, admin, email, org_id)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "active_license_confirmation_required"


def test_revoke_renew_and_history_are_audited(client):
    email, _password, _user_id, org_id = _owner_with_membership(client)
    admin = _admin(client)
    issued = _issue(client, admin, email, org_id)
    assert issued.status_code == 200, issued.text
    license_id = issued.json()["license"]["id"]
    renewed = client.post(f"/platform/licenses/{license_id}/renew", json={"validity_days": 90}, headers=admin)
    assert renewed.status_code == 200
    revoked = client.post(f"/platform/licenses/{license_id}/revoke", json={"reason": "test"}, headers=admin)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    events = client.get(f"/platform/licenses/{license_id}/history", headers=admin)
    assert events.status_code == 200
    assert {item["event_type"] for item in events.json()["items"]} >= {"license_issued", "license_renewed", "license_revoked"}
