"""Isolated security and acceptance tests for manual license issuance."""
import os
import uuid
from datetime import datetime

from app.db.models import AuditEvent, LicenseKey, Organization, OrganizationMembership, Role, User
from app.db.session import SessionLocal


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _login(client, email, password):
    response = client.post("/auth/login", json={"email": email, "password": password})
    assert response.status_code == 200, response.text
    return _auth(response.json()["access_token"])


def _admin(client):
    return _login(client, "admin@omnibioai", os.environ["ADMIN_BOOTSTRAP_PASSWORD"])


def _owner_with_membership(client, persona_prefix="manual"):
    email = f"{persona_prefix}-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        org = db.query(Organization).order_by(Organization.id).first()
        membership = OrganizationMembership(
            organization_id=org.id, user_id=user.id, status="active", roles=[],
        )
        db.add(membership)
        db.commit()
        return email, password, user.id, org.id
    finally:
        db.close()


def _issue(client, headers, email, org_id, persona="developer", days=30, **extra):
    payload = {
        "full_name": "Test License Owner",
        "email": email,
        "persona": persona,
        "validity_days": days,
        "organization_id": org_id,
        "confirm_role_change": True,
        "confirm_replace_existing": False,
    }
    payload.update(extra)
    return client.post(
        "/platform/licenses", json=payload, headers={**headers, "Idempotency-Key": uuid.uuid4().hex},
    )


def test_policy_and_authorization(client, auth_tokens):
    assert client.get("/platform/licenses/policy").status_code == 401
    assert client.get(
        "/platform/licenses/policy", headers=_auth(auth_tokens["access_token"]),
    ).status_code == 403
    body = client.get("/platform/licenses/policy", headers=_admin(client)).json()
    assert body == {
        "validity_days": [30, 90],
        "personas": ["developer", "application_user"],
        "issuance_enabled": True,
        "unknown_identity_action": "provisioning_required",
    }


def test_unknown_identity_requires_provisioning(client):
    response = _issue(client, _admin(client), f"missing-{uuid.uuid4().hex}@test", 1)
    assert response.status_code == 409
    assert response.json()["detail"]["code"] == "provisioning_required"


def test_developer_issue_digest_one_time_display_idempotency_and_activation(client):
    email, password, user_id, org_id = _owner_with_membership(client, "developer")
    admin = _admin(client)
    idempotency_key = uuid.uuid4().hex
    payload = {
        "full_name": "Developer Person", "email": email, "persona": "developer",
        "validity_days": 30, "organization_id": org_id,
        "confirm_role_change": True, "confirm_replace_existing": False,
    }
    first = client.post("/platform/licenses", json=payload, headers={**admin, "Idempotency-Key": idempotency_key})
    assert first.status_code == 200, first.text
    key = first.json()["key"]
    assert key and first.json()["one_time_display"] is True
    replay = client.post("/platform/licenses", json=payload, headers={**admin, "Idempotency-Key": idempotency_key})
    assert replay.status_code == 200
    assert replay.json()["idempotent_replay"] is True
    assert replay.json()["key"] is None

    db = SessionLocal()
    try:
        row = db.query(LicenseKey).filter(LicenseKey.id == first.json()["license"]["id"]).one()
        assert row.key is None and row.key_digest and row.key_prefix == key[:9]
        assert 29 <= (row.expires_at - row.created_at).days <= 30
        membership = db.query(OrganizationMembership).filter_by(user_id=user_id, organization_id=org_id).one()
        assert "scientist" in {role.name for role in membership.roles}
        assert db.query(AuditEvent).filter_by(event_type="license_issued", resource_id=str(row.id)).count() == 1
    finally:
        db.close()

    owner = _login(client, email, password)
    activation = client.post(
        "/license/validate", json={"key": key, "email": email, "platform": "desktop"}, headers=owner,
    )
    assert activation.status_code == 200 and activation.json()["valid"] is True
    assert activation.json()["access_token"] is None


def test_application_user_validity_confirmation_renew_revoke_and_history(client):
    email, _password, user_id, org_id = _owner_with_membership(client, "app-user")
    admin = _admin(client)
    no_confirmation = _issue(
        client, admin, email, org_id, persona="application_user", days=90,
        confirm_role_change=False,
    )
    assert no_confirmation.status_code == 409
    issued = _issue(client, admin, email, org_id, persona="application_user", days=90)
    assert issued.status_code == 200, issued.text
    license_id = issued.json()["license"]["id"]
    db = SessionLocal()
    try:
        membership = db.query(OrganizationMembership).filter_by(user_id=user_id, organization_id=org_id).one()
        assert "org_member" in {role.name for role in membership.roles}
    finally:
        db.close()

    renewed = client.post(f"/platform/licenses/{license_id}/renew", json={"validity_days": 30}, headers=admin)
    assert renewed.status_code == 200 and renewed.json()["renewed_at"] is not None
    revoked = client.post(
        f"/platform/licenses/{license_id}/revoke", json={"reason": "isolated test"}, headers=admin,
    )
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    history = client.get(f"/platform/licenses/{license_id}/history", headers=admin).json()["items"]
    assert {item["event_type"] for item in history} >= {"license_issued", "license_renewed", "license_revoked"}
    assert all("key" not in str(item.get("metadata", {})).lower() or "key_prefix" in str(item.get("metadata", {})) for item in history)


def test_cross_tenant_and_duplicate_require_confirmation(client):
    email, _password, _user_id, org_id = _owner_with_membership(client, "tenant")
    admin = _admin(client)
    denied = _issue(client, admin, email, org_id + 999999)
    assert denied.status_code == 404
    assert _issue(client, admin, email, org_id).status_code == 200
    duplicate = _issue(client, admin, email, org_id)
    assert duplicate.status_code == 409
    assert duplicate.json()["detail"]["code"] == "active_license_confirmation_required"


def test_legacy_plaintext_license_remains_compatible(client):
    email, _password, user_id, org_id = _owner_with_membership(client, "legacy")
    key = f"OMNI-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}-{uuid.uuid4().hex[:4].upper()}"
    db = SessionLocal()
    try:
        db.add(LicenseKey(
            key=key, key_digest=None, email=email, user_id=user_id, organization_id=org_id,
            plan="beta", platform="both", max_uses=1, expires_at=datetime(2099, 1, 1),
        ))
        db.commit()
    finally:
        db.close()
    response = client.post("/license/validate", json={"key": key, "email": email, "platform": "desktop"})
    assert response.status_code == 200 and response.json()["valid"] is True
    assert response.json()["access_token"] is None
    assert response.json()["refresh_token"] is None


def test_retired_generate_endpoint(client):
    assert client.post("/license/generate", json={"email": "x@test"}, headers=_admin(client)).status_code == 410
