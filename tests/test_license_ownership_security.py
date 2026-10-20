"""Identity-bound license lifecycle and authorization regression tests."""
import os
import uuid
from datetime import datetime, timedelta

import pytest

from app.db.models import LicenseKey, Organization, OrganizationMembership, User
from app.db.session import SessionLocal
from app.services import license_service


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(scope="session")
def license_admin_headers(client):
    response = client.post(
        "/auth/login",
        json={"email": "admin@omnibioai", "password": os.environ["ADMIN_BOOTSTRAP_PASSWORD"]},
    )
    assert response.status_code == 200
    return _auth(response.json()["access_token"])


def _account(client, prefix="license-owner"):
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        org = db.query(Organization).order_by(Organization.id).first()
        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[]))
        db.commit()
        org_id = org.id
    finally:
        db.close()
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"email": email, "org_id": org_id, **login.json(), "headers": _auth(login.json()["access_token"])}


def _generate(client, admin_headers, owner, **overrides):
    body = {
        "full_name": "Ownership Test", "email": owner["email"], "persona": "developer",
        "validity_days": overrides.pop("expires_days", 30), "organization_id": owner["org_id"],
        "confirm_role_change": True, "confirm_replace_existing": False,
    }
    overrides.pop("plan", None)
    overrides.pop("platform", None)
    body.update(overrides)
    response = client.post(
        "/platform/licenses", json=body,
        headers={**admin_headers, "Idempotency-Key": uuid.uuid4().hex},
    )
    assert response.status_code == 200, response.text
    return response.json()["key"]


def test_generation_requires_permission_and_existing_owner(client, license_admin_headers, auth_tokens):
    missing = f"missing-{uuid.uuid4().hex[:8]}@omnibioai.test"
    body = {"full_name": "Missing", "email": missing, "persona": "developer", "validity_days": 30, "organization_id": 1}
    assert client.post("/platform/licenses", json=body, headers={"Idempotency-Key": uuid.uuid4().hex}).status_code == 401
    assert client.post(
        "/platform/licenses", json=body,
        headers={**_auth(auth_tokens["access_token"]), "Idempotency-Key": uuid.uuid4().hex},
    ).status_code == 403
    response = client.post(
        "/platform/licenses", json=body,
        headers={**license_admin_headers, "Idempotency-Key": uuid.uuid4().hex},
    )
    assert response.status_code == 409


def test_generation_binds_existing_owner(client, license_admin_headers):
    owner = _account(client)
    key = _generate(client, license_admin_headers, owner)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == owner["email"]).one()
        row = license_service.lookup_license(db, key)
        assert row.user_id == user.id
        assert row.email == user.email
    finally:
        db.close()


def test_activation_requires_email_and_never_issues_identity_tokens(client, license_admin_headers):
    owner = _account(client)
    key = _generate(client, license_admin_headers, owner)
    assert client.post("/license/activate", json={"key": key, "platform": "web"}).status_code == 422
    response = client.post(
        "/license/activate", json={"key": key, "email": owner["email"], "platform": "web"},
    )
    body = response.json()
    assert response.status_code == 200 and body["valid"] is True
    assert body["access_token"] is None and body["refresh_token"] is None
    assert "omnibioai_session" not in response.cookies


def test_activation_rejects_wrong_email_and_inactive_owner(client, license_admin_headers):
    owner = _account(client, "activation-owner")
    key = _generate(client, license_admin_headers, owner)
    denied = client.post(
        "/license/activate",
        json={"key": key, "email": "attacker@omnibioai.test", "platform": "web"},
    )
    assert denied.json()["valid"] is False
    assert denied.json()["reason"] in {"email_mismatch", "identity_mismatch"}

    db = SessionLocal()
    try:
        db.query(User).filter(User.email == owner["email"]).one().status = "suspended"
        db.commit()
    finally:
        db.close()
    inactive = client.post(
        "/license/activate", json={"key": key, "email": owner["email"], "platform": "web"},
    )
    assert inactive.json()["valid"] is False
    assert inactive.json()["reason"] == "owner_unavailable"


def test_owner_validation_succeeds_without_issuing_identity_tokens(client, license_admin_headers):
    owner = _account(client)
    key = _generate(client, license_admin_headers, owner, expires_days=30)
    response = client.post(
        "/license/validate", json={"key": key, "email": owner["email"], "platform": "web"},
        headers=owner["headers"],
    )
    body = response.json()
    assert body["valid"] is True
    assert body["user_info"]["email"] == owner["email"]
    assert body["access_token"] is None and body["refresh_token"] is None


def test_cross_user_and_caller_email_override_are_denied(client, license_admin_headers):
    owner = _account(client, "owner")
    attacker = _account(client, "attacker")
    key = _generate(client, license_admin_headers, owner)
    for supplied_email in (None, owner["email"]):
        body = {"key": key, "platform": "web"}
        if supplied_email:
            body["email"] = supplied_email
        response = client.post("/license/validate", json=body, headers=attacker["headers"])
        assert response.json()["valid"] is False
        assert response.json()["reason"] in {"email_mismatch", "identity_mismatch"}


@pytest.mark.parametrize("state,reason", [("revoked", "revoked"), ("expired", "expired")])
def test_revoked_and_expired_denied(client, license_admin_headers, state, reason):
    owner = _account(client, state)
    key = _generate(client, license_admin_headers, owner)
    db = SessionLocal()
    try:
        row = license_service.lookup_license(db, key)
        if state == "revoked":
            row.revoked_at = datetime.utcnow()
        else:
            row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    response = client.post(
        "/license/validate", json={"key": key, "platform": "web"}, headers=owner["headers"]
    )
    assert response.json()["reason"] == reason


def test_invalid_and_cross_tenant_denied(client, license_admin_headers):
    owner = _account(client, "tenant-owner")
    invalid = client.post(
        "/license/validate", json={"key": "OMNI-ZZZZ-ZZZZ-ZZZZ-ZZZZ", "platform": "web"},
        headers=owner["headers"],
    )
    assert invalid.json()["reason"] == "invalid_key"

    key = _generate(client, license_admin_headers, owner)
    db = SessionLocal()
    try:
        row = license_service.lookup_license(db, key)
        row.organization_id = 999999
        db.commit()
    finally:
        db.close()
    denied = client.post(
        "/license/validate", json={"key": key, "platform": "web"}, headers=owner["headers"]
    )
    assert denied.json()["reason"] == "organization_mismatch"


def test_pull_token_requires_bound_owner(client, license_admin_headers, monkeypatch):
    from app.core.config import settings
    monkeypatch.setattr(settings, "GHCR_PULL_TOKEN", "test-only-pull-token")
    owner = _account(client, "pull-owner")
    attacker = _account(client, "pull-attacker")
    key = _generate(client, license_admin_headers, owner, platform="desktop")
    assert client.post("/license/pull-token", json={"key": key}).status_code == 422
    activation_pull = client.post(
        "/license/pull-token", json={"key": key, "email": owner["email"]},
    )
    assert activation_pull.status_code == 200
    assert client.post(
        "/license/pull-token", json={"key": key}, headers=attacker["headers"]
    ).status_code == 403
    allowed = client.post("/license/pull-token", json={"key": key}, headers=owner["headers"])
    assert allowed.status_code == 200
    assert allowed.json()["ghcr_token"] == "test-only-pull-token"


def test_status_scoped_and_revoke_admin_only(client, license_admin_headers):
    owner = _account(client, "status-owner")
    other = _account(client, "status-other")
    key = _generate(client, license_admin_headers, owner)
    status = client.get("/license/status", headers=owner["headers"]).json()
    assert status["key"] is None and status["key_prefix"] == key[:9]
    assert client.get("/license/status", headers=other["headers"]).status_code == 404
    assert client.post("/license/revoke", json={"key": key}, headers=owner["headers"]).status_code == 403
    assert client.post("/license/revoke", json={"key": key}, headers=license_admin_headers).status_code == 200
