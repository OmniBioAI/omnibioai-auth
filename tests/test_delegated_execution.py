"""Security contract tests for the TES -> ToolServer delegated token foundation."""
import hashlib
import uuid
from datetime import datetime, timedelta

import pytest
from app.core.jwt import _sign

from app.core.jwt import decode_token, decode_token_for_audience
from app.db.models import AuditEvent, DelegatedExecutionGrant, OAuthClient, OrganizationMembership, RevokedToken, User
from app.services.role_service import get_or_create_role
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

_engine = create_engine("sqlite:///./test.db")
Session = sessionmaker(bind=_engine)


def header(token):
    return {"Authorization": f"Bearer {token}"}


def register_login(client, email=None):
    email = email or f"delegation-{uuid.uuid4().hex[:8]}@test.invalid"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    response = client.post("/auth/login", json={"email": email, "password": password})
    return email, password, response.json()["access_token"]


def setup_delegation(client, service_scopes=None, user_permissions=None):
    service_scopes = service_scopes or ["toolserver.delegate", "workflow.execute", "runs.read"]
    user_permissions = user_permissions or ["workflow.execute", "runs.read"]
    email, password, user_token = register_login(client)
    org = client.post("/orgs", json={"name": "Delegation Org", "slug": f"delegation-{uuid.uuid4().hex[:8]}"}, headers=header(user_token)).json()
    db = Session()
    try:
        user = db.query(User).filter(User.email == email).first()
        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.user_id == user.id, OrganizationMembership.organization_id == org["id"]
        ).first()
        role = get_or_create_role(db, f"delegation-role-{uuid.uuid4().hex[:8]}", user_permissions)
        membership.roles.append(role)
        client_id, secret = f"tes-{uuid.uuid4().hex}", f"secret-{uuid.uuid4().hex}"
        oauth = OAuthClient(
            organization_id=org["id"], created_by_user_id=user.id, client_id=client_id,
            client_secret_hash=hashlib.sha256(secret.encode()).hexdigest(), name="TES", scopes=service_scopes, status="active",
        )
        db.add(oauth)
        db.commit()
    finally:
        db.close()
    service = client.post("/oauth/token", data={"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret})
    assert service.status_code == 200
    return {"org": org, "email": email, "password": password, "user": user_token,
            "service": service.json()["access_token"], "client_id": client_id}


def issue(client, data, **overrides):
    body = {"initiating_token": data["user"], "organization_id": data["org"]["id"],
            "permissions": ["workflow.execute"], "audience": "omnibioai-toolserver"}
    body.update(overrides)
    return client.post("/service/delegations/toolserver", json=body, headers=header(data["service"]))


def introspect(client, token):
    return client.post("/service/delegations/toolserver/introspect", json={"token": token})


def test_authorized_tes_issues_audience_bound_typed_delegation(client):
    data = setup_delegation(client)
    response = issue(client, data)
    assert response.status_code == 200
    token = response.json()["access_token"]
    claims = decode_token_for_audience(token, "omnibioai-toolserver")
    assert claims["type"] == "delegated_execution"
    assert claims["aud"] == "omnibioai-toolserver"
    assert claims["client_id"] == data["client_id"]
    assert claims["sub"] and claims["org_id"] == data["org"]["id"]
    assert claims["permissions"] == ["workflow.execute"]
    assert "email" not in claims
    assert response.json()["expires_in"] == 300


def test_delegation_is_not_a_user_or_service_token(client):
    token = issue(client, setup_delegation(client)).json()["access_token"]
    assert client.post("/auth/validate", json={"token": token}).json()["valid"] is False
    assert client.get("/license/status", headers=header(token)).status_code in (401, 403, 404)
    assert introspect(client, token).json()["valid"] is True


def test_arbitrary_service_and_user_are_denied(client):
    data = setup_delegation(client, service_scopes=["workflow.execute"])
    assert issue(client, data).status_code == 403
    ordinary = setup_delegation(client)
    assert client.post("/service/delegations/toolserver", json={"initiating_token": ordinary["user"], "organization_id": ordinary["org"]["id"], "permissions": ["workflow.execute"], "audience": "omnibioai-toolserver"}, headers=header(ordinary["user"])).status_code == 403


def test_issuance_rejects_bad_audience_and_permission_escalation(client):
    data = setup_delegation(client)
    assert issue(client, data, audience="other-service").status_code == 400
    assert issue(client, data, permissions=["workflow.manage"]).status_code == 400
    data = setup_delegation(client, service_scopes=["toolserver.delegate", "workflow.execute"], user_permissions=["workflow.execute", "runs.read"])
    assert issue(client, data, permissions=["runs.read"]).status_code == 403


def test_issuance_requires_authoritative_user_and_membership(client):
    data = setup_delegation(client)
    assert issue(client, data, initiating_token="bad.token.value").status_code == 403
    assert issue(client, data, organization_id=999999).status_code == 403
    other = setup_delegation(client)
    assert issue(client, data, organization_id=other["org"]["id"]).status_code == 403


def test_introspection_fails_closed_for_revocation_and_live_state_changes(client):
    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    claims = decode_token_for_audience(token, "omnibioai-toolserver")
    db = Session()
    try:
        db.add(RevokedToken(token_jti=claims["jti"]))
        db.commit()
    finally:
        db.close()
    assert introspect(client, token).json()["valid"] is False

    token = issue(client, data).json()["access_token"]
    db = Session()
    try:
        client_row = db.query(OAuthClient).filter(OAuthClient.client_id == data["client_id"]).first()
        client_row.status = "revoked"
        db.commit()
    finally:
        db.close()
    assert introspect(client, token).json()["valid"] is False


def test_introspection_rejects_disabled_user_removed_membership_expired_and_invalid_signature(client):
    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    db = Session()
    try:
        user = db.query(User).filter(User.email == data["email"]).first()
        user.status = "disabled"
        db.commit()
    finally:
        db.close()
    assert introspect(client, token).json()["valid"] is False

    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    db = Session()
    try:
        grant = db.query(DelegatedExecutionGrant).filter(DelegatedExecutionGrant.delegation_id == decode_token_for_audience(token, "omnibioai-toolserver")["jti"]).first()
        grant.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    assert introspect(client, token).json()["valid"] is False
    assert introspect(client, "not.a.jwt").json()["valid"] is False


def test_issuance_audit_contains_identifiers_not_raw_token(client):
    data = setup_delegation(client)
    response = issue(client, data)
    token = response.json()["access_token"]
    db = Session()
    try:
        event = db.query(AuditEvent).filter(AuditEvent.event_type == "delegated_execution_token_issued").order_by(AuditEvent.id.desc()).first()
        assert event is not None
        assert event.event_metadata["client_id"] == data["client_id"]
        assert token not in str(event.event_metadata)
    finally:
        db.close()


def test_introspection_rejects_removed_membership_and_permission(client):
    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    db = Session()
    try:
        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == data["org"]["id"],
            OrganizationMembership.user_id == int(decode_token(data["user"])["sub"]),
        ).first()
        membership.status = "removed"
        db.commit()
    finally:
        db.close()
    assert introspect(client, token).json()["valid"] is False

    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    db = Session()
    try:
        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.organization_id == data["org"]["id"],
            OrganizationMembership.user_id == int(decode_token(data["user"])["sub"]),
        ).first()
        membership.roles = []
        db.commit()
    finally:
        db.close()
    assert introspect(client, token).json()["valid"] is False


def test_issuance_rejects_scope_not_held_by_user(client):
    data = setup_delegation(client, user_permissions=["runs.read"])
    assert issue(client, data, permissions=["workflow.execute"]).status_code == 403


# Permanent regressions for live service authorization after delegation issuance.


@pytest.mark.parametrize("change", [
    "delegation_scope", "execution_scope", "expired", "inactive", "null_scopes",
])
def test_current_service_authority_rechecked(client, change):
    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    assert introspect(client, token).json()["valid"] is True
    with Session() as db:
        row = db.query(OAuthClient).filter(OAuthClient.client_id == data["client_id"]).one()
        original_scopes = list(row.scopes)
        if change == "delegation_scope":
            row.scopes = [s for s in row.scopes if s != "toolserver.delegate"]
        elif change == "execution_scope":
            row.scopes = [s for s in row.scopes if s != "workflow.execute"]
        elif change == "expired":
            row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        elif change == "inactive":
            row.status = "revoked"
        else:
            row.scopes = None
        db.commit()
    rejected = introspect(client, token).json()
    assert rejected["valid"] is False
    assert rejected["client_id"] is None
    assert rejected["permissions"] == []
    # These are live checks, not permanent grant revocation. Restoring current
    # authority permits the still-unexpired, independently unrevoked grant.
    with Session() as db:
        row = db.query(OAuthClient).filter(OAuthClient.client_id == data["client_id"]).one()
        row.scopes = original_scopes
        row.status = "active"
        row.expires_at = datetime.utcnow() + timedelta(minutes=10)
        db.commit()
    assert introspect(client, token).json()["valid"] is True


def test_unrelated_scope_change_preserves_grant_authority(client):
    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    with Session() as db:
        row = db.query(OAuthClient).filter(OAuthClient.client_id == data["client_id"]).one()
        row.scopes = ["toolserver.delegate", "workflow.execute"]
        db.commit()
    result = introspect(client, token).json()
    assert result["valid"] is True
    assert result["permissions"] == ["workflow.execute"]


@pytest.mark.parametrize(("claim", "value"), [
    ("exp", 1),
    ("aud", "omnibioai-platform"),
    ("type", "access"),
])
def test_introspection_rejects_wrong_token_semantics(client, claim, value):
    data = setup_delegation(client)
    token = issue(client, data).json()["access_token"]
    claims = decode_token_for_audience(token, "omnibioai-toolserver")
    claims[claim] = value
    # Auth-signed fixture isolates claim validation from signature failure.
    assert introspect(client, _sign(claims)).json()["valid"] is False


def test_delegated_token_rejected_by_service_identity_route(client):
    token = issue(client, setup_delegation(client)).json()["access_token"]
    assert client.get("/service/me", headers=header(token)).status_code == 401
