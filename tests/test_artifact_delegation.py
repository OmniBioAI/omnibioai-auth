"""Artifact-specific TES delegation contract and live revocation tests."""
import hashlib
import uuid
from datetime import datetime, timedelta

from app.core.jwt import decode_token_for_audience
from app.db.models import AuditEvent, DelegatedExecutionGrant, OAuthClient, OrganizationMembership, User
from app.services.role_service import get_or_create_role
from app.db.session import SessionLocal as Session


def header(token):
    return {"Authorization": f"Bearer {token}"}


def setup(client, *, service_scopes=None, user_permissions=None):
    email = f"artifact-{uuid.uuid4().hex[:8]}@test.invalid"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    user_token = client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]
    org = client.post("/orgs", json={"name": "Artifact Org", "slug": f"artifact-{uuid.uuid4().hex[:8]}"}, headers=header(user_token)).json()
    client_id, secret = f"tes-{uuid.uuid4().hex}", f"secret-{uuid.uuid4().hex}"
    with Session() as db:
        user = db.query(User).filter(User.email == email).one()
        membership = db.query(OrganizationMembership).filter_by(user_id=user.id, organization_id=org["id"]).one()
        membership.roles.append(get_or_create_role(
            db, f"artifact-role-{uuid.uuid4().hex[:8]}",
            user_permissions or ["artifact.promote"],
        ))
        db.add(OAuthClient(
            organization_id=org["id"], created_by_user_id=user.id, client_id=client_id,
            client_secret_hash=hashlib.sha256(secret.encode()).hexdigest(), name="TES Artifact",
            scopes=service_scopes or ["artifact.delegate", "artifact.promote"], status="active",
        ))
        db.commit()
    service = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": client_id,
        "client_secret": secret, "scope": "artifact.delegate artifact.promote",
    })
    assert service.status_code == 200
    return {"org": org, "user": user_token, "service": service.json()["access_token"], "client_id": client_id}


def issue(client, data, **changes):
    body = {
        "initiating_token": data["user"], "organization_id": data["org"]["id"],
        "project_id": "8101", "run_id": "run-9", "output_ids": ["result"],
        "permissions": ["artifact.promote"], "audience": "omnibioai-artifact-manager",
    }
    body.update(changes)
    return client.post("/service/delegations/artifact", json=body, headers=header(data["service"]))


def introspect(client, token):
    return client.post("/service/delegations/artifact/introspect", json={"token": token})


def test_issues_exact_artifact_scope_and_never_authenticates_as_human(client):
    data = setup(client)
    response = issue(client, data)
    assert response.status_code == 200, response.text
    token = response.json()["access_token"]
    claims = decode_token_for_audience(token, "omnibioai-artifact-manager")
    assert claims["type"] == "artifact_delegation"
    assert claims["client_id"] == data["client_id"]
    assert claims["project_id"] == "8101" and claims["run_id"] == "run-9"
    assert claims["output_ids"] == ["result"] and claims["permissions"] == ["artifact.promote"]
    assert client.post("/auth/validate", json={"token": token}).json()["valid"] is False
    identity = introspect(client, token).json()
    assert identity["valid"] is True and identity["project_id"] == "8101"


def test_rejects_human_caller_cross_org_bad_audience_scope_and_duplicate_outputs(client):
    data = setup(client)
    body = {
        "initiating_token": data["user"], "organization_id": data["org"]["id"],
        "project_id": "8101", "run_id": "run-9", "output_ids": ["result"],
        "permissions": ["artifact.promote"], "audience": "omnibioai-artifact-manager",
    }
    assert client.post("/service/delegations/artifact", json=body, headers=header(data["user"])).status_code == 403
    assert issue(client, data, organization_id=data["org"]["id"] + 999).status_code == 403
    assert issue(client, data, audience="omnibioai-toolserver").status_code == 400
    assert issue(client, data, permissions=["workflow.execute"]).status_code == 400
    assert issue(client, data, output_ids=["result", "result"]).status_code == 400


def test_live_revocation_expiry_and_permission_removal_fail_introspection(client):
    data = setup(client)
    token = issue(client, data).json()["access_token"]
    claims = decode_token_for_audience(token, "omnibioai-artifact-manager")
    with Session() as db:
        grant = db.query(DelegatedExecutionGrant).filter_by(delegation_id=claims["jti"]).one()
        grant.revoked_at = datetime.utcnow()
        db.commit()
    assert introspect(client, token).json()["valid"] is False

    data = setup(client)
    token = issue(client, data).json()["access_token"]
    with Session() as db:
        row = db.query(OAuthClient).filter_by(client_id=data["client_id"]).one()
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    assert introspect(client, token).json()["valid"] is False


def test_audit_records_scope_without_bearers(client):
    data = setup(client)
    response = issue(client, data)
    token = response.json()["access_token"]
    with Session() as db:
        event = db.query(AuditEvent).filter_by(event_type="delegated_execution_token_issued").order_by(AuditEvent.id.desc()).first()
        assert event.resource_type == "artifact_delegation"
        assert event.event_metadata["project_id"] == "8101"
        assert token not in str(event.event_metadata) and data["user"] not in str(event.event_metadata)
