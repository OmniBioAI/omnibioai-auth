"""Real Auth validation; only the existing suite's isolated DB/Redis are substituted."""
from datetime import datetime, timedelta
import hashlib
import uuid
from unittest.mock import patch
import pytest

from app.core.jwt import _sign, decode_token, decode_token_for_audience
from app.db.models import DelegatedExecutionGrant, OAuthClient, Organization, OrganizationMembership, RevokedToken, User
from app.db.session import SessionLocal as Session
from test_artifact_delegation import setup, issue, header

SCOPE = "billing.artifact_entitlements"
PATH = "/service/delegations/artifact/entitlement-context"


def credentials(client):
    data = setup(client)
    artifact = issue(client, data).json()["access_token"]
    # A separate Workbench service uses the real client-credentials route.
    # Registration is synthetic; production provisions the same OAuthClient model.
    workbench_id, secret = f"workbench-{uuid.uuid4().hex}", f"secret-{uuid.uuid4().hex}"
    with Session() as db:
        tes = db.query(OAuthClient).filter_by(client_id=data["client_id"]).one()
        db.add(OAuthClient(
            organization_id=tes.organization_id, created_by_user_id=tes.created_by_user_id,
            client_id=workbench_id, client_secret_hash=hashlib.sha256(secret.encode()).hexdigest(),
            name="Workbench Artifact Billing", scopes=[SCOPE], status="active",
        ))
        db.commit()
    issued = client.post("/oauth/token", data={
        "grant_type": "client_credentials", "client_id": workbench_id,
        "client_secret": secret, "scope": SCOPE,
    })
    assert issued.status_code == 200, issued.text
    data["workbench_id"] = workbench_id
    return data, artifact, issued.json()["access_token"]


def test_context_binds_verified_owner_org_project_and_service(client):
    data, artifact, service = credentials(client)
    response = client.post(PATH, json={"token": artifact}, headers=header(service))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["organization_id"] == str(data["org"]["id"])
    assert body["project_id"] == "8101" and body["run_id"] == "run-9"
    assert body["scope"] == SCOPE and body["service_client_id"] == data["workbench_id"]
    assert body["client_id"] == data["client_id"] != data["workbench_id"]
    assert artifact not in str(body) and service not in str(body)


def test_inactive_organization_denied(client):
    data, artifact, service = credentials(client)
    with Session() as db:
        db.query(Organization).filter_by(id=data['org']['id']).one().status = 'suspended'
        db.commit()
    assert client.post(PATH, json={'token': artifact}, headers=header(service)).status_code == 403


def test_context_audit_contains_no_bearers_or_personal_data(client):
    from app.db.models import AuditEvent
    _, artifact, service = credentials(client)
    assert client.post(PATH, json={'token': artifact}, headers=header(service)).status_code == 200
    with Session() as db:
        event = db.query(AuditEvent).filter_by(event_type='artifact_entitlement_context_allowed').order_by(AuditEvent.id.desc()).first()
        assert set(event.event_metadata) == {'service_client_id', 'project_id', 'run_id'}
        assert artifact not in str(event.event_metadata) and service not in str(event.event_metadata)


def test_audit_commit_failure_cannot_return_authorization_success(client):
    from sqlalchemy.exc import OperationalError
    _, artifact, service = credentials(client)
    with patch('sqlalchemy.orm.Session.commit', side_effect=OperationalError('synthetic', {}, Exception('unavailable'))):
        response = client.post(PATH, json={'token': artifact}, headers=header(service))
    assert response.status_code == 503
    assert artifact not in response.text and service not in response.text


@pytest.mark.parametrize("changes", [
    {"aud": "omnibioai-artifact-manager"}, {"aud": None}, {"iss": "forged"},
    {"iss": None}, {"exp": 1}, {"exp": None}, {"jti": None},
    {"scopes": []}, {"sub": "123"}, {"email": "forged@test.invalid"},
    {"org_id": 999999}, {"auth_method": "password"}, {"type": "refresh"},
])
def test_service_claims_fail_closed(client, changes):
    _, artifact, service = credentials(client)
    claims = decode_token(service)
    for key, value in changes.items():
        if value is None:
            claims.pop(key, None)
        else:
            claims[key] = value
    # _sign fills absent issuer/audience: remove after signing for missing tests.
    from jose import jwt
    from app.core.config import settings
    bad = jwt.encode(claims, settings.SECRET_KEY, algorithm="HS256")
    assert client.post(PATH, json={"token": artifact}, headers=header(bad)).status_code in (401, 403)


@pytest.mark.parametrize("mode", ["disabled", "expired", "scope_removed", "revoked"])
def test_live_service_state_is_rechecked(client, mode):
    data, artifact, service = credentials(client)
    with Session() as db:
        row = db.query(OAuthClient).filter_by(client_id=data["workbench_id"]).one()
        if mode == "disabled": row.status = "disabled"
        if mode == "expired": row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        if mode == "scope_removed": row.scopes = ["artifact.delegate", "artifact.promote"]
        if mode == "revoked": db.add(RevokedToken(token_jti=decode_token(service)["jti"]))
        db.commit()
    assert client.post(PATH, json={"token": artifact}, headers=header(service)).status_code in (401, 403)


def test_human_forwarding_and_cross_organization_denied(client):
    data, artifact, service = credentials(client)
    assert client.post(PATH, json={"token": artifact}, headers=header(data["user"])).status_code == 403
    assert client.post(PATH, json={"token": data["user"]}, headers=header(service)).status_code == 403
    _, other_artifact, _ = credentials(client)
    assert client.post(PATH, json={"token": other_artifact}, headers=header(service)).status_code == 403


@pytest.mark.parametrize("field", ["user_id", "owner_id", "organization_id", "plan", "storage_quota_bytes", "project_id"])
def test_context_rejects_client_overrides(client, field):
    _, artifact, service = credentials(client)
    response = client.post(PATH, json={"token": artifact, field: "forged"}, headers=header(service))
    assert response.status_code == 422


@pytest.mark.parametrize("field,value", [
    ("aud", None), ("aud", "omnibioai-platform"), ("iss", None), ("iss", "forged"),
    ("exp", None), ("exp", 1), ("sub", "999999"), ("org_id", 999999),
    ("project_id", "forged"), ("run_id", "forged"), ("output_ids", ["forged"]),
    ("permissions", [SCOPE]), ("jti", "forged"),
])
def test_artifact_proof_claims_are_bound_to_live_grant(client, field, value):
    from jose import jwt
    from app.core.config import settings
    _, artifact, service = credentials(client)
    claims = decode_token_for_audience(artifact, "omnibioai-artifact-manager")
    if value is None:
        claims.pop(field, None)
    else:
        claims[field] = value
    bad = jwt.encode(claims, settings.SECRET_KEY, algorithm="HS256")
    response = client.post(PATH, json={"token": bad}, headers=header(service))
    assert response.status_code == 403
    assert bad not in response.text and service not in response.text


@pytest.mark.parametrize("mode", ["grant_revoked", "grant_expired", "tes_disabled", "tes_moved", "user_disabled", "membership_inactive"])
def test_live_delegation_state_is_rechecked(client, mode):
    data, artifact, service = credentials(client)
    claims = decode_token_for_audience(artifact, "omnibioai-artifact-manager")
    with Session() as db:
        grant = db.query(DelegatedExecutionGrant).filter_by(delegation_id=claims["jti"]).one()
        if mode == "grant_revoked": grant.revoked_at = datetime.utcnow()
        if mode == "grant_expired": grant.expires_at = datetime.utcnow() - timedelta(seconds=1)
        if mode == "tes_disabled": db.query(OAuthClient).filter_by(client_id=data["client_id"]).one().status = "disabled"
        if mode == "tes_moved": db.query(OAuthClient).filter_by(client_id=data["client_id"]).one().organization_id += 99999
        if mode == "user_disabled": db.query(User).filter_by(id=grant.user_id).one().status = "disabled"
        if mode == "membership_inactive":
            db.query(OrganizationMembership).filter_by(user_id=grant.user_id, organization_id=grant.organization_id).one().status = "inactive"
        db.commit()
    assert client.post(PATH, json={"token": artifact}, headers=header(service)).status_code == 403


def test_revocation_dependency_failure_never_authorizes_or_leaks_credentials(client):
    _, artifact, service = credentials(client)
    with patch("app.core.token_revocation._blacklist.exists", side_effect=RuntimeError("unavailable")):
        response = client.post(PATH, json={"token": artifact}, headers=header(service))
    assert response.status_code == 503
    assert artifact not in response.text and service not in response.text
