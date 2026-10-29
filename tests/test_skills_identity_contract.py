"""Track B Skills IAM identity, delegation, revocation, and tenant isolation."""

import hashlib
import os
import uuid

import fakeredis
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core import token_revocation
from app.core.jwt import create_access_token, create_service_access_token
from app.db.base import Base
from app.db.models import AuditEvent, DelegatedExecutionGrant, OAuthClient, Organization, OrganizationMembership, User
from app.schemas.skills_identity import SkillsDelegationRequest, SkillsIdentityRequest
from app.services import skills_identity_service
from app.services.role_service import get_or_create_role

_engine = create_engine(os.environ["AUTH_TEST_DB_URL"])
Session = sessionmaker(bind=_engine)


@pytest.fixture(scope="module")
def setup_db():
    """Self-contained DB setup; this contract has no HTTP/TestClient dependency."""
    Base.metadata.create_all(bind=_engine)
    original = token_revocation._blacklist
    token_revocation._blacklist = fakeredis.FakeStrictRedis(decode_responses=True)
    try:
        yield
    finally:
        token_revocation._blacklist = original
        Base.metadata.drop_all(bind=_engine)
        _engine.dispose()


@pytest.fixture(autouse=True)
def _reset_rate_limit_state():
    """Override the root HTTP fixture: these in-process contract tests need no TestClient."""
    yield


class HandleProvider:
    def __init__(self, values):
        self.values = values
        self.calls = 0

    def resolve(self, handle):
        self.calls += 1
        return self.values[handle]


class WorkloadProvider:
    def __init__(self, token):
        self.token = token
        self.calls = 0

    def get_token(self):
        self.calls += 1
        return self.token


def _fixture():
    db = Session()
    suffix = uuid.uuid4().hex[:10]
    user = User(email=f"skills-{suffix}@test.invalid", hashed_password="unused", status="active")
    db.add(user)
    db.flush()
    org = Organization(name=f"Skills {suffix}", slug=f"skills-{suffix}", created_by_user_id=user.id)
    db.add(org)
    db.flush()
    role = get_or_create_role(db, f"skills-role-{suffix}", ["skill.discover", "skill.plan", "skill.validate"])
    membership = OrganizationMembership(organization_id=org.id, user_id=user.id, status="active", roles=[role])
    db.add(membership)
    service = OAuthClient(
        organization_id=org.id,
        created_by_user_id=user.id,
        client_id=f"skills-client-{suffix}",
        client_secret_hash=hashlib.sha256(suffix.encode()).hexdigest(),
        name="Skills verifier",
        scopes=["identity.verify", "delegation.verify"],
        status="active",
    )
    db.add(service)
    db.commit()
    user_token = create_access_token({"sub": str(user.id), "permissions": [], "roles": []})
    service_token = create_service_access_token(
        {
            "client_id": service.client_id,
            "org_id": org.id,
            "scopes": ["identity.verify", "delegation.verify"],
            "auth_method": "client_credentials",
        },
        expires_minutes=5,
    )
    return db, user, org, membership, service, user_token, service_token


def _enable(monkeypatch, *tenant_ids):
    monkeypatch.setattr(settings, "SKILLS_IAM_LIVE", True)
    monkeypatch.setattr(settings, "SKILLS_EXECUTION_KILL", False)
    monkeypatch.setattr(settings, "SKILLS_IAM_APPROVAL_REF", "approval:test-only")
    monkeypatch.setattr(settings, "SKILLS_IAM_TENANT_ALLOWLIST", frozenset(str(x) for x in tenant_ids))


def _issue_and_verify(db, org, user_token, service_token):
    subject = HandleProvider({"subject-handle": user_token})
    workload = WorkloadProvider(service_token)
    token, delegation_id = skills_identity_service.issue_delegation(
        db,
        SkillsDelegationRequest(
            subject_credential_handle="subject-handle",
            expected_tenant_id=str(org.id),
            permissions=["skill.discover", "skill.plan"],
        ),
        service_provider=workload,
        subject_provider=subject,
    )
    identity = skills_identity_service.verify_identity(
        db,
        SkillsIdentityRequest(
            credential_handle="skills-handle",
            expected_tenant_id=str(org.id),
            correlation_id=f"corr-{uuid.uuid4().hex}",
            delegation_id=delegation_id,
        ),
        credential_provider=HandleProvider({"skills-handle": token}),
        workload_provider=workload,
    )
    return token, delegation_id, identity


def test_default_off_does_not_resolve_credentials_or_change_behavior(setup_db, monkeypatch):
    db, _user, org, _membership, _service, _user_token, service_token = _fixture()
    provider = HandleProvider({"skills-handle": "must-not-be-read"})
    workload = WorkloadProvider(service_token)
    monkeypatch.setattr(settings, "SKILLS_EXECUTION_KILL", True)
    try:
        with pytest.raises(skills_identity_service.SkillsIdentityError, match="KILL_SWITCH_ACTIVE"):
            skills_identity_service.verify_identity(
                db,
                SkillsIdentityRequest(
                    credential_handle="skills-handle",
                    expected_tenant_id=str(org.id),
                    correlation_id="corr-default-off",
                ),
                credential_provider=provider,
                workload_provider=workload,
            )
        assert provider.calls == 0
        assert workload.calls == 0
        monkeypatch.setattr(settings, "SKILLS_EXECUTION_KILL", False)
        monkeypatch.setattr(settings, "SKILLS_IAM_LIVE", False)
        with pytest.raises(skills_identity_service.SkillsIdentityError, match="FEATURE_DISABLED"):
            skills_identity_service.verify_identity(
                db,
                SkillsIdentityRequest(
                    credential_handle="skills-handle",
                    expected_tenant_id=str(org.id),
                    correlation_id="corr-feature-off",
                ),
                credential_provider=provider,
                workload_provider=workload,
            )
        assert provider.calls == 0
        assert workload.calls == 0
    finally:
        db.close()


def test_verified_identity_has_complete_versioned_claims_and_no_bearer_leak(setup_db, monkeypatch):
    db, user, org, _membership, service, user_token, service_token = _fixture()
    _enable(monkeypatch, org.id)
    try:
        token, delegation_id, identity = _issue_and_verify(db, org, user_token, service_token)
        assert identity.principal_id == str(user.id)
        assert identity.tenant_id == str(org.id)
        assert identity.permissions == ["skill.discover", "skill.plan"]
        assert identity.delegation_id == delegation_id
        assert identity.actor_client_id == service.client_id
        assert identity.schema_version == "skills.iam/v1"
        assert identity.authority == "omnibioai-auth"
        assert identity.issued_at < identity.expires_at
        assert identity.verification_reference
        event = db.query(AuditEvent).filter(AuditEvent.event_type == "skill_identity_verified").order_by(AuditEvent.id.desc()).first()
        assert event is not None
        assert token not in str(event.event_metadata)
        assert "skills-handle" not in str(event.event_metadata)
    finally:
        db.close()


def test_verification_is_tenant_bound_with_no_service_account_fallback(setup_db, monkeypatch):
    db, _user, org, _membership, _service, user_token, service_token = _fixture()
    other_user = User(email=f"other-{uuid.uuid4().hex}@test.invalid", hashed_password="unused", status="active")
    db.add(other_user)
    db.flush()
    other_org = Organization(name="Other Skills Tenant", slug=f"other-{uuid.uuid4().hex[:10]}", created_by_user_id=other_user.id)
    db.add(other_org)
    db.commit()
    _enable(monkeypatch, org.id, other_org.id)
    try:
        token, _delegation_id, _identity = _issue_and_verify(db, org, user_token, service_token)
        with pytest.raises(skills_identity_service.SkillsIdentityError, match="TENANT_MISMATCH"):
            skills_identity_service.verify_identity(
                db,
                SkillsIdentityRequest(
                    credential_handle="skills-handle",
                    expected_tenant_id=str(other_org.id),
                    correlation_id="corr-cross-tenant",
                ),
                credential_provider=HandleProvider({"skills-handle": token}),
                workload_provider=WorkloadProvider(service_token),
            )
    finally:
        db.close()


@pytest.mark.parametrize("revocation", ["grant", "membership", "permission", "service"])
def test_revocation_and_live_authority_changes_fail_closed(setup_db, monkeypatch, revocation):
    db, _user, org, membership, service, user_token, service_token = _fixture()
    _enable(monkeypatch, org.id)
    try:
        token, delegation_id, _identity = _issue_and_verify(db, org, user_token, service_token)
        grant = db.query(DelegatedExecutionGrant).filter(DelegatedExecutionGrant.delegation_id == delegation_id).one()
        if revocation == "grant":
            from datetime import datetime
            grant.revoked_at = datetime.utcnow()
        elif revocation == "membership":
            membership.status = "removed"
        elif revocation == "permission":
            membership.roles = []
        else:
            service.status = "revoked"
        db.commit()
        with pytest.raises(skills_identity_service.SkillsIdentityError, match="REVOKED"):
            skills_identity_service.verify_identity(
                db,
                SkillsIdentityRequest(
                    credential_handle="skills-handle",
                    expected_tenant_id=str(org.id),
                    correlation_id=f"corr-revoked-{revocation}",
                    delegation_id=delegation_id,
                ),
                credential_provider=HandleProvider({"skills-handle": token}),
                workload_provider=WorkloadProvider(service_token),
            )
    finally:
        db.close()


def test_delegation_rejects_cross_tenant_subject_and_permission_escalation(setup_db, monkeypatch):
    db, _user, org, _membership, _service, user_token, service_token = _fixture()
    _enable(monkeypatch, org.id)
    try:
        for permissions in (["skill.execute"], ["workflow.execute"]):
            with pytest.raises(skills_identity_service.SkillsIdentityError, match="INVALID"):
                skills_identity_service.issue_delegation(
                    db,
                    SkillsDelegationRequest(
                        subject_credential_handle="subject-handle",
                        expected_tenant_id=str(org.id),
                        permissions=permissions,
                    ),
                    service_provider=WorkloadProvider(service_token),
                    subject_provider=HandleProvider({"subject-handle": user_token}),
                )
    finally:
        db.close()
