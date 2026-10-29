"""Fail-closed, default-off IAM port for the Track B Skills integration."""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import uuid
from typing import Protocol

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import create_skills_identity_token, decode_token, decode_token_for_audience
from app.core.token_revocation import assert_token_usable
from app.db.models import DelegatedExecutionGrant, OAuthClient, OrganizationMembership, User
from app.schemas.skills_identity import SkillsDelegationRequest, SkillsIdentityRequest, SkillsVerifiedIdentity
from app.services import audit_service, org_service, role_service

SKILLS_AUDIENCE = "omnibioai-skills"
VERIFY_SCOPE = "identity.verify"
DELEGATION_SCOPE = "delegation.verify"
SKILLS_PERMISSIONS = frozenset({"skill.discover", "skill.plan", "skill.validate", "skill.execute"})


class CredentialProvider(Protocol):
    """Runtime-injected resolver; implementations must keep bearers process-local."""

    def resolve(self, credential_handle: str) -> str: ...


class WorkloadCredentialProvider(Protocol):
    """Runtime-injected verifier/delegator service credential."""

    def get_token(self) -> str: ...


class SkillsIdentityError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _enabled(tenant_id: str) -> None:
    if settings.SKILLS_EXECUTION_KILL:
        raise SkillsIdentityError("KILL_SWITCH_ACTIVE")
    if not settings.SKILLS_IAM_LIVE:
        raise SkillsIdentityError("FEATURE_DISABLED")
    if not settings.SKILLS_IAM_APPROVAL_REF:
        raise SkillsIdentityError("APPROVAL_MISSING")
    if tenant_id not in settings.SKILLS_IAM_TENANT_ALLOWLIST:
        raise SkillsIdentityError("TENANT_NOT_ENABLED")


def _tenant_pk(tenant_id: str) -> int:
    try:
        value = int(tenant_id)
    except (TypeError, ValueError) as exc:
        raise SkillsIdentityError("TENANT_MISMATCH") from exc
    if value <= 0 or str(value) != tenant_id:
        raise SkillsIdentityError("TENANT_MISMATCH")
    return value


def _effective_permissions(user: User, membership: OrganizationMembership) -> set[str]:
    return role_service.permissions_for_roles(user.roles) | org_service.permissions_for_membership(membership)


def _active_service(db: Session, token: str, tenant_id: str, required_scope: str) -> OAuthClient:
    try:
        payload = decode_token(token)
    except Exception as exc:
        raise SkillsIdentityError("INVALID") from exc
    if payload.get("auth_method") != "client_credentials":
        raise SkillsIdentityError("INVALID")
    try:
        assert_token_usable(payload, db)
    except Exception as exc:
        raise SkillsIdentityError("REVOKED") from exc
    client = db.query(OAuthClient).filter(OAuthClient.client_id == payload.get("client_id")).first()
    now = datetime.utcnow()
    if client is None or client.status != "active" or (client.expires_at and client.expires_at < now):
        raise SkillsIdentityError("REVOKED")
    if str(client.organization_id) != tenant_id or str(payload.get("org_id")) != tenant_id:
        raise SkillsIdentityError("TENANT_MISMATCH")
    token_scopes = set(payload.get("scopes") or [])
    current_scopes = set(client.scopes or [])
    if required_scope not in token_scopes or required_scope not in current_scopes:
        raise SkillsIdentityError("INVALID")
    return client


def issue_delegation(
    db: Session,
    request: SkillsDelegationRequest,
    *,
    service_provider: WorkloadCredentialProvider,
    subject_provider: CredentialProvider,
) -> tuple[str, str]:
    """Create a Skills-only delegation from two injected credential handles."""
    tenant_id = request.expected_tenant_id
    _enabled(tenant_id)
    tenant_pk = _tenant_pk(tenant_id)
    try:
        service_token = service_provider.get_token()
    except Exception as exc:
        raise SkillsIdentityError("UNAVAILABLE") from exc
    service = _active_service(db, service_token, tenant_id, DELEGATION_SCOPE)
    try:
        subject_token = subject_provider.resolve(request.subject_credential_handle)
        payload = decode_token(subject_token)
        if payload.get("type") != "access" or payload.get("auth_method") == "client_credentials":
            raise ValueError("user access token required")
        assert_token_usable(payload, db)
        user_id = int(payload["sub"])
    except SkillsIdentityError:
        raise
    except Exception as exc:
        raise SkillsIdentityError("INVALID") from exc
    user = db.query(User).filter(User.id == user_id, User.status == "active").first()
    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == user_id,
        OrganizationMembership.organization_id == tenant_pk,
        OrganizationMembership.status == "active",
    ).first()
    if user is None or membership is None:
        raise SkillsIdentityError("TENANT_MISMATCH")
    requested = set(request.permissions)
    if not requested or not requested <= SKILLS_PERMISSIONS:
        raise SkillsIdentityError("INVALID")
    if not requested <= _effective_permissions(user, membership):
        raise SkillsIdentityError("INVALID")
    delegation_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(seconds=settings.SKILLS_IDENTITY_TOKEN_EXPIRE_SECONDS)
    grant = DelegatedExecutionGrant(
        delegation_id=delegation_id,
        client_id=service.client_id,
        user_id=user.id,
        organization_id=tenant_pk,
        permissions=sorted(requested),
        audience=SKILLS_AUDIENCE,
        expires_at=expires_at,
    )
    db.add(grant)
    db.commit()
    token = create_skills_identity_token(
        client_id=service.client_id,
        user_id=user.id,
        organization_id=int(tenant_id),
        permissions=sorted(requested),
        delegation_id=delegation_id,
    )
    return token, delegation_id


def _audit(db: Session, event_type: str, request: SkillsIdentityRequest, code: str, **ids: object) -> None:
    audit_service.log_event(
        db,
        event_type,
        organization_id=int(request.expected_tenant_id) if request.expected_tenant_id.isdecimal() else None,
        resource_type="skills_identity",
        resource_id=ids.get("identity_id"),
        metadata={
            "correlation_id": request.correlation_id,
            "outcome": code,
            "authority": "omnibioai-auth",
            "schema_version": "skills.iam/v1",
            **ids,
        },
    )


def verify_identity(
    db: Session,
    request: SkillsIdentityRequest,
    *,
    credential_provider: CredentialProvider,
    workload_provider: WorkloadCredentialProvider,
) -> SkillsVerifiedIdentity:
    """Resolve and verify one immutable tenant-bound identity, or fail closed."""
    try:
        _enabled(request.expected_tenant_id)
        try:
            workload_token = workload_provider.get_token()
        except Exception as exc:
            raise SkillsIdentityError("UNAVAILABLE") from exc
        _active_service(db, workload_token, request.expected_tenant_id, VERIFY_SCOPE)
        try:
            token = credential_provider.resolve(request.credential_handle)
        except Exception as exc:
            raise SkillsIdentityError("UNAVAILABLE") from exc
        try:
            payload = decode_token_for_audience(token, SKILLS_AUDIENCE)
        except Exception as exc:
            raise SkillsIdentityError("INVALID") from exc
        if payload.get("type") != "skills_identity":
            raise SkillsIdentityError("INVALID")
        delegation_id = str(payload.get("delegation_id") or "")
        if not delegation_id or payload.get("jti") != delegation_id:
            raise SkillsIdentityError("DELEGATION_INVALID")
        if request.delegation_id is not None and request.delegation_id != delegation_id:
            raise SkillsIdentityError("DELEGATION_INVALID")
        if str(payload.get("org_id")) != request.expected_tenant_id:
            raise SkillsIdentityError("TENANT_MISMATCH")
        try:
            assert_token_usable(payload, db)
        except Exception as exc:
            raise SkillsIdentityError("REVOKED") from exc
        grant = db.query(DelegatedExecutionGrant).filter(
            DelegatedExecutionGrant.delegation_id == delegation_id,
            DelegatedExecutionGrant.revoked_at.is_(None),
        ).first()
        if grant is None:
            raise SkillsIdentityError("REVOKED")
        now = _now()
        if _as_utc(grant.expires_at) <= now:
            raise SkillsIdentityError("EXPIRED")
        permissions = sorted(payload.get("permissions") or [])
        if (
            grant.audience != SKILLS_AUDIENCE
            or str(grant.organization_id) != request.expected_tenant_id
            or str(grant.user_id) != str(payload.get("sub"))
            or grant.client_id != payload.get("client_id")
            or sorted(grant.permissions or []) != permissions
            or not set(permissions) <= SKILLS_PERMISSIONS
        ):
            raise SkillsIdentityError("DELEGATION_INVALID")
        client = db.query(OAuthClient).filter(OAuthClient.client_id == grant.client_id).first()
        user = db.query(User).filter(User.id == grant.user_id, User.status == "active").first()
        membership = db.query(OrganizationMembership).filter(
            OrganizationMembership.user_id == grant.user_id,
            OrganizationMembership.organization_id == grant.organization_id,
            OrganizationMembership.status == "active",
        ).first()
        if client is None or client.status != "active" or user is None or membership is None:
            raise SkillsIdentityError("REVOKED")
        if DELEGATION_SCOPE not in set(client.scopes or []):
            raise SkillsIdentityError("REVOKED")
        if not set(permissions) <= _effective_permissions(user, membership):
            raise SkillsIdentityError("REVOKED")
        issued_at = datetime.fromtimestamp(float(payload["iat"]), timezone.utc)
        expires_at = datetime.fromtimestamp(float(payload["exp"]), timezone.utc)
        if issued_at > now + timedelta(seconds=5):
            raise SkillsIdentityError("INVALID")
        identity_id = hashlib.sha256(
            f"{grant.user_id}:{grant.organization_id}:{delegation_id}".encode()
        ).hexdigest()
        verification_reference = hashlib.sha256(json.dumps({
            "identity_id": identity_id,
            "tenant_id": request.expected_tenant_id,
            "permissions": permissions,
            "delegation_id": delegation_id,
            "approval": settings.SKILLS_IAM_APPROVAL_REF,
            "revocation_checked_at": now.isoformat(),
        }, sort_keys=True).encode()).hexdigest()
        result = SkillsVerifiedIdentity(
            principal_id=str(grant.user_id),
            tenant_id=request.expected_tenant_id,
            permissions=permissions,
            identity_id=identity_id,
            issued_at=issued_at,
            expires_at=expires_at,
            revocation_checked_at=now,
            delegation_id=delegation_id,
            actor_client_id=grant.client_id,
            verification_reference=verification_reference,
        )
        _audit(
            db,
            audit_service.AuditEventType.SKILL_IDENTITY_VERIFIED,
            request,
            "verified",
            identity_id=identity_id,
            delegation_id=delegation_id,
        )
        return result
    except SkillsIdentityError as exc:
        _audit(db, audit_service.AuditEventType.SKILL_IDENTITY_REJECTED, request, exc.code)
        raise
