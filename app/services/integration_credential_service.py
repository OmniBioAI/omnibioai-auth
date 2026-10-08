"""Encrypted integration credential lifecycle and opaque reference resolution."""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import settings
from app.db.models import IntegrationCredential, IntegrationCredentialReference, OrganizationMembership
from app.services import audit_service
from app.services.audit_service import AuditEventType
from app.services.integration_provider_client import get_provider_policy

VALID_SCOPES = {"user", "organization", "platform"}
CONSUMER = "workbench"
PURPOSE = "integration_execution"


class CredentialError(Exception):
    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code


def _active_org_id(user: dict) -> int | None:
    value = user.get("org_id")
    return value if type(value) is int and value > 0 else None


def _membership(db: Session, user_id: int, org_id: int | None) -> OrganizationMembership | None:
    if org_id is None:
        return None
    return db.query(OrganizationMembership).filter_by(
        organization_id=org_id, user_id=user_id, status="active"
    ).first()


def _require_org_context(db: Session, user: dict, *, administer: bool) -> tuple[int, OrganizationMembership]:
    user_id = int(user["sub"])
    org_id = _active_org_id(user)
    membership = _membership(db, user_id, org_id)
    if membership is None:
        raise CredentialError("Organization context is unavailable.", 404)
    if administer:
        permissions = {permission.name for role in membership.roles for permission in role.permissions}
        if "manage_org" not in permissions:
            raise CredentialError("Forbidden.", 403)
    return org_id, membership


def _policy(provider_id: str) -> dict:
    try:
        return get_provider_policy(provider_id)
    except Exception as exc:
        raise CredentialError("Provider is unavailable.", 404) from exc


def _validate_payload(policy: dict, credentials: dict[str, str]) -> dict[str, str]:
    if not isinstance(credentials, dict):
        raise CredentialError("Credentials must be an object.")
    fields = policy["authentication"].get("fields") or []
    allowed = {field["name"]: field for field in fields}
    if set(credentials) - set(allowed):
        raise CredentialError("Credential fields are invalid.")
    normalized: dict[str, str] = {}
    for name, descriptor in allowed.items():
        value = credentials.get(name)
        if descriptor.get("required") and (not isinstance(value, str) or not value.strip()):
            raise CredentialError("Required credential fields are missing.")
        if value is not None:
            if not isinstance(value, str) or not value.strip() or len(value) > 8192:
                raise CredentialError("Credential fields are invalid.")
            normalized[name] = value.strip()
    if not normalized:
        raise CredentialError("At least one credential value is required.")
    return normalized


def _owner(scope: str, user: dict, db: Session, administer_org: bool = False) -> tuple[str, int | None, int | None]:
    user_id = int(user["sub"])
    if scope == "user":
        return f"user:{user_id}", user_id, None
    if scope == "organization":
        org_id, _ = _require_org_context(db, user, administer=administer_org)
        return f"organization:{org_id}", None, org_id
    raise CredentialError("Platform credential mutation is not available.", 403)


def _query_owner(db: Session, provider_id: str, scope: str, user: dict) -> IntegrationCredential | None:
    owner_key, _, _ = _owner(scope, user, db)
    return db.query(IntegrationCredential).filter_by(
        provider_id=provider_id, scope=scope, owner_key=owner_key
    ).first()


def _masked_hint(payload: dict[str, str]) -> str | None:
    value = next(iter(payload.values()), "")
    return f"••••{value[-4:]}" if len(value) >= 8 else None


def _display_metadata(value: dict | None, secret_values: list[str]) -> dict | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) - {"label", "account"}:
        raise CredentialError("Display metadata is invalid.")
    if any(not isinstance(item, str) or not item.strip() or len(item) > 128 for item in value.values()):
        raise CredentialError("Display metadata is invalid.")
    if any(secret and secret in item for item in value.values() for secret in secret_values):
        raise CredentialError("Display metadata must not contain credential values.")
    return {key: item.strip() for key, item in value.items()}


def metadata(credential: IntegrationCredential) -> dict:
    return {
        "provider_id": credential.provider_id,
        "scope": credential.scope,
        "configured": credential.status == "active",
        "status": credential.status,
        "masked_hint": credential.masked_hint,
        "display_metadata": credential.display_metadata,
        "created_at": credential.created_at.isoformat(),
        "updated_at": credential.updated_at.isoformat(),
    }


def list_metadata(db: Session, user: dict) -> list[dict]:
    user_id = int(user["sub"])
    owner_keys = [f"user:{user_id}"]
    org_id = _active_org_id(user)
    if _membership(db, user_id, org_id) is not None:
        owner_keys.append(f"organization:{org_id}")
    rows = db.query(IntegrationCredential).filter(
        IntegrationCredential.owner_key.in_(owner_keys), IntegrationCredential.status == "active"
    ).order_by(IntegrationCredential.provider_id, IntegrationCredential.scope).all()
    return [metadata(row) for row in rows]


def set_credential(db: Session, provider_id: str, scope: str, credentials: dict[str, str], display_metadata: dict | None, user: dict) -> IntegrationCredential:
    policy = _policy(provider_id)
    if scope not in policy["authentication"].get("allowed_scopes", []):
        raise CredentialError("Credential scope is not supported.")
    owner_key, owner_user_id, org_id = _owner(scope, user, db, administer_org=scope == "organization")
    payload = _validate_payload(policy, credentials)
    actor_id = int(user["sub"])
    row = db.query(IntegrationCredential).filter_by(provider_id=provider_id, scope=scope, owner_key=owner_key).first()
    now = datetime.utcnow()
    event_type = AuditEventType.INTEGRATION_CREDENTIAL_REPLACED if row else AuditEventType.INTEGRATION_CREDENTIAL_CREATED
    if row is None:
        row = IntegrationCredential(
            provider_id=provider_id, scope=scope, owner_key=owner_key, user_id=owner_user_id,
            organization_id=org_id, created_by_user_id=actor_id, updated_by_user_id=actor_id,
            created_at=now, updated_at=now,
        )
        db.add(row)
    else:
        row.version += 1
        row.updated_by_user_id = actor_id
        row.updated_at = now
    row.encrypted_payload = crypto.encrypt(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    row.masked_hint = _masked_hint(payload)
    row.display_metadata = _display_metadata(display_metadata, list(payload.values()))
    row.status = "active"
    row.revoked_at = None
    db.flush()
    audit_service.log_event(
        db, event_type, actor_user_id=actor_id, organization_id=org_id,
        resource_type="integration_credential", resource_id=row.id,
        after_state={"provider_id": provider_id, "scope": scope, "status": "active"},
        metadata={"provider_id": provider_id, "scope": scope}, commit=False,
    )
    db.commit()
    db.refresh(row)
    return row


def revoke_credential(db: Session, provider_id: str, scope: str, user: dict) -> IntegrationCredential:
    policy = _policy(provider_id)
    if scope not in policy["authentication"].get("allowed_scopes", []):
        raise CredentialError("Credential scope is not supported.")
    owner_key, _, org_id = _owner(scope, user, db, administer_org=scope == "organization")
    row = db.query(IntegrationCredential).filter_by(provider_id=provider_id, scope=scope, owner_key=owner_key, status="active").first()
    if row is None:
        raise CredentialError("Credential is not configured.", 404)
    row.status = "revoked"
    row.encrypted_payload = None
    row.masked_hint = None
    row.revoked_at = datetime.utcnow()
    row.updated_at = row.revoked_at
    row.updated_by_user_id = int(user["sub"])
    row.version += 1
    db.query(IntegrationCredentialReference).filter_by(credential_id=row.id, revoked_at=None).update(
        {IntegrationCredentialReference.revoked_at: row.revoked_at}, synchronize_session=False
    )
    audit_service.log_event(
        db, AuditEventType.INTEGRATION_CREDENTIAL_REVOKED, actor_user_id=int(user["sub"]), organization_id=org_id,
        resource_type="integration_credential", resource_id=row.id,
        before_state={"provider_id": provider_id, "scope": scope, "status": "active"},
        after_state={"provider_id": provider_id, "scope": scope, "status": "revoked"},
        metadata={"provider_id": provider_id, "scope": scope}, commit=False,
    )
    db.commit()
    db.refresh(row)
    return row


def status(db: Session, provider_id: str, user: dict) -> dict:
    policy = _policy(provider_id)
    auth = policy["authentication"]
    for scope in auth.get("resolution_policy", []):
        if scope == "anonymous":
            return {"provider_id": provider_id, "status": "READY_NO_CREDENTIALS", "scope": "anonymous"}
        if scope == "platform":
            continue
        try:
            row = _query_owner(db, provider_id, scope, user)
        except CredentialError:
            continue
        if row is not None and row.status == "active":
            return {"provider_id": provider_id, "status": f"CONNECTED_{scope.upper()}", "scope": scope}
    return {"provider_id": provider_id, "status": "NOT_CONFIGURED", "scope": None}


def issue_reference(db: Session, provider_id: str, consumer: str, purpose: str, user: dict) -> dict:
    if consumer != CONSUMER or purpose != PURPOSE:
        raise CredentialError("Credential reference binding is not allowed.", 403)
    policy = _policy(provider_id)
    user_id = int(user["sub"])
    org_id = _active_org_id(user)
    selected = None
    for scope in policy["authentication"].get("resolution_policy", []):
        if scope == "anonymous":
            return {"provider_id": provider_id, "resolved_scope": "anonymous", "credential_ref": None, "expires_at": None}
        if scope == "platform":
            continue
        try:
            candidate = _query_owner(db, provider_id, scope, user)
        except CredentialError:
            candidate = None
        if candidate is not None and candidate.status == "active":
            selected = candidate
            break
    if selected is None:
        raise CredentialError("Credential is not configured.", 404)
    opaque = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(seconds=settings.INTEGRATION_CREDENTIAL_REFERENCE_TTL_SECONDS)
    reference = IntegrationCredentialReference(
        token_hash=hashlib.sha256(opaque.encode()).hexdigest(), credential_id=selected.id,
        credential_version=selected.version, provider_id=provider_id, scope=selected.scope,
        subject_user_id=user_id, organization_id=org_id, consumer=consumer, purpose=purpose,
        expires_at=expires_at,
    )
    db.add(reference)
    db.flush()
    audit_service.log_event(
        db, AuditEventType.INTEGRATION_CREDENTIAL_REFERENCE_ISSUED, actor_user_id=user_id,
        organization_id=org_id, resource_type="integration_credential_reference", resource_id=reference.id,
        metadata={"provider_id": provider_id, "scope": selected.scope, "consumer": consumer, "purpose": purpose},
        commit=False,
    )
    db.commit()
    return {"provider_id": provider_id, "resolved_scope": selected.scope, "credential_ref": opaque, "expires_at": expires_at.isoformat()}


def resolve_reference(db: Session, credential_ref: str, provider_id: str, consumer: str, purpose: str) -> dict:
    digest = hashlib.sha256(credential_ref.encode()).hexdigest()
    reference = db.query(IntegrationCredentialReference).filter_by(token_hash=digest).first()
    now = datetime.utcnow()
    if (
        reference is None or reference.revoked_at is not None or reference.expires_at <= now
        or reference.provider_id != provider_id or reference.consumer != consumer or reference.purpose != purpose
    ):
        raise CredentialError("Credential reference is unavailable.", 404)
    credential = db.query(IntegrationCredential).filter_by(id=reference.credential_id).first()
    if (
        credential is None or credential.status != "active" or not credential.encrypted_payload
        or credential.provider_id != provider_id or credential.scope != reference.scope
        or credential.version != reference.credential_version
    ):
        raise CredentialError("Credential reference is unavailable.", 404)
    if credential.scope == "user" and credential.user_id != reference.subject_user_id:
        raise CredentialError("Credential reference is unavailable.", 404)
    if reference.organization_id is not None and _membership(
        db, reference.subject_user_id, reference.organization_id
    ) is None:
        raise CredentialError("Credential reference is unavailable.", 404)
    if credential.scope == "organization" and credential.organization_id != reference.organization_id:
        raise CredentialError("Credential reference is unavailable.", 404)
    try:
        payload = json.loads(crypto.decrypt(credential.encrypted_payload))
    except Exception as exc:
        raise CredentialError("Credential resolution failed.", 500) from exc
    audit_service.log_event(
        db, AuditEventType.INTEGRATION_CREDENTIAL_RESOLVED, actor_user_id=reference.subject_user_id,
        organization_id=reference.organization_id, resource_type="integration_credential", resource_id=credential.id,
        metadata={"provider_id": provider_id, "scope": credential.scope, "consumer": consumer, "purpose": purpose},
    )
    return {"provider_id": provider_id, "scope": credential.scope, "credentials": payload}


def connection_test(db: Session, provider_id: str, user: dict) -> dict:
    _policy(provider_id)
    result = {"provider_id": provider_id, "status": "TEST_NOT_SUPPORTED"}
    audit_service.log_event(
        db, AuditEventType.INTEGRATION_CONNECTION_TESTED, actor_user_id=int(user["sub"]),
        organization_id=_active_org_id(user), resource_type="integration_provider", resource_id=provider_id,
        metadata={"provider_id": provider_id, "status": result["status"]},
    )
    return result
