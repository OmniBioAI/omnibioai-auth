"""Transactional, identity-bound manual-license administration.

IAM roles remain ordinary IAM assignments.  The license records only the
resolved persona role for display; authorization continues to come from the
membership tables, never from key contents.
"""
from __future__ import annotations

import hashlib
import json
from datetime import timedelta

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import AuditEvent, LicenseIssuanceRequest, LicenseKey, OrganizationMembership, User
from app.services import audit_service, license_service, org_service, role_service
from app.services.audit_service import AuditEventType

PERSONA_ROLES = {
    "developer": "scientist",
    "application_user": "org_member",
}


class ManualLicenseError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def configured_validities() -> tuple[int, ...]:
    return settings.LICENSE_ALLOWED_VALIDITY_DAYS


def require_validity(days: int) -> None:
    if not configured_validities():
        raise ManualLicenseError(
            "validity_policy_unconfigured",
            "Manual issuance is disabled until LICENSE_ALLOWED_VALIDITY_DAYS is configured",
            503,
        )
    if days not in configured_validities():
        raise ManualLicenseError("unsupported_validity", "Unsupported license validity", 422)


def _fingerprint(payload: dict) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _idempotency_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def status_for(license_key: LicenseKey) -> str:
    if license_key.revoked_at is not None:
        return "revoked"
    if license_key.expires_at is not None and license_key.expires_at <= license_service.utc_now():
        return "expired"
    return "active"


def persona_for(license_key: LicenseKey) -> str:
    membership = None
    if license_key.user_id and license_key.organization_id:
        membership = getattr(license_key, "_manual_membership", None)
    roles = {role.name for role in membership.roles} if membership else set()
    return "developer" if "scientist" in roles else "application_user"


def metadata_for(db: Session, license_key: LicenseKey) -> dict:
    membership = None
    if license_key.user_id is not None and license_key.organization_id is not None:
        membership = org_service.get_membership(db, license_key.organization_id, license_key.user_id)
    role_names = {role.name for role in membership.roles} if membership else set()
    persona = (
        "developer" if "scientist" in role_names
        else "application_user" if "org_member" in role_names
        else None
    )
    iam_role = PERSONA_ROLES[persona] if persona else None
    return {
        "id": license_key.id,
        "key_prefix": license_key.key_prefix or ((license_key.key or "")[:9]),
        "masked_key": license_service.masked_key(license_key),
        "recipient_name": license_key.recipient_name,
        "email": license_key.email,
        "user_id": license_key.user_id,
        "organization_id": license_key.organization_id,
        "persona": persona,
        "iam_role": iam_role,
        "plan": license_key.plan,
        "platform": license_key.platform,
        "created_at": license_key.created_at,
        "expires_at": license_key.expires_at,
        "renewed_at": license_key.renewed_at,
        "last_used_at": license_key.last_used_at,
        "revoked_at": license_key.revoked_at,
        "revoked_reason": license_key.revoked_reason,
        "status": status_for(license_key),
    }


def issue(
    db: Session,
    *,
    actor_user_id: int,
    idempotency_key: str,
    full_name: str,
    email: str,
    persona: str,
    validity_days: int,
    organization_id: int,
    confirm_role_change: bool,
    confirm_replace_existing: bool,
) -> tuple[LicenseKey, str | None, bool]:
    require_validity(validity_days)
    if not settings.LICENSE_KEY_PEPPER:
        raise ManualLicenseError("key_verifier_unconfigured", "Manual issuance is not configured", 503)
    if len(idempotency_key.strip()) < 16 or len(idempotency_key) > 200:
        raise ManualLicenseError("invalid_idempotency_key", "Idempotency-Key must be 16-200 characters", 422)

    normalized_email = email.strip().lower()
    normalized_name = " ".join(full_name.split())
    request_data = {
        "full_name": normalized_name,
        "email": normalized_email,
        "persona": persona,
        "validity_days": validity_days,
        "organization_id": organization_id,
        "confirm_role_change": confirm_role_change,
        "confirm_replace_existing": confirm_replace_existing,
    }
    key_hash = _idempotency_hash(idempotency_key.strip())
    fingerprint = _fingerprint(request_data)
    existing_request = db.query(LicenseIssuanceRequest).filter(
        LicenseIssuanceRequest.actor_user_id == actor_user_id,
        LicenseIssuanceRequest.idempotency_key_hash == key_hash,
    ).first()
    if existing_request:
        if existing_request.request_fingerprint != fingerprint:
            raise ManualLicenseError("idempotency_conflict", "Idempotency key was used for a different request", 409)
        if existing_request.license_id is None:
            raise ManualLicenseError("issuance_in_progress", "The original issuance request is still in progress", 409)
        license_key = db.query(LicenseKey).filter(LicenseKey.id == existing_request.license_id).one()
        return license_key, None, True

    issuance = LicenseIssuanceRequest(
        actor_user_id=actor_user_id,
        idempotency_key_hash=key_hash,
        request_fingerprint=fingerprint,
    )
    db.add(issuance)
    db.flush()  # unique actor/key constraint serializes concurrent retries

    owner = db.query(User).filter(func.lower(User.email) == normalized_email).with_for_update().first()
    if owner is None:
        raise ManualLicenseError(
            "provisioning_required",
            "No identity exists for this email; use the approved invitation workflow first",
            409,
        )
    if owner.status != "active":
        raise ManualLicenseError("identity_inactive", "The license owner identity is not active", 409)

    membership = db.query(OrganizationMembership).filter(
        OrganizationMembership.user_id == owner.id,
        OrganizationMembership.organization_id == organization_id,
        OrganizationMembership.status == "active",
    ).with_for_update().first()
    if membership is None:
        # Same response for a nonexistent org and a cross-tenant owner.
        raise ManualLicenseError("organization_membership_required", "Active organization membership is required", 404)

    iam_role_name = PERSONA_ROLES[persona]
    # Reuse the canonical lazy bootstrap used by organization invitation:
    # org_member is intentionally not created until first use.
    if iam_role_name == org_service.ORG_MEMBER_ROLE:
        iam_role = role_service.get_or_create_role(db, org_service.ORG_MEMBER_ROLE, [])
    elif iam_role_name == org_service.SCIENTIST_ROLE:
        iam_role = role_service.get_or_create_role(
            db, org_service.SCIENTIST_ROLE, org_service.SCIENTIST_PERMISSIONS,
        )
    else:  # PERSONA_ROLES is closed, but keep the boundary fail-closed.
        raise ManualLicenseError("iam_role_unavailable", "Required IAM role is not configured", 503)
    global_user_role = role_service.get_or_create_role(db, "user", [])

    other_role_name = (
        org_service.ORG_MEMBER_ROLE
        if iam_role_name == org_service.SCIENTIST_ROLE
        else org_service.SCIENTIST_ROLE
    )
    other_role = role_service.get_role_in_scope(db, other_role_name, organization_id)
    role_change = (
        iam_role not in membership.roles or global_user_role not in owner.roles or
        (other_role is not None and other_role in membership.roles)
    )
    if role_change and not confirm_role_change:
        raise ManualLicenseError(
            "role_change_confirmation_required",
            f"Explicit confirmation is required to assign {iam_role_name}",
            409,
        )

    now = license_service.utc_now()
    active = db.query(LicenseKey).filter(
        LicenseKey.user_id == owner.id,
        LicenseKey.organization_id == organization_id,
        LicenseKey.revoked_at.is_(None),
        or_(LicenseKey.expires_at.is_(None), LicenseKey.expires_at > now),
    ).with_for_update().all()
    if active and not confirm_replace_existing:
        raise ManualLicenseError(
            "active_license_confirmation_required",
            "An active license already exists; explicit replacement confirmation is required",
            409,
        )

    if role_change:
        role_service.add_user_role(db, owner, global_user_role, actor_user_id=actor_user_id, commit=False)
        if other_role is not None and other_role in membership.roles:
            org_service.remove_member_role(
                db, membership, other_role, actor_user_id=actor_user_id, commit=False,
            )
        org_service.add_member_role(db, membership, iam_role, actor_user_id=actor_user_id, commit=False)

    for previous in active:
        previous.revoked_at = now
        previous.revoked_reason = "replaced_by_manual_issuance"
        audit_service.log_event(
            db, AuditEventType.LICENSE_REVOKED,
            actor_user_id=actor_user_id, target_user_id=owner.id,
            organization_id=organization_id, resource_type="license", resource_id=previous.id,
            before_state={"status": "active"}, after_state={"status": "revoked"},
            metadata={"reason": "replaced_by_manual_issuance"}, commit=False,
        )

    license_key = license_service.create_license(
        db,
        email=owner.email,
        user_id=owner.id,
        organization_id=organization_id,
        plan="beta",
        platform="both",
        expires_days=validity_days,
        max_uses=1,
        recipient_name=normalized_name,
        commit=False,
    )
    issuance.license_id = license_key.id
    audit_service.log_event(
        db, AuditEventType.LICENSE_ISSUED,
        actor_user_id=actor_user_id, target_user_id=owner.id,
        organization_id=organization_id, resource_type="license", resource_id=license_key.id,
        after_state={
            "status": "active", "persona": persona, "iam_role": iam_role_name,
            "validity_days": validity_days, "plan": license_key.plan,
            "platform": license_key.platform,
        },
        metadata={"key_prefix": license_key.key_prefix}, commit=False,
    )
    one_time_key = license_key._one_time_key
    db.commit()
    db.refresh(license_key)
    return license_key, one_time_key, False


def list_licenses(db: Session, *, organization_id: int | None = None) -> list[LicenseKey]:
    query = db.query(LicenseKey)
    if organization_id is not None:
        query = query.filter(LicenseKey.organization_id == organization_id)
    return query.order_by(LicenseKey.created_at.desc()).all()


def get_license(db: Session, license_id: int, *, lock: bool = False) -> LicenseKey | None:
    query = db.query(LicenseKey).filter(LicenseKey.id == license_id)
    if lock:
        query = query.with_for_update()
    return query.first()


def revoke(db: Session, license_key: LicenseKey, *, actor_user_id: int, reason: str) -> LicenseKey:
    if license_key.revoked_at is None:
        previous_status = status_for(license_key)
        license_key.revoked_at = license_service.utc_now()
        license_key.revoked_reason = reason
        audit_service.log_event(
            db, AuditEventType.LICENSE_REVOKED,
            actor_user_id=actor_user_id, target_user_id=license_key.user_id,
            organization_id=license_key.organization_id, resource_type="license", resource_id=license_key.id,
            before_state={"status": previous_status}, after_state={"status": "revoked"},
            metadata={"reason": reason}, commit=False,
        )
        db.commit()
        db.refresh(license_key)
    return license_key


def renew(db: Session, license_key: LicenseKey, *, actor_user_id: int, validity_days: int) -> LicenseKey:
    require_validity(validity_days)
    if license_key.revoked_at is not None:
        raise ManualLicenseError("revoked_license", "A revoked license cannot be renewed", 409)
    before = license_key.expires_at
    now = license_service.utc_now()
    base = max(before or now, now)
    license_key.expires_at = base + timedelta(days=validity_days)
    license_key.renewed_at = now
    audit_service.log_event(
        db, AuditEventType.LICENSE_RENEWED,
        actor_user_id=actor_user_id, target_user_id=license_key.user_id,
        organization_id=license_key.organization_id, resource_type="license", resource_id=license_key.id,
        before_state={"expires_at": before.isoformat() if before else None},
        after_state={"expires_at": license_key.expires_at.isoformat()},
        metadata={"validity_days": validity_days}, commit=False,
    )
    db.commit()
    db.refresh(license_key)
    return license_key


def history(db: Session, license_id: int) -> list[AuditEvent]:
    return db.query(AuditEvent).filter(
        AuditEvent.resource_type == "license",
        AuditEvent.resource_id == str(license_id),
    ).order_by(AuditEvent.created_at.desc()).all()
