"""Secure lifecycle for organization-scoped invitations.

The invitation token is a bearer proof delivered to the invited mailbox;
only its SHA-256 digest is persisted. Account creation, role assignment,
membership activation, optional TOTP enrollment, invitation consumption,
and their audit events share one transaction.
"""
from __future__ import annotations

import hashlib
import ipaddress
import secrets
from datetime import datetime, timedelta
from urllib.parse import urlsplit

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import crypto
from app.core.config import settings
from app.core.password_policy import PasswordPolicyError, validate_new_password
from app.core.security import hash_password, verify_password
from app.db.models import (
    MFADevice, Organization, OrganizationInvitation, OrganizationMFAPolicy,
    OrganizationMembership, User,
)
from app.services import audit_service, email_delivery_service, mfa_service, org_service, role_service
from app.services.audit_service import AuditEventType


class OrganizationInvitationError(ValueError):
    def __init__(self, code: str, message: str, status_code: int = 400):
        super().__init__(message)
        self.code = code
        self.status_code = status_code


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _active_key(organization_id: int, email: str) -> str:
    return hashlib.sha256(f"{organization_id}:{email}".encode("utf-8")).hexdigest()


def _valid_accept_url(value: str) -> bool:
    """Require a public-looking HTTPS origin; never email a DGX/container URL."""
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").rstrip(".").lower()
        if parsed.scheme.lower() != "https" or not host or parsed.username or parsed.password:
            return False
        if parsed.port not in (None, 443):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            pass
        if "." not in host:
            return False
        return not host.endswith((".localhost", ".local", ".internal", ".test", ".invalid"))
    except ValueError:
        return False


def _policy_requires_mfa(db: Session, organization_id: int) -> bool:
    policy = db.query(OrganizationMFAPolicy).filter(
        OrganizationMFAPolicy.organization_id == organization_id
    ).first()
    return bool(policy and policy.required and not policy.override_active)


def _audit(db: Session, event: str, invitation: OrganizationInvitation, **kwargs) -> None:
    audit_service.log_event(
        db, event,
        actor_user_id=kwargs.get("actor_user_id"),
        target_user_id=kwargs.get("target_user_id"),
        organization_id=invitation.organization_id,
        resource_type="organization_invitation", resource_id=invitation.id,
        before_state=kwargs.get("before_state"), after_state=kwargs.get("after_state"),
        metadata=kwargs.get("metadata"), commit=False,
    )


def _set_expired(db: Session, invitation: OrganizationInvitation, *, actor_user_id: int | None = None) -> None:
    if invitation.status != "pending":
        return
    invitation.status = "expired"
    invitation.active_key = None
    _audit(
        db, AuditEventType.ORG_INVITATION_EXPIRED, invitation,
        actor_user_id=actor_user_id,
        before_state={"status": "pending"}, after_state={"status": "expired"},
    )


def _pending(db: Session, token: str, *, lock: bool = False) -> OrganizationInvitation:
    if not token or len(token) > 256:
        raise OrganizationInvitationError("invitation_invalid", "Invitation is invalid or unavailable", 404)
    query = db.query(OrganizationInvitation).filter(OrganizationInvitation.token_hash == _token_hash(token))
    invitation = query.with_for_update().first() if lock else query.first()
    if invitation is None:
        raise OrganizationInvitationError("invitation_invalid", "Invitation is invalid or unavailable", 404)
    if invitation.status != "pending":
        raise OrganizationInvitationError("invitation_unavailable", "Invitation is no longer available", 410)
    if invitation.expires_at <= datetime.utcnow():
        _set_expired(db, invitation)
        db.commit()
        raise OrganizationInvitationError("invitation_expired", "Invitation has expired", 410)
    if invitation.organization.status != "active":
        raise OrganizationInvitationError("organization_unavailable", "Organization is not accepting invitations", 409)
    return invitation


def _safe_view(invitation: OrganizationInvitation) -> dict:
    return {
        "id": invitation.id,
        "organization_id": invitation.organization_id,
        "organization_name": invitation.organization.name,
        "email": invitation.invited_email,
        "roles": list(invitation.role_names or []),
        "status": invitation.status,
        "created_at": invitation.created_at,
        "expires_at": invitation.expires_at,
        "accepted_at": invitation.accepted_at,
    }


def create_invitation(
    db: Session,
    *,
    organization: Organization,
    actor: User,
    email: str,
    role_names: list[str],
    caller_is_platform_admin: bool,
) -> OrganizationInvitation:
    if not settings.ORG_INVITATIONS_ENABLED or not settings.ORG_INVITATION_ACCEPT_URL:
        raise OrganizationInvitationError("invitations_disabled", "Organization invitations are not enabled", 503)
    if not _valid_accept_url(settings.ORG_INVITATION_ACCEPT_URL):
        raise OrganizationInvitationError(
            "invitation_configuration",
            "Invitation acceptance URL must use a public HTTPS hostname",
            503,
        )
    normalized_email = email.strip().lower()
    if "@" not in normalized_email or len(normalized_email) > 255 or "\n" in normalized_email or "\r" in normalized_email:
        raise OrganizationInvitationError("invalid_email", "Enter a valid invitation email address", 422)
    if not (60 <= settings.ORG_INVITATION_TTL_SECONDS <= 2_592_000):
        raise OrganizationInvitationError("invitation_configuration", "Invitation expiration is misconfigured", 503)
    existing_user = db.query(User).filter(User.email == normalized_email).first()
    if existing_user and db.query(OrganizationMembership.id).filter(
        OrganizationMembership.organization_id == organization.id,
        OrganizationMembership.user_id == existing_user.id,
        OrganizationMembership.status == "active",
    ).first():
        raise OrganizationInvitationError("already_member", "This identity is already an active organization member", 409)
    if not role_names:
        role_names = [org_service.ORG_MEMBER_ROLE]
    # The legacy membership-invite operation lazily ensured this base role.
    # New invitation creation must do the same before validating the catalog,
    # otherwise a fresh organization cannot issue its first invite.
    role_service.get_or_create_role(db, org_service.ORG_MEMBER_ROLE, [])
    if len(role_names) > 8 or len(set(role_names)) != len(role_names):
        raise OrganizationInvitationError("invalid_roles", "Invitation roles are invalid", 422)
    try:
        roles = role_service.resolve_roles_for_org(
            db, role_names, organization.id, caller_is_platform_admin,
            actor_user_id=actor.id,
        )
    except ValueError as exc:
        raise OrganizationInvitationError("invalid_roles", str(exc), 403) from None

    now = datetime.utcnow()
    key = _active_key(organization.id, normalized_email)
    existing = db.query(OrganizationInvitation).filter(
        OrganizationInvitation.active_key == key,
        OrganizationInvitation.status == "pending",
    ).with_for_update().first()
    if existing and existing.expires_at > now:
        raise OrganizationInvitationError("invitation_exists", "A pending invitation already exists for this email", 409)
    if existing:
        _set_expired(db, existing, actor_user_id=actor.id)

    token = secrets.token_urlsafe(32)
    invitation = OrganizationInvitation(
        organization_id=organization.id,
        invited_by_user_id=actor.id,
        inviter_is_platform_admin=caller_is_platform_admin,
        invited_email=normalized_email,
        role_names=[role.name for role in roles],
        token_hash=_token_hash(token),
        active_key=key,
        status="pending",
        created_at=now,
        expires_at=now + timedelta(seconds=settings.ORG_INVITATION_TTL_SECONDS),
    )
    db.add(invitation)
    try:
        db.flush()
        accept_url = settings.ORG_INVITATION_ACCEPT_URL.split("#", 1)[0] + "#token=" + token
        email_delivery_service.send_organization_invitation(
            normalized_email, organization_name=organization.name,
            roles=invitation.role_names, accept_url=accept_url,
        )
        _audit(
            db, AuditEventType.ORG_INVITATION_CREATED, invitation,
            actor_user_id=actor.id,
            after_state={"status": "pending", "roles": invitation.role_names, "expires_at": invitation.expires_at.isoformat()},
        )
        db.commit()
        db.refresh(invitation)
        return invitation
    except email_delivery_service.EmailDeliveryError:
        db.rollback()
        raise OrganizationInvitationError("invitation_delivery_failed", "Invitation delivery failed; no invitation was created", 503) from None
    except IntegrityError:
        db.rollback()
        raise OrganizationInvitationError("invitation_exists", "A pending invitation already exists for this email", 409) from None
    except Exception:
        db.rollback()
        raise


def list_invitations(db: Session, organization_id: int, actor_user_id: int) -> list[dict]:
    rows = db.query(OrganizationInvitation).filter(
        OrganizationInvitation.organization_id == organization_id,
        OrganizationInvitation.status == "pending",
    ).with_for_update().all()
    changed = False
    for row in rows:
        if row.expires_at <= datetime.utcnow():
            _set_expired(db, row, actor_user_id=actor_user_id)
            changed = True
    if changed:
        db.commit()
    return [
        _safe_view(row)
        for row in db.query(OrganizationInvitation)
        .filter(OrganizationInvitation.organization_id == organization_id)
        .order_by(OrganizationInvitation.created_at.desc())
        .limit(100)
        .all()
    ]


def revoke_invitation(db: Session, invitation: OrganizationInvitation, actor: User) -> OrganizationInvitation:
    if invitation.status != "pending":
        raise OrganizationInvitationError("invitation_unavailable", "Only pending invitations can be revoked", 409)
    invitation.status = "revoked"
    invitation.active_key = None
    invitation.revoked_at = datetime.utcnow()
    invitation.revoked_by_user_id = actor.id
    _audit(
        db, AuditEventType.ORG_INVITATION_REVOKED, invitation,
        actor_user_id=actor.id, before_state={"status": "pending"}, after_state={"status": "revoked"},
    )
    db.commit()
    db.refresh(invitation)
    return invitation


def preview_invitation(db: Session, token: str) -> dict:
    invitation = _pending(db, token)
    result = _safe_view(invitation)
    result["existing_user"] = db.query(User.id).filter(
        User.email == invitation.invited_email,
        User.status == "active",
    ).first() is not None
    result["mfa_required"] = _policy_requires_mfa(db, invitation.organization_id)
    return result


def start_invitation_mfa(db: Session, token: str) -> dict:
    invitation = _pending(db, token, lock=True)
    if not _policy_requires_mfa(db, invitation.organization_id):
        raise OrganizationInvitationError("mfa_not_required", "This invitation does not require organization MFA", 409)
    if not crypto.is_configured():
        raise OrganizationInvitationError("mfa_unavailable", "MFA setup is unavailable", 503)
    if not invitation.mfa_secret_encrypted:
        secret = mfa_service.generate_totp_secret()
        invitation.mfa_secret_encrypted = crypto.encrypt(secret)
        invitation.mfa_setup_at = datetime.utcnow()
        db.commit()
    else:
        secret = crypto.decrypt(invitation.mfa_secret_encrypted)
    return {
        "secret": secret,
        "otpauth_uri": mfa_service.generate_provisioning_uri(secret, invitation.invited_email),
    }


def _activate_membership(db: Session, invitation: OrganizationInvitation, user: User, now: datetime) -> OrganizationMembership:
    existing = db.query(OrganizationMembership).filter(
        OrganizationMembership.organization_id == invitation.organization_id,
        OrganizationMembership.user_id == user.id,
    ).with_for_update().first()
    if existing and existing.status == "active":
        raise OrganizationInvitationError("membership_exists", "This identity is already an active organization member", 409)

    roles = role_service.resolve_roles_for_org(
        db, list(invitation.role_names or [org_service.ORG_MEMBER_ROLE]),
        invitation.organization_id, caller_is_platform_admin=invitation.inviter_is_platform_admin,
        actor_user_id=invitation.invited_by_user_id, target_user_id=user.id,
    )
    membership = existing or OrganizationMembership(
        organization_id=invitation.organization_id,
        user_id=user.id,
        invited_by_user_id=invitation.invited_by_user_id,
    )
    membership.status = "active"
    membership.joined_at = now
    membership.roles = roles
    db.add(membership)
    db.flush()
    return membership


def _activate_invitation(db: Session, invitation: OrganizationInvitation, user: User, now: datetime) -> OrganizationMembership:
    membership = _activate_membership(db, invitation, user, now)
    invitation.status = "accepted"
    invitation.active_key = None
    invitation.accepted_at = now
    invitation.accepted_user_id = user.id
    invitation.mfa_secret_encrypted = None
    _audit(
        db, AuditEventType.ORG_INVITATION_ACCEPTED, invitation,
        actor_user_id=user.id, target_user_id=user.id,
        before_state={"status": "pending"}, after_state={"status": "accepted", "roles": list(invitation.role_names or [])},
        metadata={"email_verified_by_invitation": True},
    )
    _audit(
        db, AuditEventType.ORG_MEMBERSHIP_CHANGED, invitation,
        actor_user_id=user.id, target_user_id=user.id,
        after_state={"status": membership.status, "roles": list(invitation.role_names or [])},
        metadata={"reason": "invitation_accepted"},
    )
    return membership


def _accepted_new_user_retry(db: Session, digest: str, password: str) -> dict | None:
    """Return the original result after a concurrent same-invitation accept.

    The invitation row lock serializes this path on MySQL. The unique user
    email and invitation token constraints remain the final guards on engines
    that do not implement SELECT FOR UPDATE (including the isolated SQLite
    test backend).
    """
    consumed = db.query(OrganizationInvitation).filter(
        OrganizationInvitation.token_hash == digest,
        OrganizationInvitation.status == "accepted",
    ).first()
    if consumed and consumed.accepted_user is not None and verify_password(password, consumed.accepted_user.hashed_password):
        return {"status": "accepted", "user_id": consumed.accepted_user_id, "organization_id": consumed.organization_id}
    return None


def accept_new_user(db: Session, *, token: str, password: str, totp_code: str | None = None) -> dict:
    # An accepted token can be retried only by proving the same account
    # password; this makes network retries safe without reactivating the
    # invitation or creating a second membership.
    digest = _token_hash(token) if token and len(token) <= 256 else ""
    retry_result = _accepted_new_user_retry(db, digest, password)
    if retry_result:
        return retry_result
    try:
        invitation = _pending(db, token, lock=True)
    except OrganizationInvitationError as exc:
        if exc.status_code == 410:
            retry_result = _accepted_new_user_retry(db, digest, password)
            if retry_result:
                return retry_result
        raise
    if db.query(User.id).filter(User.email == invitation.invited_email).first():
        raise OrganizationInvitationError("existing_account", "Sign in with the invited account to accept this invitation", 409)
    try:
        validate_new_password(password, email=invitation.invited_email)
    except PasswordPolicyError as exc:
        raise OrganizationInvitationError("password_policy", str(exc), 400) from None

    needs_mfa = _policy_requires_mfa(db, invitation.organization_id)
    secret = None
    if needs_mfa:
        if not invitation.mfa_secret_encrypted or not totp_code:
            raise OrganizationInvitationError("mfa_setup_required", "Complete organization MFA setup before accepting this invitation", 403)
        secret = crypto.decrypt(invitation.mfa_secret_encrypted)
        if not mfa_service.verify_totp_code(secret, totp_code):
            invitation.mfa_attempts += 1
            _audit(
                db, AuditEventType.ORG_INVITATION_DENIED, invitation,
                metadata={"reason": "mfa_verification_failed"},
            )
            if invitation.mfa_attempts >= settings.ORG_INVITATION_MAX_ACCEPT_ATTEMPTS:
                invitation.status = "revoked"
                invitation.active_key = None
                invitation.revoked_at = datetime.utcnow()
            db.commit()
            raise OrganizationInvitationError("mfa_invalid", "Invalid MFA code", 400)

    now = datetime.utcnow()
    user = User(email=invitation.invited_email, hashed_password=hash_password(password), status="active", created_at=now)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        retry_result = _accepted_new_user_retry(db, digest, password)
        if retry_result:
            return retry_result
        raise OrganizationInvitationError("invitation_unavailable", "Invitation was already accepted or is unavailable", 409) from None
    role_service.assign_default_role(db, user)
    if needs_mfa and secret is not None:
        user.mfa_enabled = True
        user.mfa_status = "enabled"
        user.mfa_primary_method = "totp"
        user.mfa_enabled_at = now
        user.mfa_last_verified_at = now
        device = MFADevice(
            user_id=user.id, device_type="totp", label="Invitation setup",
            encrypted_secret=invitation.mfa_secret_encrypted,
            created_at=now, verified_at=now,
        )
        db.add(device)
        db.flush()
        audit_service.log_event(
            db, AuditEventType.MFA_DEVICE_ADDED,
            actor_user_id=user.id, target_user_id=user.id,
            resource_type="mfa_device", resource_id=device.id,
            after_state={"device_type": "totp", "verified": True},
            metadata={"enrollment": "organization_invitation"}, commit=False,
        )
        audit_service.log_event(
            db, AuditEventType.MFA_ENABLED,
            actor_user_id=user.id, target_user_id=user.id,
            resource_type="user", resource_id=user.id,
            after_state={"mfa_enabled": True, "mfa_primary_method": "totp"},
            metadata={"enrollment": "organization_invitation"}, commit=False,
        )
    try:
        _activate_invitation(db, invitation, user, now)
        db.commit()
    except IntegrityError:
        db.rollback()
        retry_result = _accepted_new_user_retry(db, digest, password)
        if retry_result:
            return retry_result
        raise OrganizationInvitationError("invitation_unavailable", "Invitation was already accepted or is unavailable", 409) from None
    return {"status": "accepted", "user_id": user.id, "organization_id": invitation.organization_id}


def accept_existing_user(db: Session, *, token: str, user: User, totp_code: str | None = None) -> dict:
    # Idempotent retry after a successful commit: the consumed token is never
    # reactivated and the response remains limited to the bearer invitee.
    digest = _token_hash(token) if token and len(token) <= 256 else ""
    consumed = db.query(OrganizationInvitation).filter(
        OrganizationInvitation.token_hash == digest,
        OrganizationInvitation.status == "accepted",
        OrganizationInvitation.accepted_user_id == user.id,
        OrganizationInvitation.invited_email == user.email.strip().lower(),
    ).first()
    if consumed:
        return {"status": "accepted", "user_id": user.id, "organization_id": consumed.organization_id}
    try:
        invitation = _pending(db, token, lock=True)
    except OrganizationInvitationError as exc:
        if exc.status_code == 410:
            consumed = db.query(OrganizationInvitation).filter(
                OrganizationInvitation.token_hash == digest,
                OrganizationInvitation.status == "accepted",
                OrganizationInvitation.accepted_user_id == user.id,
                OrganizationInvitation.invited_email == user.email.strip().lower(),
            ).first()
            if consumed:
                return {"status": "accepted", "user_id": user.id, "organization_id": consumed.organization_id}
        raise
    if user.status != "active" or user.email.strip().lower() != invitation.invited_email:
        _audit(db, AuditEventType.ORG_INVITATION_DENIED, invitation, actor_user_id=user.id, metadata={"reason": "identity_mismatch"})
        db.commit()
        raise OrganizationInvitationError("identity_mismatch", "Invitation does not match the authenticated identity", 403)
    if _policy_requires_mfa(db, invitation.organization_id):
        if not user.mfa_enabled:
            raise OrganizationInvitationError("mfa_enrollment_required", "Enroll in MFA before accepting this organization invitation", 403)
        if not mfa_service.verify_user_totp_step_up(db, user.id, totp_code or ""):
            invitation.mfa_attempts += 1
            _audit(db, AuditEventType.ORG_INVITATION_DENIED, invitation, actor_user_id=user.id, metadata={"reason": "mfa_step_up_failed"})
            if invitation.mfa_attempts >= settings.ORG_INVITATION_MAX_ACCEPT_ATTEMPTS:
                invitation.status = "revoked"
                invitation.active_key = None
                invitation.revoked_at = datetime.utcnow()
            db.commit()
            raise OrganizationInvitationError("mfa_invalid", "A valid authenticator code is required", 400)
        # Claiming a TOTP step is intentionally a durable commit in the
        # existing anti-replay service. Re-lock and revalidate the invite
        # afterwards because that commit releases the initial row lock.
        invitation = _pending(db, token, lock=True)
    now = datetime.utcnow()
    membership = _activate_invitation(db, invitation, user, now)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise OrganizationInvitationError("invitation_unavailable", "Invitation was already accepted or is unavailable", 409) from None
    return {"status": "accepted", "user_id": user.id, "organization_id": membership.organization_id}
