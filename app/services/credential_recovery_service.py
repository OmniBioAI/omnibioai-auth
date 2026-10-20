"""Transaction-bound local administrator credential recovery."""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core.password_policy import PasswordPolicyError, validate_new_password
from app.core.recovery_approval import RecoveryApproval
from app.core.security import hash_password, password_verifier_scheme
from app.db.models import AuditEvent, RefreshToken, RevokedToken, User
from app.services import audit_service, auth_service, mfa_service, session_service
from app.services.audit_service import AuditEventType


class CredentialRecoveryError(ValueError):
    """Safe-to-display recovery rejection without identity or credential data."""


def recover_admin_password(
    db: Session,
    *,
    target_user_id: int,
    operator_login: str,
    confirmation: str,
    password: str,
    approval: RecoveryApproval,
) -> dict[str, int | bool]:
    """Recover an existing disabled-password Admin under a signed Owner approval.

    Every write, including session/MFA revocation and the signed audit record,
    shares one transaction. The caller must not log password or approval-file
    contents.
    """
    expected_confirmation = f"RECOVER {approval.target_user_id} {approval.target_email} {approval.ticket_id}"
    if confirmation != expected_confirmation:
        raise CredentialRecoveryError("Target confirmation does not match the approval")
    if (
        approval.target_user_id != target_user_id
        or approval.operator_login != operator_login
        or approval.action != "admin_credential_recovery"
        or approval.expected_credential_state != "disabled_or_unsupported"
    ):
        raise CredentialRecoveryError("Approval does not authorize this recovery")

    try:
        user = (
            db.query(User).filter(User.id == target_user_id).with_for_update().one_or_none()
        )
        if user is None or user.email != approval.target_email or user.status != "active":
            raise CredentialRecoveryError("Approved active Admin identity was not found")
        if not any(role.name == "admin" and role.organization_id is None for role in user.roles):
            raise CredentialRecoveryError("Target is not an existing global Admin")

        approver = db.query(User).filter(User.id == approval.approver_user_id).with_for_update().one_or_none()
        approver_roles = {
            role.name for role in approver.roles if role.organization_id is None
        } if approver is not None else set()
        if (
            approver is None
            or approver.status != "active"
            or approver.id == user.id
            or not {"platform_admin", "admin"}.issubset(approver_roles)
        ):
            raise CredentialRecoveryError("Approval is not from an active Platform Owner")

        approval_claim = f"credential-recovery-approval:{approval.approval_id}"
        if db.query(RevokedToken).filter(RevokedToken.token_jti == approval_claim).first():
            raise CredentialRecoveryError("Approval has already been used")
        # token_jti is already uniquely constrained in every supported Auth
        # database. A namespaced claim gives the approval a cross-worker,
        # cross-process single-use gate without adding a schema migration.
        # The claim commits atomically with the recovery and rolls back with it.
        db.add(RevokedToken(token_jti=approval_claim))
        db.flush()

        if password_verifier_scheme(user.hashed_password) is not None:
            raise CredentialRecoveryError("Target already has a supported password credential")

        try:
            validate_new_password(password, user.email)
        except PasswordPolicyError:
            raise CredentialRecoveryError(str(PasswordPolicyError("policy"))) from None
        password_hash = hash_password(password)
        old_roles = tuple(sorted((role.id, role.name, role.organization_id) for role in user.roles))
        old_email = user.email
        old_status = user.status
        mfa_was_enabled = bool(user.mfa_enabled)
        mfa_was_reset = mfa_was_enabled and approval.allow_mfa_reset
        old_verifier = user.hashed_password
        updated = db.query(User).filter(
            User.id == target_user_id,
            User.email == approval.target_email,
            User.status == "active",
            User.hashed_password == old_verifier,
        ).update({"hashed_password": password_hash}, synchronize_session=False)
        if updated != 1:
            raise CredentialRecoveryError("Credential state changed during recovery")
        db.expire(user, ["hashed_password"])
        db.flush()

        if mfa_was_reset:
            mfa_service.reset_user_mfa(db, user.id, actor_user_id=approver.id, commit=False)

        sessions_revoked = auth_service.revoke_all_sessions_for_user(
            db,
            user.id,
            session_service.REASON_CREDENTIAL_RECOVERY,
            actor_user_id=approver.id,
            commit=False,
        )
        # Also revoke legacy refresh rows without a UserSession backfill.
        db.query(RefreshToken).filter(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked.is_(False),
        ).update({"revoked": True}, synchronize_session=False)

        current_roles = tuple(sorted((role.id, role.name, role.organization_id) for role in user.roles))
        if (user.id, user.email, user.status, current_roles) != (
            target_user_id, old_email, old_status, old_roles
        ):
            raise CredentialRecoveryError("Identity state changed during recovery")

        audit_service.log_event(
            db,
            AuditEventType.CREDENTIAL_RECOVERY_COMPLETED,
            actor_user_id=approver.id,
            target_user_id=user.id,
            resource_type="credential_recovery_approval",
            resource_id=approval.approval_id,
            before_state={"credential_state": "disabled_or_unsupported"},
            after_state={"credential_scheme": "bcrypt_sha256", "mfa_reset": mfa_was_reset},
            metadata={
                "ticket_id": approval.ticket_id,
                "identity_verification_ref": approval.identity_verification_ref,
                "operator_login": operator_login,
                "approver_user_id": approver.id,
                "sessions_revoked": sessions_revoked,
                "approval_id": approval.approval_id,
            },
            commit=False,
        )
        db.commit()
        return {"user_id": user.id, "sessions_revoked": sessions_revoked, "mfa_reset": mfa_was_reset}
    except Exception:
        db.rollback()
        raise


def recover_admin_mfa(
    db: Session,
    *,
    target_user_id: int,
    operator_login: str,
    confirmation: str,
    approval: RecoveryApproval,
) -> dict[str, int | bool]:
    """Reset only an unknown Admin authenticator under a distinct signed approval."""
    expected_confirmation = f"RECOVER-MFA {approval.target_user_id} {approval.target_email} {approval.ticket_id}"
    if confirmation != expected_confirmation:
        raise CredentialRecoveryError("Target confirmation does not match the approval")
    if (
        approval.target_user_id != target_user_id
        or approval.operator_login != operator_login
        or approval.action != "admin_mfa_recovery"
        or approval.expected_credential_state != "unknown_authenticator_enrollment"
        or not approval.allow_mfa_reset
    ):
        raise CredentialRecoveryError("Approval does not authorize MFA recovery")

    try:
        user = db.query(User).filter(User.id == target_user_id).with_for_update().one_or_none()
        if user is None or user.email != approval.target_email or user.status != "active":
            raise CredentialRecoveryError("Approved active Admin identity was not found")
        if not any(role.name == "admin" and role.organization_id is None for role in user.roles):
            raise CredentialRecoveryError("Target is not an existing global Admin")
        if not user.mfa_enabled:
            raise CredentialRecoveryError("Target has no active MFA enrollment to replace")

        approver = db.query(User).filter(User.id == approval.approver_user_id).with_for_update().one_or_none()
        approver_roles = {
            role.name for role in approver.roles if role.organization_id is None
        } if approver is not None else set()
        if (
            approver is None
            or approver.status != "active"
            or approver.id == user.id
            or not {"platform_admin", "admin"}.issubset(approver_roles)
        ):
            raise CredentialRecoveryError("Approval is not from an active Platform Owner")

        approval_claim = f"mfa-recovery-approval:{approval.approval_id}"
        if db.query(RevokedToken).filter(RevokedToken.token_jti == approval_claim).first():
            raise CredentialRecoveryError("Approval has already been used")
        db.add(RevokedToken(token_jti=approval_claim))
        db.flush()

        mfa_service.reset_user_mfa(db, user.id, actor_user_id=approver.id, commit=False)
        sessions_revoked = auth_service.revoke_all_sessions_for_user(
            db,
            user.id,
            session_service.REASON_CREDENTIAL_RECOVERY,
            actor_user_id=approver.id,
            commit=False,
        )
        db.query(RefreshToken).filter(
            RefreshToken.user_id == user.id,
            RefreshToken.revoked.is_(False),
        ).update({"revoked": True}, synchronize_session=False)
        audit_service.log_event(
            db,
            AuditEventType.MFA_RECOVERY_COMPLETED,
            actor_user_id=approver.id,
            target_user_id=user.id,
            resource_type="mfa_recovery_approval",
            resource_id=approval.approval_id,
            before_state={"mfa_state": "enabled_unknown_enrollment"},
            after_state={"mfa_state": "reset_for_reenrollment"},
            metadata={
                "ticket_id": approval.ticket_id,
                "identity_verification_ref": approval.identity_verification_ref,
                "operator_login": operator_login,
                "approver_user_id": approver.id,
                "sessions_revoked": sessions_revoked,
                "approval_id": approval.approval_id,
            },
            commit=False,
        )
        db.commit()
        return {"user_id": user.id, "sessions_revoked": sessions_revoked, "mfa_reset": True}
    except Exception:
        db.rollback()
        raise
