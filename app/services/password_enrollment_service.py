"""Local operator-only enrollment of a password for an existing user.

This module deliberately has no HTTP route. The management CLI is the only
entry point; it takes the secret from hidden interactive input and delegates
all persistence here so the credential update, session revocation and signed
audit event commit or roll back together.
"""
from dataclasses import dataclass

from sqlalchemy import func

from app.core.password_policy import PasswordPolicyError, validate_new_password
from app.core.security import hash_password
from app.db.models import MFADevice, OAuthAccount, RefreshToken, User, UserSession
from app.services import audit_service, session_service


class PasswordEnrollmentError(ValueError):
    """A safe-to-display enrollment failure; never includes password data."""


@dataclass(frozen=True)
class UserAuthProfile:
    user_id: int
    email: str
    status: str
    password_credential_present: bool
    oauth_account_count: int
    mfa_enabled: bool
    mfa_device_count: int


@dataclass(frozen=True)
class PasswordEnrollmentResult:
    user_id: int
    email: str
    revoked_refresh_tokens: int
    revoked_sessions: int


def _resolve_user(db, identity: str) -> User:
    normalized = identity.strip().lower()
    if not normalized:
        raise PasswordEnrollmentError("Identity is required")
    matches = (
        db.query(User)
        .filter(func.lower(func.trim(User.email)) == normalized)
        .all()
    )
    if not matches:
        raise PasswordEnrollmentError("No user matches that identity")
    if len(matches) != 1:
        raise PasswordEnrollmentError("Identity is ambiguous; no changes made")
    user = matches[0]
    if user.status != "active":
        raise PasswordEnrollmentError("Target user is not active; no changes made")
    return user


def inspect_user_auth_profile(db, identity: str) -> UserAuthProfile:
    """Return safe credential-method metadata, never credential contents."""
    user = _resolve_user(db, identity)
    oauth_count = db.query(OAuthAccount).filter(OAuthAccount.user_id == user.id).count()
    mfa_count = db.query(MFADevice).filter(
        MFADevice.user_id == user.id,
        MFADevice.disabled_at.is_(None),
    ).count()
    return UserAuthProfile(
        user_id=user.id,
        email=user.email,
        status=user.status,
        password_credential_present=bool(user.hashed_password),
        oauth_account_count=oauth_count,
        mfa_enabled=bool(user.mfa_enabled),
        mfa_device_count=mfa_count,
    )


def enroll_existing_user_password(
    db,
    confirmed_profile: UserAuthProfile,
    password: str,
    confirmation: str,
) -> PasswordEnrollmentResult:
    """Replace a local password for the exact inspected user ID/email pair.

    Existing OAuth and MFA records are left unchanged. All refresh-token rows
    and session families for this user are revoked in the same transaction.
    `confirmed_profile` is returned by inspect_user_auth_profile;
    it is never looked up again. The row is selected by stable ID under a
    database row lock, then its canonical email/status are revalidated.
    """
    if password != confirmation:
        raise PasswordEnrollmentError("Password confirmation does not match")

    try:
        # MySQL/InnoDB honors FOR UPDATE here. SQLite ignores it, while still
        # running this operation within the same transaction used by tests.
        user = (
            db.query(User)
            .filter(User.id == confirmed_profile.user_id)
            .with_for_update()
            .one_or_none()
        )
        if user is None:
            raise PasswordEnrollmentError("Confirmed user no longer exists; no changes made")
        if user.email != confirmed_profile.email:
            raise PasswordEnrollmentError("Confirmed identity changed; no changes made")
        if user.status != "active":
            raise PasswordEnrollmentError("Target user is not active; no changes made")

        # Reuse exactly the registration policy and hasher.
        validate_new_password(password, email=user.email)
        new_hash = hash_password(password)
        user.hashed_password = new_hash

        refresh_tokens = db.query(RefreshToken).filter(RefreshToken.user_id == user.id).all()
        revoked_token_count = 0
        family_ids = set()
        for token in refresh_tokens:
            if not token.revoked:
                token.revoked = True
                revoked_token_count += 1
            if token.family_id:
                family_ids.add(token.family_id)

        sessions = db.query(UserSession).filter(UserSession.user_id == user.id).all()
        revoked_session_count = sum(
            1 for session in sessions if session.status != session_service.STATUS_REVOKED
        )
        # Include session-only families (e.g. rows retained after token
        # cleanup) as well as families found through refresh-token history.
        family_ids.update(session.session_id for session in sessions if session.session_id)
        for family_id in family_ids:
            session_service.revoke(db, family_id, session_service.REASON_PASSWORD_CHANGED)
        audit_service.log_event(
            db,
            audit_service.AuditEventType.ADMIN_PASSWORD_CREDENTIAL_CHANGED,
            target_user_id=user.id,
            resource_type="user",
            resource_id=user.id,
            metadata={
                "origin": "local_management_command",
                "revoked_refresh_token_count": revoked_token_count,
                "revoked_session_count": revoked_session_count,
            },
            commit=False,
        )
        target_user_id = user.id
        target_email = user.email
        db.commit()
    except PasswordEnrollmentError:
        db.rollback()
        raise
    except PasswordPolicyError as exc:
        db.rollback()
        raise PasswordEnrollmentError(str(exc)) from None
    except Exception:
        db.rollback()
        # Do not propagate lower-level exception strings: they may contain
        # SQL parameters or driver context. The secret is never part of those
        # parameters except as a one-way hash, but fail closed regardless.
        raise PasswordEnrollmentError("Password enrollment failed; no changes committed") from None

    return PasswordEnrollmentResult(
        user_id=target_user_id,
        email=target_email,
        revoked_refresh_tokens=revoked_token_count,
        revoked_sessions=revoked_session_count,
    )
