"""Persistent, challenge-bound email OTP issuance and verification."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta

from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import decode_token
from app.db.models import MFAEmailOTP, RevokedToken, User
from app.services import audit_service, email_delivery_service
from app.services.audit_service import AuditEventType


class EmailMFAUnavailableError(RuntimeError):
    pass


class EmailMFAChallengeError(ValueError):
    pass


class EmailMFAResendLimitedError(Exception):
    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, retry_after_seconds)
        super().__init__("Email verification code cannot be sent yet")


def is_enabled_for(user: User) -> bool:
    """Return whether password login must use the registered email factor.

    The DGX switch is deployment-scoped.  Once enabled it applies to every
    active local-password account, not only a hard-coded administrator, so a
    non-admin Studio account cannot retain the old password-only path.
    """
    return bool(settings.EMAIL_MFA_ENABLED and user.status == "active" and user.email)


def _digest(user_id: int, challenge_jti: str, code: str) -> str:
    if not settings.EMAIL_MFA_OTP_PEPPER:
        raise EmailMFAUnavailableError("Email MFA is unavailable")
    message = f"{user_id}:{challenge_jti}:{code}".encode("utf-8")
    return hmac.new(settings.EMAIL_MFA_OTP_PEPPER.encode("utf-8"), message, hashlib.sha256).hexdigest()


def _challenge_identity(challenge_token: str) -> tuple[int, str]:
    try:
        payload = decode_token(challenge_token)
        user_id = int(payload["user_id"])
        jti = str(payload["jti"])
    except Exception:
        raise EmailMFAChallengeError("Invalid or expired challenge token") from None
    if payload.get("type") != "mfa_challenge" or payload.get("auth_method") != "password" or not jti:
        raise EmailMFAChallengeError("Invalid or expired challenge token")
    return user_id, jti


def issue_code(db: Session, user: User, challenge_token: str, *, resend: bool = False) -> int:
    """Invalidate older codes, deliver a fresh code, and persist only its HMAC."""
    if not is_enabled_for(user):
        raise EmailMFAUnavailableError("Email MFA is unavailable")
    user_id, challenge_jti = _challenge_identity(challenge_token)
    if user_id != user.id or user.status != "active":
        raise EmailMFAChallengeError("Invalid or expired challenge token")
    if db.query(RevokedToken).filter(RevokedToken.token_jti == challenge_jti).first():
        raise EmailMFAChallengeError("Invalid or expired challenge token")

    # Serialize issuance and cooldown/hourly-cap checks across Auth workers.
    # The account row is the existing shared lock point, so no new lock table
    # or process-local assumption is introduced.
    db.query(User.id).filter(User.id == user.id).with_for_update().first()

    now = datetime.utcnow()
    latest = (
        db.query(MFAEmailOTP)
        .filter(MFAEmailOTP.user_id == user.id)
        .order_by(MFAEmailOTP.created_at.desc(), MFAEmailOTP.id.desc())
        .first()
    )
    if resend and latest is not None:
        elapsed = (now - latest.created_at).total_seconds()
        if elapsed < settings.EMAIL_MFA_RESEND_COOLDOWN_SECONDS:
            raise EmailMFAResendLimitedError(settings.EMAIL_MFA_RESEND_COOLDOWN_SECONDS - int(elapsed))

    hour_ago = now - timedelta(hours=1)
    sends = db.query(MFAEmailOTP).filter(
        MFAEmailOTP.user_id == user.id,
        MFAEmailOTP.created_at >= hour_ago,
    ).count()
    if sends >= settings.EMAIL_MFA_MAX_SENDS_PER_HOUR:
        retry = 3600
        oldest = (
            db.query(MFAEmailOTP)
            .filter(MFAEmailOTP.user_id == user.id, MFAEmailOTP.created_at >= hour_ago)
            .order_by(MFAEmailOTP.created_at.asc())
            .first()
        )
        if oldest is not None:
            retry = max(1, int((oldest.created_at + timedelta(hours=1) - now).total_seconds()))
        raise EmailMFAResendLimitedError(retry)

    db.query(MFAEmailOTP).filter(
        MFAEmailOTP.user_id == user.id,
        MFAEmailOTP.consumed_at.is_(None),
        MFAEmailOTP.invalidated_at.is_(None),
    ).update({MFAEmailOTP.invalidated_at: now}, synchronize_session=False)

    code = f"{secrets.randbelow(1_000_000):06d}"
    row = MFAEmailOTP(
        user_id=user.id,
        challenge_jti=challenge_jti,
        code_hash=_digest(user.id, challenge_jti, code),
        attempts=0,
        created_at=now,
        expires_at=now + timedelta(seconds=settings.EMAIL_MFA_TTL_SECONDS),
    )
    db.add(row)
    try:
        db.flush()
        email_delivery_service.send_mfa_code(user.email, code, expires_minutes=5)
        audit_service.log_event(
            db,
            AuditEventType.MFA_EMAIL_CODE_RESENT if resend else AuditEventType.MFA_EMAIL_CODE_SENT,
            actor_user_id=user.id,
            target_user_id=user.id,
            resource_type="mfa_email_otp",
            resource_id=row.id,
            metadata={"delivery": "email"},
            commit=False,
        )
        db.commit()
    except Exception:
        db.rollback()
        raise EmailMFAUnavailableError("Email MFA is unavailable") from None
    return settings.EMAIL_MFA_RESEND_COOLDOWN_SECONDS


def resend_code(db: Session, challenge_token: str) -> int:
    user_id, _ = _challenge_identity(challenge_token)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise EmailMFAChallengeError("Invalid or expired challenge token")
    return issue_code(db, user, challenge_token, resend=True)


def verify_code(db: Session, user_id: int, challenge_jti: str, code: str) -> bool:
    """Check and atomically claim one code; every presented code gets at most five tries."""
    row = (
        db.query(MFAEmailOTP)
        .filter(
            MFAEmailOTP.user_id == user_id,
            MFAEmailOTP.challenge_jti == challenge_jti,
            MFAEmailOTP.consumed_at.is_(None),
            MFAEmailOTP.invalidated_at.is_(None),
        )
        .order_by(MFAEmailOTP.created_at.desc(), MFAEmailOTP.id.desc())
        .first()
    )
    now = datetime.utcnow()
    if row is None or row.expires_at <= now or row.attempts >= settings.EMAIL_MFA_MAX_ATTEMPTS:
        return False

    candidate = _digest(user_id, challenge_jti, code)
    if not hmac.compare_digest(row.code_hash, candidate):
        updated = db.query(MFAEmailOTP).filter(
            MFAEmailOTP.id == row.id,
            MFAEmailOTP.consumed_at.is_(None),
            MFAEmailOTP.invalidated_at.is_(None),
            MFAEmailOTP.attempts < settings.EMAIL_MFA_MAX_ATTEMPTS,
        ).update({MFAEmailOTP.attempts: MFAEmailOTP.attempts + 1}, synchronize_session=False)
        if updated:
            db.flush()
            db.refresh(row)
            if row.attempts >= settings.EMAIL_MFA_MAX_ATTEMPTS:
                row.invalidated_at = now
                db.flush()
        return False

    claimed = db.query(MFAEmailOTP).filter(
        MFAEmailOTP.id == row.id,
        MFAEmailOTP.code_hash == candidate,
        MFAEmailOTP.consumed_at.is_(None),
        MFAEmailOTP.invalidated_at.is_(None),
        MFAEmailOTP.expires_at > now,
        MFAEmailOTP.attempts < settings.EMAIL_MFA_MAX_ATTEMPTS,
    ).update({MFAEmailOTP.consumed_at: now}, synchronize_session=False)
    if claimed != 1:
        db.rollback()
        return False
    db.commit()
    return True
