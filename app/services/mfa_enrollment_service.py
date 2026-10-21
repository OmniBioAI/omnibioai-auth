"""Issue and consume the narrowly scoped pre-authentication MFA capability."""

from datetime import datetime, timedelta
import uuid

from sqlalchemy.orm import Session

from app.core.jwt import create_mfa_enrollment_token
from app.db.models import MFAEnrollmentSession

ENROLLMENT_TOKEN_TTL = timedelta(minutes=10)


def create_enrollment_token(db: Session, user_id: int) -> str:
    now = datetime.utcnow()
    token_jti = str(uuid.uuid4())
    expires_at = now + ENROLLMENT_TOKEN_TTL
    db.add(MFAEnrollmentSession(
        user_id=user_id,
        token_jti=token_jti,
        created_at=now,
        expires_at=expires_at,
    ))
    db.commit()
    return create_mfa_enrollment_token(user_id, token_jti, expires_at)


def get_active_session(
    db: Session,
    *,
    user_id: int,
    token_jti: str,
    lock: bool = False,
) -> MFAEnrollmentSession | None:
    query = db.query(MFAEnrollmentSession).filter(
        MFAEnrollmentSession.user_id == user_id,
        MFAEnrollmentSession.token_jti == token_jti,
        MFAEnrollmentSession.expires_at > datetime.utcnow(),
        MFAEnrollmentSession.consumed_at.is_(None),
    )
    if lock:
        query = query.with_for_update()
    return query.first()


def consume_session(db: Session, session_id: int) -> bool:
    """Atomically consume the enrollment capability after successful TOTP verification."""
    now = datetime.utcnow()
    changed = (
        db.query(MFAEnrollmentSession)
        .filter(
            MFAEnrollmentSession.id == session_id,
            MFAEnrollmentSession.expires_at > now,
            MFAEnrollmentSession.consumed_at.is_(None),
        )
        .update({MFAEnrollmentSession.consumed_at: now}, synchronize_session=False)
    )
    if changed:
        db.commit()
    else:
        db.rollback()
    return changed == 1
