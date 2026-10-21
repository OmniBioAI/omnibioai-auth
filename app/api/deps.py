"""
OmniBioAI app.api.deps.

Purpose:
    Defines get_current_user and require_permission for app.api.deps.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.core.jwt import decode_token
from app.db.models import User
from app.db.session import get_db
from app.services import mfa_enrollment_service

security = HTTPBearer()

def get_current_user(token=Depends(security)):
    try:
        payload = decode_token(token.credentials)
        if payload.get("type") in {"mfa_challenge", "mfa_enrollment"}:
            raise ValueError("restricted token")
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


def get_mfa_enrollment_user(token=Depends(security), db: Session = Depends(get_db)):
    """Accept normal access tokens or the scoped pre-auth enrollment token.

    This dependency is used only by the TOTP start/verify routes. The
    enrollment token has no `sub` claim and must match an active,
    unconsumed server-side session for the user and token jti.
    """
    try:
        payload = decode_token(token.credentials)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

    if payload.get("type") != "mfa_enrollment":
        from app.rbac import get_current_user as get_validated_current_user
        return get_validated_current_user(token, db)

    user_id = payload.get("user_id")
    token_jti = payload.get("jti")
    if payload.get("purpose") != "totp_enrollment" or not user_id or not token_jti:
        raise HTTPException(status_code=401, detail="Invalid token")

    user = db.query(User).filter(User.id == user_id, User.status == "active").first()
    session = mfa_enrollment_service.get_active_session(
        db, user_id=user_id, token_jti=token_jti,
    )
    if user is None or user.mfa_enabled or session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired enrollment token")

    return {
        "sub": str(user.id),
        "email": user.email,
        "mfa_enrollment_only": True,
        "mfa_enrollment_jti": token_jti,
        "mfa_enrollment_session_id": session.id,
    }


def require_permission(permission: str):
    def wrapper(user=Depends(get_current_user)):
        perms = user.get("permissions", [])
        if permission not in perms:
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return wrapper
