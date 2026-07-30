import json
import os
from datetime import datetime

import redis as _redis_sync
from fastapi import APIRouter, Depends, HTTPException
from prometheus_client import Counter
from sqlalchemy.orm import Session

JWT_AUTH_TOTAL = Counter(
    "jwt_auth_total",
    "JWT authentication attempts",
    ["endpoint", "result"],
)

from app.db.session import get_db
from app.db.models import User, RefreshToken, RevokedToken
from app.schemas.auth import LoginRequest, RefreshRequest, LogoutRequest
from app.core.security import hash_password
from app.core.jwt import decode_token, create_access_token
from app.services.auth_service import (
    authenticate_user,
    generate_tokens,
    revoke_token,
    validate_refresh_token,
)
from app.services.role_service import assign_default_role

router = APIRouter(prefix="/auth", tags=["auth"])

_pub = _redis_sync.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379"),
    decode_responses=True,
)

_blacklist = _redis_sync.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379"),
    decode_responses=True,
)

ACCESS_TOKEN_TTL = 15 * 60  # seconds — matches jwt.py


def _blacklist_access_token(access_token: str) -> None:
    """Store access token jti in Redis blacklist with remaining-lifetime TTL."""
    try:
        payload = decode_token(access_token)
        jti = payload.get("jti")
        if jti:
            exp = payload.get("exp", 0)
            now = int(datetime.utcnow().timestamp())
            ttl = max(exp - now, 1)
            _blacklist.setex(f"blacklist:jti:{jti}", ttl, "1")
    except Exception:
        pass  # fail open — never block logout


def _publish_invalidation(user_id: str, token: str = ""):
    """Broadcast cache-invalidation event on the policy:invalidate channel."""
    try:
        _pub.publish(
            "policy:invalidate",
            json.dumps({"user_id": str(user_id), "token": token}),
        )
    except Exception:
        pass


# ---------------- REGISTER ----------------
@router.post("/register")
def register(req: LoginRequest, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == req.email).first()
    if existing:
        raise HTTPException(400, "User already exists")

    user = User(
        email=req.email,
        hashed_password=hash_password(req.password),
        status="active",
    )
    db.add(user)
    db.flush()
    assign_default_role(db, user)
    db.commit()
    return {"message": "User created"}


# ---------------- LOGIN ----------------
@router.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = authenticate_user(db, req.email, req.password)
    if not user:
        JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="failure").inc()
        raise HTTPException(401, "Invalid credentials")

    access, refresh = generate_tokens(db, user)
    JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="success").inc()
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }


# ---------------- REFRESH ----------------
@router.post("/refresh")
def refresh(req: RefreshRequest, db: Session = Depends(get_db)):
    db_token = validate_refresh_token(db, req.refresh_token)
    if not db_token:
        raise HTTPException(401, "Invalid refresh token")

    payload = decode_token(req.refresh_token)
    new_access = create_access_token(payload)
    return {
        "access_token": new_access,
        "refresh_token": req.refresh_token,
    }


# ---------------- LOGOUT ----------------
@router.post("/logout")
def logout(req: LogoutRequest, db: Session = Depends(get_db)):
    revoke_token(db, req.refresh_token)

    if req.access_token:
        _blacklist_access_token(req.access_token)

    try:
        payload = decode_token(req.refresh_token)
        _publish_invalidation(
            user_id=str(payload.get("sub", "")),
            token=req.refresh_token,
        )
    except Exception:
        pass

    return {"message": "Logged out"}


# ---------------- VALIDATE ----------------
@router.post("/validate")
def validate_token(req: dict, db: Session = Depends(get_db)):
    token = req.get("token")

    try:
        payload = decode_token(token)
        jti = payload.get("jti")

        # Check Redis blacklist first (fast path — access token revocation)
        if jti and _blacklist.exists(f"blacklist:jti:{jti}"):
            return {"valid": False}

        # Check DB revoked tokens (refresh token revocation)
        revoked = db.query(RevokedToken).filter(
            RevokedToken.token_jti == jti
        ).first()
        if revoked:
            return {"valid": False}

        user = db.query(User).filter(User.id == payload["sub"]).first()
        if not user or user.status != "active":
            return {"valid": False}

        return {
            "valid": True,
            "user_id": user.id,
            "email": user.email,
            "roles": payload.get("roles", []),
            "permissions": payload.get("permissions", []),
        }
    except Exception:
        return {"valid": False}
