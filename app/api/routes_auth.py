import json
import os
from datetime import datetime

import redis as _redis_sync
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from prometheus_client import Counter
from sqlalchemy.orm import Session

JWT_AUTH_TOTAL = Counter(
    "jwt_auth_total",
    "JWT authentication attempts",
    ["endpoint", "result"],
)

from app.db.session import get_db
from app.db.models import User
from app.schemas.auth import LoginRequest, RefreshRequest, LogoutRequest
from app.core.security import hash_password
from app.core.jwt import decode_token
from app.core import token_revocation
from app.core.token_revocation import assert_token_usable
from app.services.auth_service import (
    REFRESH_TOKEN_TTL_DAYS as _REFRESH_TOKEN_TTL_DAYS,
    MFAEnrollmentRequiredError,
    authenticate_user,
    generate_tokens_or_mfa_challenge,
    revoke_token,
    rotate_refresh_token,
)
from app.services.role_service import assign_default_role
from app.services import org_service, sso_discovery_service

router = APIRouter(prefix="/auth", tags=["auth"])

# ── SSO Phase 2 PR10: browser session cookie ────────────────────────────────
#
# Mirrors the existing refresh_token exactly -- same value, same lifetime --
# in a second, server-set form a browser can carry across first-party
# subdomains without any frontend JS involvement. Does NOT replace the
# existing JSON access_token/refresh_token response (backward compatible:
# every existing API client that only ever read the JSON body is
# unaffected). This is additive to the existing refresh-rotation/
# revocation/logout machinery below, not a new session mechanism -- the
# cookie's value IS the same refresh_token rotate_refresh_token/revoke_token
# already manage; there is no separate session store, no Redis session
# state, no sessions table (PR10 non-goals).
SESSION_COOKIE_NAME = "omnibioai_session"
SESSION_COOKIE_DOMAIN = os.getenv("SESSION_COOKIE_DOMAIN", ".omnibioai.org")
SESSION_COOKIE_MAX_AGE = _REFRESH_TOKEN_TTL_DAYS * 24 * 60 * 60


def _set_session_cookie(response: Response, refresh_token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=refresh_token,
        max_age=SESSION_COOKIE_MAX_AGE,
        path="/",
        domain=SESSION_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _clear_session_cookie(response: Response) -> None:
    response.delete_cookie(
        key=SESSION_COOKIE_NAME,
        path="/",
        domain=SESSION_COOKIE_DOMAIN,
        secure=True,
        httponly=True,
        samesite="lax",
    )

_pub = _redis_sync.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379"),
    decode_responses=True,
)

ACCESS_TOKEN_TTL = 15 * 60  # seconds — matches jwt.py


def _blacklist_access_token(access_token: str) -> None:
    """Store access token jti in Redis blacklist with remaining-lifetime TTL.

    Writes through `token_revocation._blacklist` (qualified attribute
    access, not a local `_blacklist` name) -- PR0.1 made that module the
    canonical owner of this Redis client, since `assert_token_usable` reads
    from the exact same object to enforce revocation in `get_current_user`.
    """
    try:
        payload = decode_token(access_token)
        jti = payload.get("jti")
        if jti:
            exp = payload.get("exp", 0)
            now = int(datetime.utcnow().timestamp())
            ttl = max(exp - now, 1)
            token_revocation._blacklist.setex(f"blacklist:jti:{jti}", ttl, "1")
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
def login(req: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    # Phase 2 PR5: checked before any credential verification at all --
    # authenticate_user (the only caller of verify_password) is never
    # reached for an org that enforces SSO, not just short-circuited
    # after a failed check. domain-based matching (same as GET
    # /auth/sso/discover) is the only signal available here: there is no
    # authenticated identity yet to look up a real membership against.
    enforced_config = sso_discovery_service.find_enforced_org_for_email(db, req.email)
    if enforced_config:
        org = org_service.get_organization(db, enforced_config.organization_id)
        raise HTTPException(
            403,
            detail={
                "reason": "sso_required",
                "org_slug": org.slug,
                "sso_login_url": f"/auth/sso/{org.slug}/login",
            },
        )

    user = authenticate_user(db, req.email, req.password)
    if not user:
        JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="failure").inc()
        raise HTTPException(401, "Invalid credentials")

    # PR11.5.3: single shared MFA decision point, see
    # docs/pr11-mfa-login-challenge-discovery.md SS2. Non-MFA response
    # shape below is byte-identical to before this PR -- backward
    # compatible per that PR's own explicit requirement.
    # PR11.5.5: org-required MFA the user hasn't personally enrolled --
    # same 403 shape the SSO-enforcement check above already uses.
    # Phase 4 PR-A: best-effort client metadata for the new session row --
    # never logged, never returned in this endpoint's own response (see
    # app/services/session_service.py). `request.client` is None in some
    # test-client/ASGI-transport configurations, hence the guard.
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    try:
        result = generate_tokens_or_mfa_challenge(
            db, user, auth_method="password", client_ip=client_ip, user_agent=user_agent,
        )
    except MFAEnrollmentRequiredError:
        raise HTTPException(403, detail={
            "error": "mfa_enrollment_required",
            "message": "Your organization requires MFA enrollment",
        })
    if result["mfa_required"]:
        JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="mfa_required").inc()
        return {
            "mfa_required": True,
            "challenge_token": result["challenge_token"],
            "methods": result["methods"],
        }

    access, refresh = result["access_token"], result["refresh_token"]
    JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="success").inc()
    _set_session_cookie(response, refresh)
    return {
        "access_token": access,
        "refresh_token": refresh,
        "token_type": "bearer",
    }


# ---------------- REFRESH ----------------
@router.post("/refresh")
def refresh(req: RefreshRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    # PR0.2: rotate_refresh_token rebuilds claims from the current database
    # state (not the presented token's own stale payload) and returns a
    # NEW refresh token -- the presented one is single-use from here on.
    # Presenting it again is treated as token-family compromise; see
    # auth_service.rotate_refresh_token / _revoke_family.
    #
    # SSO Phase 2 PR10: the body-supplied token still always wins when
    # present -- existing API clients that only ever send it in the body
    # are completely unaffected. Only falls back to the omnibioai_session
    # cookie when the body omits it, so a browser holding only the cookie
    # (no JS-visible token at all) can still refresh.
    presented_token = req.refresh_token or request.cookies.get(SESSION_COOKIE_NAME)
    if not presented_token:
        raise HTTPException(401, "Invalid refresh token")

    result = rotate_refresh_token(db, presented_token)
    if not result:
        raise HTTPException(401, "Invalid refresh token")

    new_access, new_refresh = result
    _set_session_cookie(response, new_refresh)
    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
    }


# ---------------- LOGOUT ----------------
@router.post("/logout")
def logout(req: LogoutRequest, response: Response, db: Session = Depends(get_db)):
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

    _clear_session_cookie(response)
    return {"message": "Logged out"}


# ---------------- VALIDATE ----------------
@router.post("/validate")
def validate_token(req: dict, db: Session = Depends(get_db)):
    token = req.get("token")

    try:
        payload = decode_token(token)

        # PR0.1: blacklist/revoked_tokens/status checks now live in
        # assert_token_usable (app/core/token_revocation.py), shared with
        # get_current_user, instead of being duplicated here. HTTPException
        # is caught by this function's own broad `except Exception` below
        # and translated into this endpoint's existing {"valid": False}
        # contract -- unlike get_current_user, this route never raises.
        assert_token_usable(payload, db)

        user = db.query(User).filter(User.id == payload["sub"]).first()

        return {
            "valid": True,
            "user_id": user.id,
            "email": user.email,
            "roles": payload.get("roles", []),
            "permissions": payload.get("permissions", []),
            # Phase 1 PR3 -- additive. A token minted before this change
            # has no org_id/org_role/auth_method/token_version claims at
            # all, so these fall back to None/[]/None/1 exactly as they
            # should for a genuinely pre-org-context token, not an error.
            "org_id": payload.get("org_id"),
            "org_role": payload.get("org_role", []),
            "auth_method": payload.get("auth_method"),
            # Phase 2 PR4 -- additive, same graceful-default reasoning as
            # the rest of this block. None for every token minted before
            # this change or by any non-SSO auth_method.
            "idp_org_id": payload.get("idp_org_id"),
            "schema_version": payload.get("token_version", 1),
        }
    except Exception:
        return {"valid": False}
