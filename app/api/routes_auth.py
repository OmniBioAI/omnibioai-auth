import json
import os

import redis as _redis_sync
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import JSONResponse
from prometheus_client import Counter
from sqlalchemy.orm import Session

JWT_AUTH_TOTAL = Counter(
    "jwt_auth_total",
    "JWT authentication attempts",
    ["endpoint", "result"],
)

from app.db.session import get_db
from app.db.models import Team, User
from app.schemas.auth import LoginRequest, RefreshRequest, LogoutRequest, SwitchTeamRequest
from app.core.security import hash_password
from app.core.password_policy import PasswordPolicyError, validate_new_password
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
from app.services import login_throttle_service, org_service, sso_discovery_service, team_service

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

    # HIPAA Phase 1 PR2: the only local-password-creation endpoint this
    # service has -- see app/core/password_policy.py's module docstring
    # for why this is the one and only call site. Checked before the
    # password is hashed/stored; `PasswordPolicyError.__str__` is always
    # the same generic message regardless of which specific rule failed
    # (length/common-password/compromised), by design -- see that
    # exception's own docstring.
    try:
        validate_new_password(req.password, email=req.email)
    except PasswordPolicyError as e:
        raise HTTPException(400, str(e))

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
    # Phase 4 PR-A: best-effort client metadata -- never logged, never
    # returned in this endpoint's own response (see
    # app/services/session_service.py). `request.client` is None in some
    # test-client/ASGI-transport configurations, hence the guard.
    #
    # HIPAA Phase 1 PR1: computed before the SSO-enforcement check below
    # (moved up from after `authenticate_user`, where it used to live) --
    # the throttle peek a few lines down needs it, and this value doesn't
    # change meaning by being read earlier.
    client_ip = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")

    # Phase 2 PR5: checked before any credential verification at all --
    # authenticate_user (the only caller of verify_password) is never
    # reached for an org that enforces SSO, not just short-circuited
    # after a failed check. domain-based matching (same as GET
    # /auth/sso/discover) is the only signal available here: there is no
    # authenticated identity yet to look up a real membership against.
    #
    # HIPAA Phase 1 PR1: also unaffected by login throttling -- SSO-
    # enforced orgs never reach authenticate_user, so they never record
    # against or get blocked by the local-password rate limiter. Their
    # own IdP is the correct place for brute-force protection.
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

    # HIPAA Phase 1 PR1: peek-only, no DB/bcrypt work yet. Keyed off a
    # hash of whatever email string was submitted, real account or not --
    # see login_throttle_service.py's module docstring for why this
    # doesn't leak account existence. 429/Retry-After is deliberately a
    # different status than the 401 below (bad credentials), which is the
    # one place this endpoint's response shape changes for this PR;
    # neither response reveals anything about the submitted email that
    # the other doesn't.
    throttle = login_throttle_service.check_throttled(req.email, client_ip)
    if throttle.locked:
        JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="throttled").inc()
        return JSONResponse(
            status_code=429,
            content={"error": "too_many_attempts", "message": "Too many failed login attempts. Try again later."},
            headers={"Retry-After": str(throttle.retry_after_seconds)},
        )

    user = authenticate_user(db, req.email, req.password, client_ip=client_ip)
    if not user:
        JWT_AUTH_TOTAL.labels(endpoint="/auth/login", result="failure").inc()
        raise HTTPException(401, "Invalid credentials")

    # PR11.5.3: single shared MFA decision point, see
    # docs/pr11-mfa-login-challenge-discovery.md SS2. Non-MFA response
    # shape below is byte-identical to before this PR -- backward
    # compatible per that PR's own explicit requirement.
    # PR11.5.5: org-required MFA the user hasn't personally enrolled --
    # same 403 shape the SSO-enforcement check above already uses.

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


# ---------------- SWITCH TEAM ----------------
# Multi-user Workspaces (Studio v0.8.0), Mode B: the "switch workspace"
# action. Reuses rotate_refresh_token wholesale for the actual token
# reissue -- same rotation/reuse-detection/session-usability machinery
# /auth/refresh already has, just with an explicit team_id instead of
# carrying the presented token's own forward. What's new here is purely
# the pre-check: an invalid explicit switch request (team doesn't exist,
# belongs to a different org, or the caller isn't a member) fails loudly
# with 403/404 -- unlike rotate_refresh_token's own defense-in-depth
# fallback (team_service.resolve_team_claim silently degrading to the
# personal workspace), which is correct for the *implicit* carry-forward
# on a plain refresh but would be a silent, confusing failure for a user
# who just explicitly clicked a team in the workspace switcher.
@router.post("/switch-team")
def switch_team(req: SwitchTeamRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    presented_token = req.refresh_token or request.cookies.get(SESSION_COOKIE_NAME)
    if not presented_token:
        raise HTTPException(401, "Invalid refresh token")

    try:
        old_claims = decode_token(presented_token)
    except Exception:
        raise HTTPException(401, "Invalid refresh token")

    user_id = int(old_claims.get("sub", 0))

    if req.team_id is not None:
        team = db.query(Team).filter(Team.id == req.team_id).first()
        if not team:
            raise HTTPException(404, "Team not found")

        # Organization membership and team membership are checked
        # separately and both must hold -- neither substitutes for the
        # other, same posture team_service.resolve_team_claim documents.
        org_id = old_claims.get("org_id")
        if org_id is None or team.organization_id != org_id:
            raise HTTPException(403, "Team does not belong to your organization")

        if not team_service.get_team_member(db, req.team_id, user_id):
            raise HTTPException(403, "Not a member of this team")

    result = rotate_refresh_token(db, presented_token, team_id=req.team_id)
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
        token_revocation.blacklist_access_token(req.access_token)

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
            # Multi-user Workspaces (Studio v0.8.0), Mode B -- additive,
            # same graceful-default reasoning as org_id/org_role above. A
            # token minted before this change, or one where team_id
            # resolved to None (personal workspace, or a team claim that
            # no longer validated), both correctly fall back to None here.
            "team_id": payload.get("team_id"),
            "team_role": payload.get("team_role"),
            "auth_method": payload.get("auth_method"),
            # Phase 2 PR4 -- additive, same graceful-default reasoning as
            # the rest of this block. None for every token minted before
            # this change or by any non-SSO auth_method.
            "idp_org_id": payload.get("idp_org_id"),
            "schema_version": payload.get("token_version", 1),
        }
    except Exception:
        return {"valid": False}
