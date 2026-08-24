import hmac
import json
import os
import secrets
import time

import redis as _redis_sync
from fastapi import APIRouter, Depends, Form, HTTPException, Query
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session
from fastapi.responses import RedirectResponse

from app.core.config import settings
from app.core.jwt import create_access_token, create_service_access_token
from app.db.session import get_db
from app.schemas.oauth_client import AuthorizationCodeTokenResponse, ClientCredentialsTokenResponse
from app.services import oauth_client_service
from app.rbac import get_current_user

router = APIRouter(prefix="/oauth", tags=["oauth-token"])

# Optional -- RFC 6749 SS2.3.1 allows client_id/client_secret via HTTP Basic
# instead of the request body. auto_error=False so a request that instead
# supplies them as form fields isn't rejected before the handler runs.
_basic = HTTPBasic(auto_error=False)
_codes = _redis_sync.from_url(os.getenv("REDIS_URL", "redis://redis:6379"), decode_responses=True)


def _require_lims_sso_config() -> None:
    if not (settings.LIMS_SSO_CLIENT_ID and settings.LIMS_SSO_CLIENT_SECRET and settings.LIMS_SSO_REDIRECT_URI):
        raise HTTPException(503, "first-party SSO is not configured")


def _verify_lims_client(client_id: str | None, client_secret: str | None) -> None:
    _require_lims_sso_config()
    if not client_id or not client_secret or not hmac.compare_digest(client_id, settings.LIMS_SSO_CLIENT_ID) or not hmac.compare_digest(client_secret, settings.LIMS_SSO_CLIENT_SECRET):
        raise HTTPException(401, "invalid_client")


@router.get("/authorize")
def authorize_first_party_client(
    client_id: str = Query(...),
    redirect_uri: str = Query(...),
    response_type: str = Query(...),
    state: str = Query(..., min_length=16, max_length=512),
    nonce: str | None = Query(None, min_length=16, max_length=512),
    user=Depends(get_current_user),
):
    """Issue a one-time code for the authenticated platform owner.

    This endpoint is intentionally opt-in and narrowly registered for LIMS.
    It never accepts a user identity in the query; identity comes only from
    the independently verified bearer token.
    """
    _require_lims_sso_config()
    if response_type != "code" or client_id != settings.LIMS_SSO_CLIENT_ID or redirect_uri != settings.LIMS_SSO_REDIRECT_URI:
        raise HTTPException(400, "invalid_request")
    if "manage_all_orgs" not in (user.get("permissions") or []):
        raise HTTPException(403, "Forbidden")
    try:
        code = secrets.token_urlsafe(32)
        jti = secrets.token_urlsafe(24)
        ttl = settings.LIMS_SSO_CODE_TTL_SECONDS
        _codes.setex(
            f"oauth:first-party:{code}",
            ttl,
            json.dumps({
                "jti": jti,
                "sub": str(user.get("sub")),
                "email": user.get("email"),
                "roles": user.get("roles", []),
                "permissions": user.get("permissions", []),
                "org_id": user.get("org_id"),
                "org_role": user.get("org_role", []),
                "auth_method": user.get("auth_method"),
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "state": state,
                "nonce": nonce,
                "exp": int(time.time()) + ttl,
            }),
        )
    except Exception:
        raise HTTPException(503, "authorization service unavailable")
    separator = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{separator}code={code}&state={state}", status_code=302)


@router.post("/token", response_model=ClientCredentialsTokenResponse)
def issue_client_credentials_token(
    grant_type: str = Form(...),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    scope: str | None = Form(None),
    basic: HTTPBasicCredentials | None = Depends(_basic),
    db: Session = Depends(get_db),
):
    if grant_type != "client_credentials":
        raise HTTPException(400, "unsupported_grant_type")

    # HTTP Basic takes precedence over body fields when both are present --
    # a caller sending both is almost certainly a client library defaulting
    # to Basic while also filling out the form struct; Basic is the more
    # deliberate signal.
    if basic is not None:
        client_id, client_secret = basic.username, basic.password

    if not client_id or not client_secret:
        raise HTTPException(400, "invalid_request -- client_id and client_secret are required")

    oauth_client = oauth_client_service.verify_client_credentials(db, client_id, client_secret)
    if not oauth_client:
        # RFC 6749 SS5.2: invalid_client covers unknown/revoked/expired/
        # wrong-secret alike -- never distinguish these to the caller.
        raise HTTPException(401, "invalid_client")

    granted_scopes = set(oauth_client.scopes or [])
    if scope:
        requested_scopes = set(scope.split())
        if not requested_scopes <= granted_scopes:
            raise HTTPException(400, "invalid_scope")
        token_scopes = sorted(requested_scopes)
    else:
        token_scopes = sorted(granted_scopes)

    oauth_client_service.mark_used(db, oauth_client)

    access_token = create_service_access_token(
        {
            "org_id": oauth_client.organization_id,
            "client_id": oauth_client.client_id,
            "scopes": token_scopes,
            "auth_method": "client_credentials",
        },
        expires_minutes=settings.CLIENT_CREDENTIALS_TOKEN_EXPIRE_MINUTES,
    )

    return ClientCredentialsTokenResponse(
        access_token=access_token,
        expires_in=settings.CLIENT_CREDENTIALS_TOKEN_EXPIRE_MINUTES * 60,
        scope=" ".join(token_scopes),
    )


@router.post("/token/authorization-code", response_model=AuthorizationCodeTokenResponse)
def redeem_first_party_authorization_code(
    grant_type: str = Form(...),
    code: str = Form(...),
    redirect_uri: str = Form(...),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    basic: HTTPBasicCredentials | None = Depends(_basic),
):
    """Redeem a LIMS launch code and return a short-lived user access token."""
    if basic is not None:
        client_id, client_secret = basic.username, basic.password
    if grant_type != "authorization_code":
        raise HTTPException(400, "unsupported_grant_type")
    _verify_lims_client(client_id, client_secret)
    try:
        raw = _codes.getdel(f"oauth:first-party:{code}")
    except Exception:
        raise HTTPException(503, "authorization service unavailable")
    if not raw:
        raise HTTPException(400, "invalid_grant")
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError):
        raise HTTPException(400, "invalid_grant")
    if payload.get("exp", 0) < int(time.time()) or payload.get("client_id") != client_id or payload.get("redirect_uri") != redirect_uri or "manage_all_orgs" not in (payload.get("permissions") or []):
        raise HTTPException(400, "invalid_grant")
    token = create_access_token({k: payload[k] for k in ("sub", "email", "roles", "permissions", "org_id", "org_role", "auth_method") if k in payload})
    return AuthorizationCodeTokenResponse(
        access_token=token,
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        state=payload.get("state"),
    )
