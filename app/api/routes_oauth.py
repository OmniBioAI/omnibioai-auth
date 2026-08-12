from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import decode_token
from app.core.oauth_providers import PROVIDERS, is_configured
from app.core.security import verify_password
from app.db.session import get_db
from app.schemas.oauth import OAuthCallbackBody, OAuthLinkConfirmRequest
from app.services import oauth_service, org_service, sso_discovery_service
from app.services.auth_service import MFAEnrollmentRequiredError, generate_tokens_or_mfa_challenge

router = APIRouter(prefix="/auth", tags=["oauth"])


def _issue_tokens_or_challenge(db: Session, user, auth_method: str, idp_org_id: int | None = None) -> dict:
    """PR11.5.5: thin wrapper shared by every generate_tokens_or_mfa_challenge
    call site in this file, translating MFAEnrollmentRequiredError to the
    same 403 shape routes_auth.py's login() uses -- see
    docs/pr11-mfa-org-policy-discovery.md SS4."""
    try:
        return generate_tokens_or_mfa_challenge(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
    except MFAEnrollmentRequiredError:
        raise HTTPException(403, detail={
            "error": "mfa_enrollment_required",
            "message": "Your organization requires MFA enrollment",
        })


def _require_provider(provider: str) -> None:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unknown OAuth provider")
    if not is_configured(provider):
        raise HTTPException(503, f"{provider} SSO is not configured")


def _verify_state(provider: str, state: str) -> str | None:
    """Returns the PKCE code_verifier embedded in the state token (Phase 2
    PR2), or None for a state token that predates PKCE -- see
    create_oauth_state_token/exchange_code_for_userinfo for why that's
    handled as "don't send one," not an error."""
    try:
        payload = decode_token(state)
    except Exception:
        raise HTTPException(400, "Invalid or expired OAuth state")
    if payload.get("type") != "oauth_state" or payload.get("provider") != provider:
        raise HTTPException(400, "Invalid OAuth state")
    return payload.get("code_verifier")


async def _complete_oauth_flow(db: Session, provider: str, code: str, code_verifier: str | None = None) -> dict:
    """Shared exchange logic for both the GET (browser-redirect) and POST
    (SPA-mediated) callback variants below."""
    try:
        provider_user_id, email = await oauth_service.exchange_code_for_userinfo(
            provider, code, code_verifier=code_verifier
        )
    except oauth_service.OAuthError as e:
        raise HTTPException(400, str(e))

    # Phase 2 PR5: checked post-userinfo-fetch (we need the email this
    # provider vouches for), pre-token-issuance -- before find_linked_user,
    # so an enforcing org's member can't bypass enforcement by using
    # Google/GitHub/Microsoft instead of password login, even if they
    # already have a linked identity via one of those providers from
    # before enforcement was turned on.
    enforced_config = sso_discovery_service.find_enforced_org_for_email(db, email)
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

    linked_user = oauth_service.find_linked_user(db, provider, provider_user_id)
    if linked_user:
        # PR11.5.3: single shared MFA decision point, see
        # docs/pr11-mfa-login-challenge-discovery.md SS2.
        result = _issue_tokens_or_challenge(db, linked_user, auth_method="oauth")
        if result["mfa_required"]:
            return {"status": "mfa_required", "mfa_required": True, "challenge_token": result["challenge_token"], "methods": result["methods"]}
        return {"status": "ok", "access_token": result["access_token"], "refresh_token": result["refresh_token"], "token_type": "bearer"}

    existing_user = oauth_service.find_user_by_email(db, email)
    if existing_user:
        # Email matches an account this OAuth identity isn't linked to yet —
        # never link silently; require the existing account's password first.
        link_token = oauth_service.issue_link_confirmation(existing_user, provider, provider_user_id, email)
        return {"status": "link_required", "link_token": link_token, "provider": provider, "email": email}

    new_user = oauth_service.create_user_with_oauth(db, provider, provider_user_id, email)
    result = _issue_tokens_or_challenge(db, new_user, auth_method="oauth")
    if result["mfa_required"]:
        return {"status": "mfa_required", "mfa_required": True, "challenge_token": result["challenge_token"], "methods": result["methods"]}
    return {"status": "ok", "access_token": result["access_token"], "refresh_token": result["refresh_token"], "token_type": "bearer"}


@router.get("/{provider}/login")
def oauth_login(provider: str):
    _require_provider(provider)
    return RedirectResponse(oauth_service.build_authorize_url(provider))


@router.get("/{provider}/callback")
async def oauth_callback_redirect(provider: str, code: str, state: str, db: Session = Depends(get_db)):
    # This is a real browser navigation (the provider's redirect), so failures
    # must land the user back in the app with a message, never a raw JSON error page.
    try:
        _require_provider(provider)
        code_verifier = _verify_state(provider, state)
        result = await _complete_oauth_flow(db, provider, code, code_verifier=code_verifier)
    except HTTPException as e:
        # Phase 2 PR5's enforcement check raises with a dict detail
        # (reason/org_slug/sso_login_url) so the redirect can carry all
        # three as flat, urlencode-safe query params instead of an
        # unreadable encoded dict repr. Every pre-existing HTTPException
        # in this route (unknown provider, invalid state, OAuthError, ...)
        # still raises a plain string detail, so this branch is new,
        # additive behavior for them: unchanged, still `error=<message>`.
        if isinstance(e.detail, dict):
            result = {"status": "error", **e.detail}
        else:
            result = {"status": "error", "error": e.detail}
    return RedirectResponse(f"{settings.FRONTEND_BASE_URL}/oauth-complete?{urlencode(result)}")


@router.post("/{provider}/callback")
async def oauth_callback_json(provider: str, body: OAuthCallbackBody, db: Session = Depends(get_db)):
    """SPA-mediated variant: if the OAuth redirect lands on the frontend
    rather than this service directly, the frontend can forward the code
    here instead of relying on the GET redirect above."""
    _require_provider(provider)
    code_verifier = _verify_state(provider, body.state)
    return await _complete_oauth_flow(db, provider, body.code, code_verifier=code_verifier)


@router.post("/link/confirm")
def confirm_oauth_link(body: OAuthLinkConfirmRequest, db: Session = Depends(get_db)):
    try:
        payload = decode_token(body.link_token)
    except Exception:
        raise HTTPException(400, "Invalid or expired link token")
    if payload.get("type") != "oauth_link":
        raise HTTPException(400, "Invalid link token")

    user = oauth_service.find_user_by_email(db, payload["email"])
    if not user or user.id != payload["user_id"]:
        raise HTTPException(404, "Account not found")

    if not user.hashed_password:
        raise HTTPException(
            409,
            "This account has no password set — sign in with its original provider "
            "to link additional providers.",
        )
    if not verify_password(body.password, user.hashed_password):
        raise HTTPException(401, "Incorrect password")

    oauth_service.link_oauth_to_existing_user(
        db, user, payload["provider"], payload["provider_user_id"], payload["email"],
        organization_sso_config_id=payload.get("organization_sso_config_id"),
        organization_saml_config_id=payload.get("organization_saml_config_id"),
    )

    # Phase 2 PR4 -- additive. Every link token minted by the existing
    # 3-provider flow has idp_org_id=None (oauth_service.issue_link_confirmation's
    # default), so this branch is never taken for them: auth_method stays
    # "oauth" and no membership is touched, byte-identical to before this
    # change. Only a link token that originated from an enterprise SSO
    # callback carries a real idp_org_id, which is when membership actually
    # needs to exist for org_id/org_role to resolve to that org afterward.
    idp_org_id = payload.get("idp_org_id")
    if idp_org_id is not None:
        org_service.jit_provision_membership(db, idp_org_id, user.id)

    auth_method = "sso" if idp_org_id is not None else "oauth"
    result = _issue_tokens_or_challenge(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
    if result["mfa_required"]:
        return {"mfa_required": True, "challenge_token": result["challenge_token"], "methods": result["methods"]}
    return {"access_token": result["access_token"], "refresh_token": result["refresh_token"], "token_type": "bearer"}
