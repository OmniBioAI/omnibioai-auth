import secrets
from urllib.parse import urlencode

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import create_sso_state_token, decode_token
from app.db.session import get_db
from app.schemas.oauth import OAuthCallbackBody
from app.services import org_oidc_service, org_service, org_sso_service, oauth_service, sso_discovery_service
from app.services.auth_service import generate_tokens
# Reusing PR2's own PKCE helpers rather than re-implementing them --
# they're pure functions with no shared state, and the task this PR
# implements explicitly calls for reusing PR2's PKCE support as-is.
from app.services.oauth_service import _code_challenge_s256, _generate_code_verifier

router = APIRouter(prefix="/auth/sso", tags=["sso"])


# ---------------- DISCOVER ----------------
@router.get("/discover")
def sso_discover(email: str, db: Session = Depends(get_db)):
    """Public, unauthenticated -- domain-based SSO routing only. Never
    reveals whether an account exists for `email` (see
    sso_discovery_service.find_org_for_email's own docstring for why
    that's structurally guaranteed, not just a convention here)."""
    config = sso_discovery_service.find_org_for_email(db, email)
    if not config:
        return {"sso_available": False}

    org = org_service.get_organization(db, config.organization_id)
    return {"sso_available": True, "org_slug": org.slug, "enforced": bool(config.enforced)}


# ---------------- LOGIN ----------------
@router.get("/{org_slug}/login")
def sso_login(org_slug: str, db: Session = Depends(get_db)):
    org = org_service.get_organization_by_slug(db, org_slug)
    if not org:
        raise HTTPException(404, "Unknown organization")

    config = org_sso_service.get_sso_config(db, org.id)
    if not config or config.status != "active":
        raise HTTPException(404, "SSO is not configured for this organization")

    code_verifier = _generate_code_verifier()
    code_challenge = _code_challenge_s256(code_verifier)
    nonce = secrets.token_urlsafe(32)

    state = create_sso_state_token(org.id, config.id, code_verifier, nonce)
    url = org_oidc_service.build_authorize_url(config, org_slug, state, code_challenge, nonce)
    return RedirectResponse(url)


def _verify_sso_state(db: Session, org_slug: str, state: str):
    """Returns (org, config) resolved from a validated state token.
    Raises HTTPException on any mismatch. The org/config used for the
    token exchange always come from the *state* (organization_id /
    organization_sso_config_id, signed and unforgeable), never re-derived
    from the caller-supplied org_slug or the IdP's own response --
    org_slug is only used as a consistency check against what the state
    already committed to at /login time."""
    try:
        payload = decode_token(state)
    except Exception:
        raise HTTPException(400, "Invalid or expired SSO state")
    if payload.get("type") != "sso_state":
        raise HTTPException(400, "Invalid SSO state")

    org = org_service.get_organization_by_slug(db, org_slug)
    if not org or payload.get("organization_id") != org.id:
        raise HTTPException(400, "SSO state does not match this organization")

    config = org_sso_service.get_sso_config(db, org.id)
    if not config or config.id != payload.get("organization_sso_config_id") or config.status != "active":
        raise HTTPException(400, "This organization's SSO configuration is no longer valid")

    return org, config, payload


async def _complete_sso_flow(db: Session, org_slug: str, code: str, state: str) -> dict:
    """Shared exchange + account-linking logic for both the GET
    (browser-redirect) and POST (SPA-mediated) callback variants below.
    Mirrors routes_oauth.py's _complete_oauth_flow deliberately closely --
    same three-way decision tree (linked -> log in, existing email ->
    require confirmation, neither -> create), reusing oauth_service.py's
    actual functions rather than a parallel implementation.
    """
    org, config, state_payload = _verify_sso_state(db, org_slug, state)

    try:
        claims = await org_oidc_service.exchange_code_for_id_token_claims(
            config, org_slug, code,
            code_verifier=state_payload["code_verifier"],
            nonce=state_payload["nonce"],
        )
    except org_oidc_service.SSOLoginError as e:
        raise HTTPException(400, str(e))

    sub = claims["sub"]
    email = claims["email"]

    # organization_sso_config_id scoping here is what prevents a `sub`
    # collision between two different orgs' IdPs from resolving to the
    # wrong org's linked account -- see find_linked_user's own docstring.
    linked_user = oauth_service.find_linked_user(db, "oidc", sub, organization_sso_config_id=config.id)
    if linked_user:
        org_service.jit_provision_membership(db, org.id, linked_user.id)
        access, refresh = generate_tokens(db, linked_user, auth_method="sso", idp_org_id=org.id)
        return {"status": "ok", "access_token": access, "refresh_token": refresh, "token_type": "bearer"}

    existing_user = oauth_service.find_user_by_email(db, email)
    if existing_user:
        # Same protection as the 3-provider flow: an email match to an
        # identity not yet linked to this IdP account is never linked
        # silently -- the existing account's password must be confirmed
        # first via the same POST /auth/link/confirm this flow already has.
        link_token = oauth_service.issue_link_confirmation(
            existing_user, "oidc", sub, email,
            organization_sso_config_id=config.id, idp_org_id=org.id,
        )
        return {"status": "link_required", "link_token": link_token, "provider": "oidc", "email": email}

    new_user = oauth_service.create_user_with_oauth(db, "oidc", sub, email, organization_sso_config_id=config.id)
    org_service.jit_provision_membership(db, org.id, new_user.id)
    access, refresh = generate_tokens(db, new_user, auth_method="sso", idp_org_id=org.id)
    return {"status": "ok", "access_token": access, "refresh_token": refresh, "token_type": "bearer"}


# ---------------- CALLBACK ----------------
@router.get("/{org_slug}/callback")
async def sso_callback_redirect(org_slug: str, code: str, state: str, db: Session = Depends(get_db)):
    # Real browser navigation (the IdP's redirect) -- failures must land
    # the user back in the app with a message, never a raw JSON error
    # page, same convention as routes_oauth.py's provider callback.
    try:
        result = await _complete_sso_flow(db, org_slug, code, state)
    except HTTPException as e:
        result = {"status": "error", "error": e.detail}
    return RedirectResponse(f"{settings.FRONTEND_BASE_URL}/oauth-complete?{urlencode(result)}")


@router.post("/{org_slug}/callback")
async def sso_callback_json(org_slug: str, body: OAuthCallbackBody, db: Session = Depends(get_db)):
    """SPA-mediated variant, same reasoning as routes_oauth.py's POST
    callback: if the IdP redirect lands on the frontend rather than this
    service directly, the frontend forwards the code/state here instead."""
    return await _complete_sso_flow(db, org_slug, body.code, body.state)
