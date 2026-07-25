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
from app.services import oauth_service
from app.services.auth_service import generate_tokens

router = APIRouter(prefix="/auth", tags=["oauth"])


def _require_provider(provider: str) -> None:
    if provider not in PROVIDERS:
        raise HTTPException(404, "Unknown OAuth provider")
    if not is_configured(provider):
        raise HTTPException(503, f"{provider} SSO is not configured")


def _verify_state(provider: str, state: str) -> None:
    try:
        payload = decode_token(state)
    except Exception:
        raise HTTPException(400, "Invalid or expired OAuth state")
    if payload.get("type") != "oauth_state" or payload.get("provider") != provider:
        raise HTTPException(400, "Invalid OAuth state")


async def _complete_oauth_flow(db: Session, provider: str, code: str) -> dict:
    """Shared exchange logic for both the GET (browser-redirect) and POST
    (SPA-mediated) callback variants below."""
    try:
        provider_user_id, email = await oauth_service.exchange_code_for_userinfo(provider, code)
    except oauth_service.OAuthError as e:
        raise HTTPException(400, str(e))

    linked_user = oauth_service.find_linked_user(db, provider, provider_user_id)
    if linked_user:
        access, refresh = generate_tokens(db, linked_user)
        return {"status": "ok", "access_token": access, "refresh_token": refresh, "token_type": "bearer"}

    existing_user = oauth_service.find_user_by_email(db, email)
    if existing_user:
        # Email matches an account this OAuth identity isn't linked to yet —
        # never link silently; require the existing account's password first.
        link_token = oauth_service.issue_link_confirmation(existing_user, provider, provider_user_id, email)
        return {"status": "link_required", "link_token": link_token, "provider": provider, "email": email}

    new_user = oauth_service.create_user_with_oauth(db, provider, provider_user_id, email)
    access, refresh = generate_tokens(db, new_user)
    return {"status": "ok", "access_token": access, "refresh_token": refresh, "token_type": "bearer"}


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
        _verify_state(provider, state)
        result = await _complete_oauth_flow(db, provider, code)
    except HTTPException as e:
        result = {"status": "error", "error": e.detail}
    return RedirectResponse(f"{settings.FRONTEND_BASE_URL}/oauth-complete?{urlencode(result)}")


@router.post("/{provider}/callback")
async def oauth_callback_json(provider: str, body: OAuthCallbackBody, db: Session = Depends(get_db)):
    """SPA-mediated variant: if the OAuth redirect lands on the frontend
    rather than this service directly, the frontend can forward the code
    here instead of relying on the GET redirect above."""
    _require_provider(provider)
    _verify_state(provider, body.state)
    return await _complete_oauth_flow(db, provider, body.code)


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
        db, user, payload["provider"], payload["provider_user_id"], payload["email"]
    )

    access, refresh = generate_tokens(db, user)
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}
