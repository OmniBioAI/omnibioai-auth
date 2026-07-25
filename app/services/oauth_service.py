from urllib.parse import urlencode

import httpx

from app.core.jwt import create_oauth_state_token, create_link_token
from app.core.oauth_providers import PROVIDERS, redirect_uri_for, parse_userinfo
from app.db.models import OAuthAccount, User


class OAuthError(Exception):
    pass


def build_authorize_url(provider: str) -> str:
    cfg = PROVIDERS[provider]
    state = create_oauth_state_token(provider)
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri_for(provider),
        "response_type": "code",
        "scope": cfg["scope"],
        "state": state,
    }
    return f"{cfg['authorize_url']}?{urlencode(params)}"


async def exchange_code_for_userinfo(provider: str, code: str):
    """Exchange an authorization code for the provider's access token, then
    fetch and normalize userinfo. Raises OAuthError on any failure."""
    cfg = PROVIDERS[provider]

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            cfg["token_url"],
            data={
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "code": code,
                "redirect_uri": redirect_uri_for(provider),
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
        )
        if token_resp.status_code != 200:
            raise OAuthError(f"{provider} token exchange failed: {token_resp.text}")

        token_data = token_resp.json()
        provider_access_token = token_data.get("access_token")
        if not provider_access_token:
            raise OAuthError(f"{provider} token response missing access_token")

        auth_header = {"Authorization": f"Bearer {provider_access_token}"}
        userinfo_resp = await client.get(cfg["userinfo_url"], headers=auth_header)
        if userinfo_resp.status_code != 200:
            raise OAuthError(f"{provider} userinfo fetch failed: {userinfo_resp.text}")
        userinfo = userinfo_resp.json()

        emails = None
        if provider == "github" and not userinfo.get("email"):
            emails_resp = await client.get("https://api.github.com/user/emails", headers=auth_header)
            if emails_resp.status_code == 200:
                emails = emails_resp.json()

    provider_user_id, email = parse_userinfo(provider, userinfo, emails)
    if not email:
        raise OAuthError(f"{provider} did not return an email address for this account")

    return provider_user_id, email


def find_linked_user(db, provider: str, provider_user_id: str):
    account = (
        db.query(OAuthAccount)
        .filter(OAuthAccount.provider == provider, OAuthAccount.provider_user_id == provider_user_id)
        .first()
    )
    return account.user if account else None


def find_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()


def create_user_with_oauth(db, provider: str, provider_user_id: str, email: str) -> User:
    user = User(email=email, hashed_password=None, status="active")
    db.add(user)
    db.flush()
    db.add(OAuthAccount(user_id=user.id, provider=provider, provider_user_id=provider_user_id, email=email))
    db.commit()
    db.refresh(user)
    return user


def link_oauth_to_existing_user(db, user: User, provider: str, provider_user_id: str, email: str) -> None:
    db.add(OAuthAccount(user_id=user.id, provider=provider, provider_user_id=provider_user_id, email=email))
    db.commit()


def issue_link_confirmation(user: User, provider: str, provider_user_id: str, email: str) -> str:
    return create_link_token(user.id, provider, provider_user_id, email)
