import base64
import hashlib
import secrets
from urllib.parse import urlencode

import httpx

from app.core.jwt import create_oauth_state_token, create_link_token
from app.core.oauth_providers import PROVIDERS, redirect_uri_for, parse_userinfo
from app.db.models import OAuthAccount, User
from app.services.role_service import assign_default_role


class OAuthError(Exception):
    pass


def _generate_code_verifier() -> str:
    # RFC 7636 SS4.1: 43-128 chars from [A-Za-z0-9-._~]. token_urlsafe's
    # alphabet (A-Za-z0-9-_) is already a subset of that, so no extra
    # filtering is needed -- 64 random bytes base64url-encodes to ~86 chars,
    # comfortably inside the allowed range.
    return secrets.token_urlsafe(64)


def _code_challenge_s256(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def build_authorize_url(provider: str) -> str:
    """Phase 2 PR2: PKCE (RFC 7636), added to the existing 3-provider flow
    as hardening, not a load-bearing security boundary -- this service
    already holds client_secret and performs the code exchange itself as a
    confidential client (Google/GitHub/Microsoft never see the browser
    directly). code_verifier travels inside the state token (see
    create_oauth_state_token); nothing new is stored server-side.
    """
    cfg = PROVIDERS[provider]
    code_verifier = _generate_code_verifier()
    code_challenge = _code_challenge_s256(code_verifier)
    state = create_oauth_state_token(provider, code_verifier=code_verifier)
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": redirect_uri_for(provider),
        "response_type": "code",
        "scope": cfg["scope"],
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return f"{cfg['authorize_url']}?{urlencode(params)}"


async def exchange_code_for_userinfo(provider: str, code: str, code_verifier: str | None = None):
    """Exchange an authorization code for the provider's access token, then
    fetch and normalize userinfo. Raises OAuthError on any failure.

    code_verifier is optional: absent only for a state token minted in the
    narrow window just before this PR's deploy (pre-PKCE), in which case no
    code_challenge was sent at authorize time either, so omitting it here
    keeps that in-flight login working instead of failing it.
    """
    cfg = PROVIDERS[provider]

    token_request_data = {
        "client_id": cfg["client_id"],
        "client_secret": cfg["client_secret"],
        "code": code,
        "redirect_uri": redirect_uri_for(provider),
        "grant_type": "authorization_code",
    }
    if code_verifier:
        token_request_data["code_verifier"] = code_verifier

    async with httpx.AsyncClient(timeout=10.0) as client:
        token_resp = await client.post(
            cfg["token_url"],
            data=token_request_data,
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


def find_linked_user(
    db,
    provider: str,
    provider_user_id: str,
    organization_sso_config_id: int | None = None,
    organization_saml_config_id: int | None = None,
):
    """organization_sso_config_id is a Phase 2 PR4 addition, default None
    preserves the exact query (and therefore behavior) every existing
    caller already gets. Passing it scopes the lookup to one org's IdP --
    required for multi-tenant OIDC, where `provider` is the generic
    string "oidc" for every enterprise IdP and provider_user_id (the
    IdP's `sub`) is only guaranteed unique *within* one IdP, not globally.
    Without this, two different orgs' IdPs that happen to issue the same
    sub value could resolve to each other's linked account -- exactly the
    cross-tenant identity confusion this scoping exists to prevent.

    organization_saml_config_id is SAML PR6's exact analogue for
    provider="saml": scopes the lookup to one org's SAML IdP the same way,
    for the same reason (a NameID is only guaranteed unique within one
    IdP). Both scoping params default to None and are independent columns
    (see OAuthAccount's own comment), so passing one never affects a query
    for the other provider family.
    """
    query = db.query(OAuthAccount).filter(
        OAuthAccount.provider == provider, OAuthAccount.provider_user_id == provider_user_id
    )
    if organization_sso_config_id is not None:
        query = query.filter(OAuthAccount.organization_sso_config_id == organization_sso_config_id)
    if organization_saml_config_id is not None:
        query = query.filter(OAuthAccount.organization_saml_config_id == organization_saml_config_id)
    account = query.first()
    return account.user if account else None


def find_user_by_email(db, email: str):
    return db.query(User).filter(User.email == email).first()


def _assert_single_idp_scope(organization_sso_config_id, organization_saml_config_id) -> None:
    """OAuthAccount's two scoping columns (see its own model comment) are
    each a real ForeignKey into a different table -- a row scoped to an
    OIDC config can never also be scoped to a SAML config, and vice versa.
    Guards every write path (create/link) against ever persisting both at
    once, which the schema's nullable-FK shape alone does not prevent."""
    if organization_sso_config_id is not None and organization_saml_config_id is not None:
        raise ValueError(
            "organization_sso_config_id and organization_saml_config_id are mutually exclusive"
        )


def create_user_with_oauth(
    db,
    provider: str,
    provider_user_id: str,
    email: str,
    organization_sso_config_id: int | None = None,
    organization_saml_config_id: int | None = None,
) -> User:
    _assert_single_idp_scope(organization_sso_config_id, organization_saml_config_id)
    user = User(email=email, hashed_password=None, status="active")
    db.add(user)
    db.flush()
    assign_default_role(db, user)
    db.add(
        OAuthAccount(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
            organization_sso_config_id=organization_sso_config_id,
            organization_saml_config_id=organization_saml_config_id,
        )
    )
    db.commit()
    db.refresh(user)
    return user


def link_oauth_to_existing_user(
    db,
    user: User,
    provider: str,
    provider_user_id: str,
    email: str,
    organization_sso_config_id: int | None = None,
    organization_saml_config_id: int | None = None,
) -> None:
    _assert_single_idp_scope(organization_sso_config_id, organization_saml_config_id)
    db.add(
        OAuthAccount(
            user_id=user.id,
            provider=provider,
            provider_user_id=provider_user_id,
            email=email,
            organization_sso_config_id=organization_sso_config_id,
            organization_saml_config_id=organization_saml_config_id,
        )
    )
    db.commit()


def issue_link_confirmation(
    user: User,
    provider: str,
    provider_user_id: str,
    email: str,
    organization_sso_config_id: int | None = None,
    organization_saml_config_id: int | None = None,
    idp_org_id: int | None = None,
) -> str:
    _assert_single_idp_scope(organization_sso_config_id, organization_saml_config_id)
    return create_link_token(
        user.id, provider, provider_user_id, email,
        organization_sso_config_id=organization_sso_config_id,
        organization_saml_config_id=organization_saml_config_id,
        idp_org_id=idp_org_id,
    )
