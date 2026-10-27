"""
OmniBioAI app.core.oauth_providers.

Purpose:
    Defines redirect_uri_for, is_configured and parse_userinfo for app.core.oauth_providers.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from app.core.config import settings

PROVIDERS = {
    "google": {
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
        "authorize_url": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_url": "https://oauth2.googleapis.com/token",
        "userinfo_url": "https://openidconnect.googleapis.com/v1/userinfo",
        "scope": "openid email profile",
    },
    "github": {
        "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
        "client_secret": settings.GITHUB_OAUTH_CLIENT_SECRET,
        "authorize_url": "https://github.com/login/oauth/authorize",
        "token_url": "https://github.com/login/oauth/access_token",
        "userinfo_url": "https://api.github.com/user",
        "scope": "read:user user:email",
    },
    "microsoft": {
        "client_id": settings.MICROSOFT_OAUTH_CLIENT_ID,
        "client_secret": settings.MICROSOFT_OAUTH_CLIENT_SECRET,
        "authorize_url": "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
        "token_url": "https://login.microsoftonline.com/common/oauth2/v2.0/token",
        "userinfo_url": "https://graph.microsoft.com/oidc/userinfo",
        "scope": "openid email profile",
    },
}


def redirect_uri_for(provider: str) -> str:
    return f"{settings.OAUTH_REDIRECT_BASE_URL}/auth/{provider}/callback"


def is_configured(provider: str) -> bool:
    cfg = PROVIDERS.get(provider)
    return bool(cfg and cfg["client_id"] and cfg["client_secret"])


MICROSOFT_CONSUMER_TENANT_ID = "9188040d-6c67-4c5b-b112-36a304b66dad"


class UnverifiedEmailError(ValueError):
    """The provider did not vouch for this account's email address."""

    def __init__(self, email: str | None):
        super().__init__("unverified_email")
        self.email = email


def _claim_true(value) -> bool:
    return value is True or value in ("true", "True", "1", 1)


def parse_userinfo(
    provider: str,
    userinfo: dict,
    emails: list | None = None,
    id_token_claims: dict | None = None,
):
    """Normalize each provider's userinfo shape to (provider_user_id, email).

    `emails` is GitHub's separate /user/emails response — GitHub's /user
    endpoint omits email entirely when the user has made it private.
    `id_token_claims` is Microsoft's id_token payload (tid/xms_edov).

    Raises UnverifiedEmailError before any account lookup when the provider
    does not vouch for the email.
    """
    if provider == "google":
        if not _claim_true(userinfo.get("email_verified")):
            raise UnverifiedEmailError(userinfo.get("email"))
        return str(userinfo["sub"]), userinfo.get("email")

    if provider == "github":
        provider_user_id = str(userinfo["id"])
        email = userinfo.get("email")
        if not email and emails:
            primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
            if not primary:
                primary = next((e for e in emails if e.get("verified")), None)
            email = primary["email"] if primary else None
        return provider_user_id, email

    if provider == "microsoft":
        # preferred_username is a mutable sign-in name, not a verified email,
        # and must never be used for account discovery or linking. Microsoft
        # vouches for consumer-tenant email; Entra tenants require xms_edov.
        email = userinfo.get("email")
        claims = id_token_claims or {}
        verified = (
            claims.get("tid") == MICROSOFT_CONSUMER_TENANT_ID
            or _claim_true(claims.get("xms_edov"))
        )
        if not email or not verified:
            raise UnverifiedEmailError(email)
        return str(userinfo["sub"]), email

    raise ValueError(f"Unknown provider: {provider}")
