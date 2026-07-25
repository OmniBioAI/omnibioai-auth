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


def parse_userinfo(provider: str, userinfo: dict, emails: list | None = None):
    """Normalize each provider's userinfo shape to (provider_user_id, email).

    `emails` is GitHub's separate /user/emails response — GitHub's /user
    endpoint omits email entirely when the user has made it private.
    """
    if provider == "google":
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
        # Azure AD doesn't always populate `email` (depends on tenant/mailbox
        # config) — preferred_username is typically the UPN, email-shaped.
        email = userinfo.get("email") or userinfo.get("preferred_username")
        return str(userinfo["sub"]), email

    raise ValueError(f"Unknown provider: {provider}")
