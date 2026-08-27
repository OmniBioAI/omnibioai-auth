"""#443: lets a trusted internal service (svc-bio-agent, holding
service_token.mint) mint a short-lived access token on behalf of an
already-authenticated user of that service, so the real user's identity
-- not the service's own shared identity -- reaches a downstream system
that only accepts an omnibioai-auth JWT (e.g. TES, via api-gateway).

Deliberately lightweight, not a call to auth_service.generate_tokens:
this is not a login. No RefreshToken row, no UserSession row, no
users.last_login_at write, no session-eviction accounting touched --
calling generate_tokens here would manufacture a persisted "session" for
every mint (bio_agent may mint far more often than a human logs in), and
would misrepresent a token-mint as this user having just authenticated.
Reuses exactly the two pieces of generate_tokens that a login-shaped
token issuance and a lightweight one both need: build_user_claims (the
single source of truth for what goes in the payload) and
create_access_token (the actual signing) -- the same reuse shape
rotate_refresh_token already established for "recompute fresh claims,
issue a token, without treating this as a new login."

Security: this function trusts its caller's assertion of `target_email`
absolutely -- there is no independent proof of identity here beyond
"the caller already held service_token.mint." That permission must
only ever be granted to a service that itself verified the email before
calling this (e.g. an OAuth/allauth login that already confirmed it with
the identity provider) -- never to a caller that accepts a
user-supplied, unverified email. See app/api/routes_service_mint.py's
own module docstring for how the permission grant enforces that.
"""
from app.core.jwt import create_access_token
from app.core.config import settings
from app.services import audit_service, oauth_service
from app.services.audit_service import AuditEventType
from app.services.auth_service import build_user_claims


def mint_user_service_token(db, target_email: str, actor_user_id: int):
    """Resolves `target_email` to a real User (JIT-provisioning one via
    oauth_service.create_user_with_oauth if none exists yet -- the exact
    same primitive every OAuth/SSO/SAML login already JIT-provisions
    through, not a new user-creation path), then mints a token carrying
    that user's own real, freshly-resolved permissions -- never anything
    broader than a real login for them would produce right now.

    provider="bio_agent_session" documents *how* this identity was
    vouched for (this service's own authenticated session, not an IdP
    round-trip) the same way provider="oidc"/"saml" already document
    theirs -- so a future admin looking at this user's OAuthAccount rows
    can tell this account originated from a mint call, not a real IdP
    login.

    Returns (access_token, expires_in_seconds).
    """
    user = oauth_service.find_user_by_email(db, target_email)
    if user is None:
        user = oauth_service.create_user_with_oauth(
            db, provider="bio_agent_session", provider_user_id=target_email, email=target_email,
        )

    payload = build_user_claims(db, user, auth_method="service_mint")
    access_token = create_access_token(payload)

    audit_service.log_event(
        db, AuditEventType.SERVICE_TOKEN_MINTED, actor_user_id=actor_user_id,
        target_user_id=user.id, resource_type="user", resource_id=user.id,
        metadata={"target_email": target_email},
    )

    return access_token, settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60
