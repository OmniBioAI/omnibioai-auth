from datetime import datetime, timedelta
from jose import jwt
from app.core.config import settings
from app.core.rsa_keys import KID, PRIVATE_KEY_PEM, PUBLIC_KEY_PEM

import uuid


def _sign(payload: dict) -> str:
    """SSO Phase 2 PR15: single signing choke point for every token type
    below. When JWT_ALGORITHM=RS256, signs with the RSA private key and
    stamps a `kid` header so a verifier (this service or another one,
    eventually) knows which JWKS entry to check against. Defaults to the
    unchanged HS256 shared-secret path -- an operator has to opt in.
    """
    if settings.JWT_ALGORITHM == "RS256":
        return jwt.encode(payload, PRIVATE_KEY_PEM, algorithm="RS256", headers={"kid": KID})
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def create_access_token(data: dict):
    to_encode = data.copy()

    to_encode.update({
        "exp": datetime.utcnow() + timedelta(minutes=15),
        "type": "access",
        "jti": str(uuid.uuid4())   # 👈 IMPORTANT
    })

    return _sign(to_encode)


def create_refresh_token(data: dict):
    to_encode = data.copy()
    to_encode.update({
        "exp": datetime.utcnow() + timedelta(days=7),
        "type": "refresh",
        "jti": str(uuid.uuid4())   # without this, same-second logins collide on the refresh_tokens.token UNIQUE constraint
    })
    return _sign(to_encode)


def decode_token(token: str):
    """Verifies either algorithm, dispatched by the token's own `alg`
    header rather than by settings.JWT_ALGORITHM -- a migration window
    means already-issued HS256 tokens must keep validating for their full
    remaining lifetime even after an operator switches new issuance to
    RS256 (PR15 Task 6/success criteria). A malformed token that can't even
    be parsed for its header falls through to the HS256 decode call so it
    raises the same JWTError shape callers already catch.
    """
    try:
        alg = jwt.get_unverified_header(token).get("alg")
    except Exception:
        alg = None

    if alg == "RS256":
        return jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"])
    return jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])


def create_oauth_state_token(provider: str, code_verifier: str | None = None):
    """Short-lived, self-contained CSRF token for the OAuth authorize step.
    Avoids needing server-side session storage — verified purely by
    signature + expiry on callback, consistent with the rest of this
    service's stateless JWT approach.

    Phase 2 PR2: also the PKCE (RFC 7636) carrier -- code_verifier rides
    inside this same signed token rather than needing separate storage,
    the same "no server-side session" reasoning that motivated this
    token's design in the first place. Optional so a state token minted
    just before a rolling deploy (pre-PKCE) still decodes fine on a
    post-deploy instance -- oauth_service.exchange_code_for_userinfo
    treats a missing code_verifier as "don't send one," not an error.
    """
    payload = {
        "type": "oauth_state",
        "provider": provider,
        "exp": datetime.utcnow() + timedelta(minutes=10),
        "jti": str(uuid.uuid4()),
    }
    if code_verifier:
        payload["code_verifier"] = code_verifier
    return _sign(payload)


def create_sso_state_token(
    organization_id: int, organization_sso_config_id: int, code_verifier: str, nonce: str
):
    """Phase 2 PR4: state token for the per-org OIDC login flow
    (/auth/sso/{org_slug}/login -> /auth/sso/{org_slug}/callback).

    Deliberately a distinct token type ("sso_state", not "oauth_state") --
    routes_oauth.py's _verify_state explicitly requires type == "oauth_state",
    so a token minted here can never be replayed against the 3 existing
    provider callback routes, and vice versa. Self-contained, same
    reasoning as create_oauth_state_token: organization_id (which org's
    login this is for -- the authoritative source for the eventual
    idp_org_id JWT claim, never re-derived from the IdP's response),
    organization_sso_config_id (which config to use for the token
    exchange), code_verifier (PKCE), and nonce (OIDC replay protection)
    all travel inside this one signed token, no server-side session
    needed.
    """
    return _sign(
        {
            "type": "sso_state",
            "organization_id": organization_id,
            "organization_sso_config_id": organization_sso_config_id,
            "code_verifier": code_verifier,
            "nonce": nonce,
            "created_at": datetime.utcnow().isoformat(),
            "exp": datetime.utcnow() + timedelta(minutes=10),
            "jti": str(uuid.uuid4()),
        }
    )


def create_service_access_token(data: dict, expires_minutes: int):
    """Phase 2 PR1: issues a client_credentials-grant access token (RFC 6749
    SS4.4) -- a service identity, not a user. Deliberately does not go
    through create_access_token: that function always signs whatever
    `sub`/`email`-shaped payload a caller hands it, but a service token
    must never carry `sub`/`email` at all (there is no user), so this is a
    separate, smaller code path rather than a flag on the existing one --
    it can't accidentally be called with a user payload and produce
    something `get_current_user` would treat as a real account.
    """
    to_encode = data.copy()
    to_encode.update({
        "exp": datetime.utcnow() + timedelta(minutes=expires_minutes),
        "type": "access",
        "jti": str(uuid.uuid4()),
    })
    return _sign(to_encode)


def create_link_token(
    user_id: int,
    provider: str,
    provider_user_id: str,
    email: str,
    organization_sso_config_id: int | None = None,
    idp_org_id: int | None = None,
):
    """Short-lived token proving an OAuth exchange resolved to `user_id`'s
    existing email, pending password confirmation via POST /auth/link/confirm.

    organization_sso_config_id/idp_org_id are Phase 2 PR4 additions --
    both None for the existing 3-provider flow (unchanged payload shape
    for those callers), populated only when the exchange that produced
    this token came from an enterprise IdP, so /auth/link/confirm knows
    which org to JIT-provision membership in and what idp_org_id to put
    on the eventually-issued access token.
    """
    return _sign(
        {
            "type": "oauth_link",
            "user_id": user_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "email": email,
            "organization_sso_config_id": organization_sso_config_id,
            "idp_org_id": idp_org_id,
            "exp": datetime.utcnow() + timedelta(minutes=10),
            "jti": str(uuid.uuid4()),
        }
    )

