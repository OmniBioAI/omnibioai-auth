import time
from urllib.parse import urlencode

import httpx
from jose import jwt as jose_jwt
from jose.exceptions import JWTError

from app.core import crypto
from app.core.config import settings
from app.db.models import OrganizationSSOConfig

_TOKEN_EXCHANGE_TIMEOUT_SECONDS = 10.0
_JWKS_TIMEOUT_SECONDS = 5.0
_JWKS_CACHE_TTL_SECONDS = 600
# Requesting an id_token requires "openid"; email/profile mirror what the 3
# static providers already request (app/core/oauth_providers.py).
_OIDC_SCOPE = "openid email profile"
# Deliberately narrow: never accept "none" or a symmetric (HS*) algorithm
# here. HS* would let anyone who can read the (public) JWKS forge a token
# by signing with it as an HMAC secret -- a variant of the classic
# algorithm-confusion attack. Every signing_key we'd ever match from a
# real IdP's JWKS is RSA or EC, so this allowlist costs nothing real.
_ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256", "ES256")

# In-process cache keyed by organization_sso_configs.id -- {id: (fetched_at, jwks_dict)}.
# A single-process cache is fine here: the worst case on a miss/expiry is
# one extra HTTP fetch to the IdP's own jwks_uri (not a correctness
# issue), and nothing else in this service's OAuth path depends on a
# shared cross-process cache (e.g. Redis) for correctness either.
_jwks_cache: dict[int, tuple[float, dict]] = {}


class SSOLoginError(Exception):
    """Raised for any failure exchanging or validating an enterprise IdP's
    response. Message is safe to return directly to the caller."""


def redirect_uri_for(org_slug: str) -> str:
    return f"{settings.OAUTH_REDIRECT_BASE_URL}/auth/sso/{org_slug}/callback"


def build_authorize_url(
    config: OrganizationSSOConfig, org_slug: str, state: str, code_challenge: str, nonce: str
) -> str:
    params = {
        "client_id": config.client_id,
        "redirect_uri": redirect_uri_for(org_slug),
        "response_type": "code",
        "scope": _OIDC_SCOPE,
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    return f"{config.authorization_endpoint}?{urlencode(params)}"


async def _fetch_jwks(config: OrganizationSSOConfig) -> dict:
    if not config.jwks_uri:
        raise SSOLoginError("this organization's SSO configuration is incomplete (no signing key endpoint)")

    cached = _jwks_cache.get(config.id)
    if cached and (time.monotonic() - cached[0]) < _JWKS_CACHE_TTL_SECONDS:
        return cached[1]

    try:
        async with httpx.AsyncClient(timeout=_JWKS_TIMEOUT_SECONDS) as client:
            # jwks_uri came from a discovery document already fetched
            # (and SSRF-checked) at registration time in org_sso_service.py
            # -- not re-validating the hostname again here, on every
            # login, is a deliberate tradeoff, not an oversight.
            resp = await client.get(config.jwks_uri, follow_redirects=False)
    except httpx.HTTPError as e:
        raise SSOLoginError(f"could not fetch signing keys from the identity provider: {e}")

    if resp.status_code != 200:
        raise SSOLoginError(f"identity provider's key endpoint returned HTTP {resp.status_code}")

    try:
        jwks = resp.json()
    except ValueError:
        raise SSOLoginError("identity provider's key endpoint did not return valid JSON")

    _jwks_cache[config.id] = (time.monotonic(), jwks)
    return jwks


def _find_signing_key(jwks: dict, kid: str | None) -> dict:
    keys = jwks.get("keys", [])
    if kid is not None:
        for key in keys:
            if key.get("kid") == kid:
                return key
        raise SSOLoginError("id_token's key id does not match any key published by the identity provider")
    if len(keys) == 1:
        # No kid in the token header, but exactly one candidate key -- the
        # common case for a small IdP that doesn't rotate keys.
        return keys[0]
    raise SSOLoginError("could not determine which signing key to use for this id_token")


async def exchange_code_for_id_token_claims(
    config: OrganizationSSOConfig, org_slug: str, code: str, code_verifier: str, nonce: str
) -> dict:
    """Exchanges the authorization code for tokens, then fully verifies
    the returned id_token: signature (via the IdP's own JWKS), issuer,
    audience, expiry, and OIDC nonce. Never trusts a userinfo-endpoint
    response for identity -- some enterprise IdPs don't even expose one,
    and the id_token is the actual OIDC-signed identity assertion.
    Raises SSOLoginError on any failure. Returns the verified claims dict
    (sub, email, name if present, ...).
    """
    client_secret = crypto.decrypt(config.client_secret_encrypted)

    try:
        async with httpx.AsyncClient(timeout=_TOKEN_EXCHANGE_TIMEOUT_SECONDS) as client:
            token_resp = await client.post(
                config.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri_for(org_slug),
                    "client_id": config.client_id,
                    "client_secret": client_secret,
                    "code_verifier": code_verifier,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as e:
        raise SSOLoginError(f"could not reach the identity provider's token endpoint: {e}")

    if token_resp.status_code != 200:
        raise SSOLoginError(
            f"identity provider rejected the authorization code (HTTP {token_resp.status_code})"
        )

    try:
        token_data = token_resp.json()
    except ValueError:
        raise SSOLoginError("identity provider's token endpoint did not return valid JSON")

    id_token = token_data.get("id_token")
    if not id_token:
        raise SSOLoginError("identity provider did not return an id_token")

    try:
        header = jose_jwt.get_unverified_header(id_token)
    except JWTError as e:
        raise SSOLoginError(f"could not read id_token header: {e}")

    jwks = await _fetch_jwks(config)
    signing_key = _find_signing_key(jwks, header.get("kid"))

    algorithm = signing_key.get("alg") or header.get("alg")
    if algorithm not in _ALLOWED_ID_TOKEN_ALGORITHMS:
        raise SSOLoginError(f"unsupported or missing id_token signing algorithm: {algorithm!r}")

    try:
        claims = jose_jwt.decode(
            id_token,
            signing_key,
            algorithms=[algorithm],
            audience=config.client_id,
            issuer=config.issuer,
        )
    except JWTError as e:
        raise SSOLoginError(f"id_token failed validation: {e}")

    if claims.get("nonce") != nonce:
        raise SSOLoginError("id_token nonce does not match the original request")

    if not claims.get("sub"):
        raise SSOLoginError("identity provider's id_token did not include a subject (sub) claim")

    if not claims.get("email"):
        raise SSOLoginError("identity provider's id_token did not include an email claim")

    return claims
