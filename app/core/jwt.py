from datetime import datetime, timedelta
from jose import jwt
from jose.exceptions import JWTClaimsError
from app.core.config import settings
from app.core.rsa_keys import KID, PRIVATE_KEY_PEM, PUBLIC_KEY_PEM

import uuid


def _sign(payload: dict) -> str:
    """SSO Phase 2 PR15: single signing choke point for every token type
    below. When JWT_ALGORITHM=RS256, signs with the RSA private key and
    stamps a `kid` header so a verifier (this service or another one,
    eventually) knows which JWKS entry to check against. Defaults to the
    unchanged HS256 shared-secret path -- an operator has to opt in.

    PR12: also stamps iss/aud (setdefault, so no existing caller's
    explicit payload keys are ever overridden -- none currently set
    either) on every token type issued below, verified opportunistically
    by decode_token.
    """
    payload = {**payload}
    payload.setdefault("iss", settings.JWT_ISSUER)
    payload.setdefault("aud", settings.JWT_AUDIENCE)
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

    PR12: aud is passed to jose so a token carrying an `aud` that doesn't
    match settings.JWT_AUDIENCE is rejected -- jose itself only enforces
    this when the claim is present, so a token minted before this change
    (no `aud` at all) still decodes. iss is checked the same
    opportunistically-but-when-present way, but by hand: unlike `aud`,
    jose's `issuer` kwarg requires the claim to exist at all once passed,
    which would reject every pre-PR12 and synthetic-test token outright --
    too strict for a rolling deploy / migration window.
    """
    try:
        alg = jwt.get_unverified_header(token).get("alg")
    except Exception:
        alg = None

    if alg == "RS256":
        claims = jwt.decode(token, PUBLIC_KEY_PEM, algorithms=["RS256"], audience=settings.JWT_AUDIENCE)
    else:
        claims = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"], audience=settings.JWT_AUDIENCE)

    issuer = claims.get("iss")
    if issuer is not None and issuer != settings.JWT_ISSUER:
        raise JWTClaimsError(f"Invalid issuer: {issuer!r}")

    return claims


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


def create_first_party_authorization_code(
    *, user: dict, client_id: str, redirect_uri: str, state: str, nonce: str | None = None
):
    """Create a short-lived, signed first-party authorization code.

    The code is only a signed envelope; the issuing route also records its
    ``jti`` in Redis and the token endpoint atomically consumes that marker.
    This keeps the code single-use across Auth instances without introducing
    a new database table or treating a code as an access token.
    """
    return _sign(
        {
            "type": "first_party_authorization_code",
            "sub": str(user.get("sub")),
            "email": user.get("email"),
            "roles": user.get("roles", []),
            "permissions": user.get("permissions", []),
            "org_id": user.get("org_id"),
            "org_role": user.get("org_role", []),
            "auth_method": user.get("auth_method"),
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "state": state,
            "nonce": nonce,
            "exp": datetime.utcnow() + timedelta(seconds=settings.LIMS_SSO_CODE_TTL_SECONDS),
            "jti": str(uuid.uuid4()),
        }
    )


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


def create_saml_relay_state_token(organization_id: int, organization_saml_config_id: int, request_id: str):
    """SAML SSO PR4: signed, opaque RelayState for the SP-initiated SAML
    login flow (/auth/saml/{org_slug}/login). Structural analog of
    create_sso_state_token's role for OIDC SSO's `state` parameter --
    same "no server-side session, verified purely by signature + expiry"
    design -- but a distinct token type ("saml_relay_state", not
    "sso_state"), for the identical reason create_sso_state_token's own
    docstring gives for why it isn't "oauth_state": a token minted here
    must never be replayable against the existing OIDC
    /auth/sso/{org_slug}/callback route, or vice versa, even though both
    carry an organization_id.

    No code_verifier/nonce -- SAML's SP-initiated AuthnRequest has no
    PKCE or OIDC-nonce equivalent at this stage (PR4 does not sign the
    AuthnRequest). organization_saml_config_id is the SAML equivalent of
    create_sso_state_token's organization_sso_config_id: which IdP config
    this login attempt is for, bound server-side at /login time from the
    already-resolved Organization/OrganizationSAMLConfig rows -- never
    from anything client-supplied -- so PR5's ACS handler can verify the
    callback's RelayState commits to the same organization/config this
    login actually started with, instead of trusting org_slug (or any
    other client-supplied value) a second time at that point.

    request_id (PR5 addition): the AuthnRequest's own ID, generated at
    /login time -- carried here so PR5 can pass it back into
    OneLogin_Saml2_Auth.process_response(request_id=...) and get a real
    InResponseTo check from python3-saml itself, instead of skipping
    that validation (which the library treats as "don't check
    InResponseTo" when request_id is None -- not acceptable for a
    security-relevant check). Required, not optional: unlike
    code_verifier on create_oauth_state_token, there is no pre-PR5
    RelayState in the wild that would need to keep decoding without it.
    """
    return _sign(
        {
            "type": "saml_relay_state",
            "organization_id": organization_id,
            "organization_saml_config_id": organization_saml_config_id,
            "request_id": request_id,
            "exp": datetime.utcnow() + timedelta(minutes=10),
            "jti": str(uuid.uuid4()),
        }
    )


def create_saml_slo_relay_state_token(organization_id: int, organization_saml_config_id: int, request_id: str):
    """PR11 (SLO): signed, opaque RelayState for the SP-initiated logout
    round trip (POST /auth/saml/{org_slug}/logout builds the redirect;
    GET /auth/saml/{org_slug}/slo consumes it when the IdP redirects the
    browser back with a LogoutResponse). Structurally identical to
    create_saml_relay_state_token above, and deliberately a DISTINCT
    token `type` ("saml_slo_relay_state", not "saml_relay_state") for the
    same reason that function's own docstring gives for why it isn't
    reused for OIDC's `state`: a token minted for one purpose must never
    be replayable against a different route that also happens to accept
    a RelayState-shaped payload. In particular, this token must never be
    accepted by POST /auth/saml/{org_slug}/acs, and the login RelayState
    must never be accepted by GET /auth/saml/{org_slug}/slo.

    request_id: the SP-initiated LogoutRequest's own ID (generated when
    org_saml_service.build_logout_request_url constructs it) -- carried
    here for the identical reason create_saml_relay_state_token's own
    request_id is: so the returning LogoutResponse's InResponseTo can be
    validated for real (OneLogin_Saml2_Logout_Response.is_valid(...,
    request_id=...)) instead of skipping that check.
    """
    return _sign(
        {
            "type": "saml_slo_relay_state",
            "organization_id": organization_id,
            "organization_saml_config_id": organization_saml_config_id,
            "request_id": request_id,
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


def create_mfa_challenge_token(
    user_id: int,
    auth_method: str,
    idp_org_id: int | None = None,
    saml_name_id: str | None = None,
    saml_session_index: str | None = None,
    organization_saml_config_id: int | None = None,
):
    """PR11.5.3: short-lived, self-contained proof that primary
    authentication (password/oauth/sso/license) already succeeded for
    `user_id` and only the second factor remains -- same "no
    server-side session" design as create_oauth_state_token/
    create_sso_state_token/create_link_token above.

    Deliberately minimal claims: `user_id`, not `sub` -- so this token
    doesn't structurally resemble a real access token's payload shape
    at all (on top of the explicit `type` check get_current_user
    performs, app/rbac.py). No roles/permissions/org_id/org_role, no
    password/secret/OTP code -- see
    docs/pr11-mfa-login-challenge-discovery.md SS5. auth_method/idp_org_id
    are carried through so a successful verification
    (mfa_service.verify_mfa_challenge) can call the existing
    generate_tokens() and produce a token identical in shape to what
    primary auth would have issued directly, had MFA not been required.

    saml_name_id/saml_session_index/organization_saml_config_id (PR11,
    SLO): same optional/default-None convention, carried through for the
    identical reason auth_method/idp_org_id are -- a SAML login for a
    user with personal MFA enabled doesn't reach generate_tokens (and
    therefore doesn't get a UserSession row written) until this
    challenge is verified; without threading these three through, that
    session would come out the other side with no SAML identity
    recorded on it at all, and an IdP-initiated LogoutRequest would have
    no way to find it. None for every non-SAML login, unaffected.
    """
    return _sign(
        {
            "type": "mfa_challenge",
            "user_id": user_id,
            "mfa_required": True,
            "auth_method": auth_method,
            "idp_org_id": idp_org_id,
            "saml_name_id": saml_name_id,
            "saml_session_index": saml_session_index,
            "organization_saml_config_id": organization_saml_config_id,
            "exp": datetime.utcnow() + timedelta(minutes=5),
            "jti": str(uuid.uuid4()),
        }
    )


def create_link_token(
    user_id: int,
    provider: str,
    provider_user_id: str,
    email: str,
    organization_sso_config_id: int | None = None,
    organization_saml_config_id: int | None = None,
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

    organization_saml_config_id is SAML PR6's exact analogue, populated
    only when the exchange came from a SAML login instead -- always None
    for every existing caller (OIDC and the 3-provider flow), so this is
    purely additive to the payload shape.
    """
    return _sign(
        {
            "type": "oauth_link",
            "user_id": user_id,
            "provider": provider,
            "provider_user_id": provider_user_id,
            "email": email,
            "organization_sso_config_id": organization_sso_config_id,
            "organization_saml_config_id": organization_saml_config_id,
            "idp_org_id": idp_org_id,
            "exp": datetime.utcnow() + timedelta(minutes=10),
            "jti": str(uuid.uuid4()),
        }
    )
