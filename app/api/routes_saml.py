"""SAML SSO PR3+PR4+PR5+PR6+PR7+PR11: SP metadata endpoint (PR3),
SP-initiated login (PR4), ACS/assertion validation (PR5), identity
linking (PR6), JIT provisioning of brand-new users (PR7), and Single
Logout (PR11) -- see app/services/org_saml_service.py's module
docstring, particularly its own "PR11: Single Logout (SLO)" section, for
the full python3-saml-verified design this file's two SLO routes below
implement. CRUD API (PR8) and admin UI (PR9) live in
routes_org_saml.py/omnibioai-control-center respectively.
"""
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import token_revocation
from app.core.jwt import (
    create_saml_relay_state_token,
    create_saml_slo_relay_state_token,
    decode_token,
)
from app.db.session import get_db
from app.schemas.auth import LogoutRequest
from app.services import (
    auth_service,
    oauth_service,
    org_saml_service,
    org_service,
    session_service,
)
from app.services.auth_service import (
    MFAEnrollmentRequiredError,
    generate_tokens_or_mfa_challenge,
)

router = APIRouter(prefix="/auth/saml", tags=["saml"])


def _issue_tokens_or_challenge(
    db: Session, user, auth_method: str, idp_org_id: int | None = None,
    saml_name_id: str | None = None, saml_session_index: str | None = None,
    organization_saml_config_id: int | None = None,
) -> dict:
    """PR6: same wrapper shape as routes_sso.py/routes_oauth.py's own.

    PR11 (SLO): saml_name_id/saml_session_index/organization_saml_
    config_id are threaded straight through to generate_tokens_or_mfa_
    challenge -- this is the one place every SAML login (already-linked
    or freshly JIT-provisioned, MFA-gated or not) funnels through, so
    every resulting session gets its SAML identity recorded on it by
    construction, the same reasoning idp_org_id already relies on here.
    """
    try:
        return generate_tokens_or_mfa_challenge(
            db, user, auth_method=auth_method, idp_org_id=idp_org_id,
            saml_name_id=saml_name_id, saml_session_index=saml_session_index,
            organization_saml_config_id=organization_saml_config_id,
        )
    except MFAEnrollmentRequiredError:
        raise HTTPException(403, detail={
            "error": "mfa_enrollment_required",
            "message": "Your organization requires MFA enrollment",
        })


@router.get("/{org_slug}/metadata")
def sp_metadata(org_slug: str, db: Session = Depends(get_db)):
    """Public, unauthenticated -- same posture as GET /auth/sso/discover
    and GET /auth/sso/{org_slug}/login: an external IdP administrator,
    not an OmniBioAI user, is the intended caller, and there is no
    identity to authenticate at this point in the SAML setup flow (this
    document is what lets that setup flow start at all).

    404s for an unknown org_slug, same precedent sso_login already
    establishes for this URL shape. Unlike that route, this one
    deliberately does NOT also require an OrganizationSAMLConfig row to
    exist -- see org_saml_service's module docstring for why: this
    document is what makes creating that row possible in the first
    place, not something that depends on it already existing.
    """
    org = org_service.get_organization_by_slug(db, org_slug)
    if not org:
        raise HTTPException(404, "Unknown organization")

    try:
        metadata = org_saml_service.build_sp_metadata(org_slug)
    except org_saml_service.SAMLMetadataError as e:
        raise HTTPException(500, str(e))

    return Response(content=metadata, media_type=org_saml_service.SP_METADATA_CONTENT_TYPE)


@router.get("/{org_slug}/login")
def saml_login(org_slug: str, db: Session = Depends(get_db)):
    """SP-initiated SAML login (PR4). Same org-resolution and 404 posture
    as GET /auth/sso/{org_slug}/login: a single generic 404 whether the
    org doesn't exist, has no OrganizationSAMLConfig, or has one that
    isn't active, so a caller can never distinguish "no SAML" from "SAML
    not yet active" from "unknown org" by response shape alone (same
    enumeration-resistance reasoning sso_login's own precedent
    establishes).

    organization_id/organization_saml_config_id bound into the RelayState
    below are always the server-resolved values (org.id, config.id) --
    never anything from the request -- so a future ACS handler (PR5) can
    verify the callback's RelayState commits to the same organization/
    config this login actually started with, without trusting org_slug
    (or any other client-supplied value) a second time at that point.
    """
    org = org_service.get_organization_by_slug(db, org_slug)
    if not org:
        raise HTTPException(404, "Unknown organization")

    config = org_saml_service.get_saml_config(db, org.id)
    if not config or config.status != "active":
        raise HTTPException(404, "SAML SSO is not configured for this organization")

    try:
        redirect_url = org_saml_service.build_authn_request_url(
            org_slug, config,
            lambda request_id: create_saml_relay_state_token(org.id, config.id, request_id),
        )
    except org_saml_service.SAMLLoginError as e:
        raise HTTPException(500, str(e))

    return RedirectResponse(redirect_url)


def _verify_saml_relay_state(db: Session, org_slug: str, relay_state: str | None):
    """Returns (org, config, payload) resolved from a validated
    RelayState. Raises HTTPException on any mismatch. Mirrors
    routes_sso.py's _verify_sso_state exactly: the org/config actually
    used for SAML validation always come from the *RelayState*
    (organization_id/organization_saml_config_id, signed and
    unforgeable at /login time), never re-derived from the caller-
    supplied org_slug or anything in the IdP's own SAMLResponse --
    org_slug is only used as a consistency check against what the
    RelayState already committed to at /login time.
    """
    if not relay_state:
        raise HTTPException(400, "Missing RelayState")
    try:
        payload = decode_token(relay_state)
    except Exception:
        raise HTTPException(400, "Invalid or expired SAML RelayState")
    if payload.get("type") != "saml_relay_state":
        raise HTTPException(400, "Invalid SAML RelayState")

    org = org_service.get_organization_by_slug(db, org_slug)
    if not org or payload.get("organization_id") != org.id:
        raise HTTPException(400, "SAML RelayState does not match this organization")

    config = org_saml_service.get_saml_config(db, org.id)
    if not config or config.id != payload.get("organization_saml_config_id") or config.status != "active":
        raise HTTPException(400, "This organization's SAML configuration is no longer valid")

    return org, config, payload


def _login_or_challenge_result(db: Session, user, org_id: int, identity, config) -> dict:
    """Shared MFA-aware success shape for both the 'already linked' and
    the 'freshly JIT-provisioned' branches below -- same choke point
    (_issue_tokens_or_challenge -> generate_tokens_or_mfa_challenge) and
    the exact same response shape routes_sso.py/routes_oauth.py's own
    OIDC/OAuth callers already produce. A SAML JIT user follows this
    identical path -- there is no SAML-specific token format and no way
    for either branch to skip the MFA decision.

    PR11 (SLO): `identity`/`config` -- both already server-verified
    before this function is ever reached, same as everywhere else in
    this file -- are what let the resulting session (or MFA challenge
    token) carry identity.name_id/identity.session_index/config.id, so
    an IdP-initiated LogoutRequest can later find it.
    """
    result = _issue_tokens_or_challenge(
        db, user, auth_method="saml", idp_org_id=org_id,
        saml_name_id=identity.name_id, saml_session_index=identity.session_index,
        organization_saml_config_id=config.id,
    )
    if result["mfa_required"]:
        return {"status": "mfa_required", "mfa_required": True, "challenge_token": result["challenge_token"], "methods": result["methods"]}
    return {"status": "ok", "access_token": result["access_token"], "refresh_token": result["refresh_token"], "token_type": "bearer"}


def _complete_saml_login(db: Session, org, config, identity) -> dict:
    """PR6+PR7: resolves a *validated* SAMLIdentity (see org_saml_service's
    own hard guarantee that this is never called with anything that
    hasn't passed OneLogin_Saml2_Auth.is_authenticated() first) to a real
    login outcome. `org`/`config` are themselves already server-verified
    by _verify_saml_relay_state before this function is ever reached --
    never re-derived from org_slug, RelayState contents without signature
    verification, or anything client-supplied -- so every branch below
    inherits that same trust boundary for free. Mirrors routes_sso.py's
    _complete_sso_flow deliberately closely -- same decision tree, reusing
    oauth_service.py's actual provider-agnostic functions rather than a
    parallel implementation:

      1. Already linked (an OAuthAccount row scoped to this exact
         organization_saml_config_id already exists) -> log in directly.
      2. Not linked, but an existing user account has this email -> never
         link silently (see oauth_service.link_oauth_to_existing_user's
         own reasoning); require the *same* password-confirmation flow
         POST /auth/link/confirm already provides for OIDC/OAuth.
      3. Neither -> PR7: JIT-provision a brand-new user. Reuses
         create_user_with_oauth (User + OAuthAccount in one commit,
         provider="saml") + org_service.jit_provision_membership exactly
         as OIDC's own new-user branch does -- no SAML-specific user
         schema, no SAML-specific role, no SAML-specific token format.

    This SP's identity model is NameID-based (declared NameIDFormat is
    "emailAddress" -- see org_saml_service's _NAME_ID_FORMAT), so
    identity.name_id doubles as both provider_user_id (the stable
    per-IdP identifier oauth_service scopes lookups by) and email (what
    find_user_by_email/OAuthAccount.email/the new User row need) --
    exactly the shape OrganizationSAMLConfig.attribute_mapping's own
    example ("email": "NameID") already documented. A NameID that isn't
    actually an email address is rejected outright rather than silently
    used as one. `identity.attributes` is not read anywhere in this
    function: attribute_mapping-driven extraction (first/last/display
    name) is still not part of this codebase's contract anywhere (PR5's
    own docstring: "no attribute extraction/processing exists yet"), and
    `User` itself has no such columns for any provider today -- there is
    nothing trustworthy-and-
    appropriate left to populate beyond email, matching OIDC/OAuth's own
    identical `create_user_with_oauth` defaults exactly (hashed_password=
    None, status="active", no profile fields at all).

    `identity.session_index` (PR11, SLO): unlike attributes, this IS now
    read -- by _login_or_challenge_result below, which threads it (and
    identity.name_id, config.id) through to generate_tokens_or_mfa_
    challenge so the resulting UserSession row can be found again by an
    IdP-initiated LogoutRequest. Not used for any identity-resolution
    decision here, same as before -- purely carried through for that one
    write.

    Race handling (PR7): two concurrent requests that both pass the
    find_linked_user/find_user_by_email checks above with the SAME NameID
    (two IdP round-trips racing) or the SAME email (a SAML JIT racing
    another SAML/OIDC/OAuth signup for that address) resolve to a single
    winner via the database's own uniqueness constraints -- User.email's
    UNIQUE index and OAuthAccount's uq_oauth_provider_saml_account -- not
    a process-local lock. The loser's create_user_with_oauth raises
    IntegrityError; caught, rolled back, and the *entire* decision tree
    above is re-run once against the now-committed winner's rows, so the
    loser correctly falls into whichever branch is now true (already
    linked, if the SAME identity won; link_required, if a DIFFERENT
    identity happened to share the email) rather than a raw 500 or a
    second, duplicate user. Mirrors interaction_service.persist_
    interaction's own catch-IntegrityError-and-re-resolve idiom, this
    codebase's only other precedent for this exact class of race. Bounded
    to one retry: a second failure is not a recognized race (both
    resolution paths were re-checked and still found nothing) and is
    left to propagate as a fail-closed 500 rather than looping.
    """
    if "@" not in identity.name_id:
        raise HTTPException(400, "SAML authentication failed")
    email = identity.name_id

    for _attempt in range(2):
        linked_user = oauth_service.find_linked_user(
            db, "saml", identity.name_id, organization_saml_config_id=config.id
        )
        if linked_user:
            org_service.jit_provision_membership(db, org.id, linked_user.id)
            return _login_or_challenge_result(db, linked_user, org.id, identity, config)

        existing_user = oauth_service.find_user_by_email(db, email)
        if existing_user:
            link_token = oauth_service.issue_link_confirmation(
                existing_user, "saml", identity.name_id, email,
                organization_saml_config_id=config.id, idp_org_id=org.id,
            )
            return {"status": "link_required", "link_token": link_token, "provider": "saml", "email": email}

        try:
            new_user = oauth_service.create_user_with_oauth(
                db, "saml", identity.name_id, email, organization_saml_config_id=config.id,
            )
        except IntegrityError:
            db.rollback()
            continue

        org_service.jit_provision_membership(db, org.id, new_user.id)
        return _login_or_challenge_result(db, new_user, org.id, identity, config)

    raise HTTPException(500, "SAML authentication failed")


@router.post("/{org_slug}/acs")
def saml_acs(
    org_slug: str,
    SAMLResponse: str = Form(...),
    RelayState: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Assertion Consumer Service (PR5, extended by PR6) -- consumes the
    IdP's SAMLResponse from the PR4 login redirect. Form fields, not
    JSON: SAML's HTTP-POST binding is defined as
    application/x-www-form-urlencoded (same convention already
    established by routes_oauth_token.py's client_credentials grant, the
    one other form-encoded endpoint in this service).

    RelayState is verified BEFORE the SAMLResponse itself is touched --
    org/config resolution must be unforgeable and server-side first, so
    that org_saml_service.validate_saml_response is always called with
    the correct, already-verified OrganizationSAMLConfig (the trust
    anchor for signature validation), never one an attacker could steer
    by supplying an arbitrary org_slug alongside someone else's
    SAMLResponse. The same already-verified `config` -- never anything
    re-derived from the request -- is what _complete_saml_login below
    scopes every identity lookup/link by, too.

    Error handling fails closed and stays generic on purpose: no
    certificate, no raw SAMLResponse, no assertion contents, and no
    internal exception detail from python3-saml is ever included in a
    response -- see org_saml_service.SAMLAssertionError's own docstring
    for why every validation failure collapses into one exception type
    before it ever reaches this route.

    PR6+PR7 together replace PR5's original unconditional 501 with a real
    login outcome for every case: an already-linked identity, a
    password-confirmed link to an existing account, or (PR7) JIT
    provisioning of a brand-new user -- see _complete_saml_login's own
    docstring for the full decision tree, its race handling, and its
    attribute trust model.
    """
    org, config, relay_payload = _verify_saml_relay_state(db, org_slug, RelayState)

    try:
        identity = org_saml_service.validate_saml_response(
            org_slug, config, SAMLResponse, RelayState, relay_payload["request_id"],
        )
    except org_saml_service.SAMLAssertionError:
        raise HTTPException(400, "SAML authentication failed")

    if not identity.name_id:
        raise HTTPException(400, "SAML authentication failed")

    return _complete_saml_login(db, org, config, identity)


# ── PR11: Single Logout (SLO) ────────────────────────────────────────────


@router.post("/{org_slug}/logout")
def saml_logout(org_slug: str, req: LogoutRequest, db: Session = Depends(get_db)):
    """SP-initiated logout (PR11). Same request shape as the existing
    POST /auth/logout (app/schemas/auth.py's LogoutRequest, unchanged)
    -- the refresh_token itself is the proof of the session being ended,
    exactly as that route already relies on, so this needs no separate
    authentication dependency of its own.

    Always performs the same local logout POST /auth/logout already
    does -- revoke the refresh-token family (auth_service.revoke_token,
    unmodified), mark its UserSession revoked, best-effort blacklist the
    access token if supplied (token_revocation.blacklist_access_token,
    the same function /auth/logout itself now calls, PR11 promoted it
    out of routes_auth.py's own private scope for exactly this reuse) --
    regardless of org_slug, and regardless of whether this session even
    is a SAML one. org_slug only matters for the one thing this route
    adds beyond /auth/logout: if the session being logged out really was
    a SAML login for *this* org_slug's own config (session.
    organization_saml_config_id must equal the org_slug-resolved
    config's id -- never trusted from org_slug alone, the same
    "server-resolved, not client-asserted" discipline every other org/
    config check in this file already applies), and that config has a
    configured slo_url, the response additionally carries
    idp_logout_url: a redirect the caller can navigate the browser to,
    completing IdP-side logout too. Every other case (non-SAML session,
    session belongs to a different org's config, no slo_url configured)
    degrades to the exact same {"message": "Logged out"} shape
    /auth/logout already returns -- purely additive, never a stricter or
    different contract for what is still fundamentally a local logout.

    Deliberately does not also send the policy:invalidate broadcast
    /auth/logout's own _publish_invalidation performs -- a disclosed
    simplification (a downstream cache-freshness optimization, not a
    security boundary; that cache entry still expires on its own TTL),
    not an oversight. See this PR's own report.
    """
    session = auth_service.get_session_for_refresh_token(db, req.refresh_token)

    auth_service.revoke_token(db, req.refresh_token)
    if req.access_token:
        token_revocation.blacklist_access_token(req.access_token)

    idp_logout_url = None
    if session and session.saml_name_id and session.organization_saml_config_id:
        org = org_service.get_organization_by_slug(db, org_slug)
        config = org_saml_service.get_saml_config(db, org.id) if org else None
        if (
            org is not None and config is not None
            and config.id == session.organization_saml_config_id
            and config.status == "active"
        ):
            idp_logout_url = org_saml_service.build_logout_request_url(
                org_slug, config, session.saml_name_id, session.saml_session_index,
                lambda request_id: create_saml_slo_relay_state_token(org.id, config.id, request_id),
            )

    if idp_logout_url:
        return {"message": "Logged out", "idp_logout_url": idp_logout_url}
    return {"message": "Logged out"}


@router.get("/{org_slug}/slo")
def saml_slo(
    org_slug: str,
    request: Request,
    SAMLRequest: str | None = None,
    SAMLResponse: str | None = None,
    RelayState: str | None = None,
    SigAlg: str | None = None,
    Signature: str | None = None,
    db: Session = Depends(get_db),
):
    """Single Logout Service (PR11) -- one endpoint handling both
    directions of SLO, mirroring OneLogin_Saml2_Auth.process_slo's own
    internal dispatch (verified by reading it directly, then
    decomposed the same way build_authn_request_url already decomposed
    .login() -- see org_saml_service.py's validate_slo_logout_request/
    validate_slo_logout_response docstrings for why): a query string
    carrying SAMLRequest is an unsolicited, IdP-initiated LogoutRequest;
    one carrying SAMLResponse is the IdP's reply to a LogoutRequest THIS
    SP sent (the SP-initiated round trip POST .../logout's own
    idp_logout_url starts).

    GET, not POST: python3-saml only supports SLO over HTTP-Redirect
    binding (query-string parameters) -- verified directly against the
    installed library, which raises "Only supported HTTP_REDIRECT
    Binding" for anything else. See org_saml_service.py's own "PR11:
    Single Logout" module comment for the full verification.

    org_slug resolves the trusted org/config exactly as saml_login/
    saml_acs above do -- never anything else. A LogoutRequest/
    LogoutResponse arriving here is only ever validated against THIS
    org's own config.x509_certificate/entity_id (org_saml_service.
    _slo_settings_dict), so a message genuinely signed for a different
    org's IdP fails signature/issuer validation here, the same
    cross-org isolation _verify_saml_relay_state already establishes
    for login/ACS -- there is no separate "which org does this belong
    to" trust decision for SLO to get wrong.
    """
    org = org_service.get_organization_by_slug(db, org_slug)
    if not org:
        raise HTTPException(404, "Unknown organization")

    config = org_saml_service.get_saml_config(db, org.id)
    if not config or config.status != "active":
        raise HTTPException(404, "SAML SSO is not configured for this organization")

    query_string = request.url.query

    if SAMLRequest:
        try:
            identity = org_saml_service.validate_slo_logout_request(
                org_slug, config, SAMLRequest, RelayState, SigAlg, Signature, query_string,
            )
        except org_saml_service.SAMLLogoutError:
            raise HTTPException(400, "SAML logout failed")

        # config.id scopes this lookup to THIS org's own SAML config --
        # the same isolation session_service.find_active_by_saml_
        # identity's own docstring requires: a NameID that happens to
        # match under a different org's config can never be found (let
        # alone revoked) by a LogoutRequest validated against this one.
        sessions = session_service.find_active_by_saml_identity(
            db, config.id, identity.name_id, identity.session_index,
        )
        for session in sessions:
            session_service.revoke(db, session.session_id, session_service.REASON_USER_LOGOUT)
        db.commit()

        try:
            redirect_url = org_saml_service.build_slo_logout_response_redirect(
                org_slug, config, identity.request_id,
            )
        except org_saml_service.SAMLLogoutError:
            raise HTTPException(400, "SAML logout failed")
        return RedirectResponse(redirect_url)

    if SAMLResponse:
        # Mirrors _verify_saml_relay_state's own RelayState-first
        # discipline: the request_id this response's InResponseTo is
        # checked against comes only from a RelayState this SP itself
        # signed when it sent the original LogoutRequest (POST
        # .../logout's idp_logout_url) -- never from anything else in
        # the request.
        if not RelayState:
            raise HTTPException(400, "Missing RelayState")
        try:
            relay_payload = decode_token(RelayState)
        except Exception:
            raise HTTPException(400, "Invalid or expired SAML RelayState")
        if relay_payload.get("type") != "saml_slo_relay_state":
            raise HTTPException(400, "Invalid SAML RelayState")
        if (
            relay_payload.get("organization_id") != org.id
            or relay_payload.get("organization_saml_config_id") != config.id
        ):
            raise HTTPException(400, "SAML RelayState does not match this organization")

        try:
            org_saml_service.validate_slo_logout_response(
                org_slug, config, SAMLResponse, RelayState, relay_payload["request_id"],
                SigAlg, Signature, query_string,
            )
        except org_saml_service.SAMLLogoutError:
            raise HTTPException(400, "SAML logout failed")

        # The local session was already revoked in POST .../logout,
        # before this SP ever redirected the browser to the IdP -- this
        # branch only confirms the IdP's own reply is genuine.
        return {"message": "Logged out"}

    raise HTTPException(400, "Missing SAMLRequest or SAMLResponse")
