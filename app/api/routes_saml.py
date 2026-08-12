"""SAML SSO PR3+PR4+PR5+PR6: SP metadata endpoint (PR3), SP-initiated login
(PR4), ACS/assertion validation (PR5), and identity linking (PR6). JIT
provisioning of brand-new users from an unrecognized SAML identity is
still PR7 scope -- see app/services/org_saml_service.py's module
docstring and _complete_saml_login's own docstring below for that
boundary, and for CRUD/admin UI/SLO's own separate roadmap slots.
"""
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.core.jwt import create_saml_relay_state_token, decode_token
from app.db.session import get_db
from app.services import oauth_service, org_saml_service, org_service
from app.services.auth_service import MFAEnrollmentRequiredError, generate_tokens_or_mfa_challenge

router = APIRouter(prefix="/auth/saml", tags=["saml"])


def _issue_tokens_or_challenge(db: Session, user, auth_method: str, idp_org_id: int | None = None) -> dict:
    """PR6: same wrapper shape as routes_sso.py/routes_oauth.py's own."""
    try:
        return generate_tokens_or_mfa_challenge(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
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


def _complete_saml_login(db: Session, org, config, identity) -> dict:
    """PR6: resolves a *validated* SAMLIdentity (see org_saml_service's own
    hard guarantee that this is never called with anything that hasn't
    passed OneLogin_Saml2_Auth.is_authenticated() first) to a real login
    outcome. Mirrors routes_sso.py's _complete_sso_flow deliberately
    closely -- same decision tree, reusing oauth_service.py's actual
    provider-agnostic functions rather than a parallel implementation:

      1. Already linked (an OAuthAccount row scoped to this exact
         organization_saml_config_id already exists) -> log in directly.
      2. Not linked, but an existing user account has this email -> never
         link silently (see oauth_service.link_oauth_to_existing_user's
         own reasoning); require the *same* password-confirmation flow
         POST /auth/link/confirm already provides for OIDC/OAuth.
      3. Neither -> PR6's own remaining hard boundary. Auto-creating a
         brand-new user purely from an IdP's say-so (JIT provisioning) is
         a materially bigger trust decision than linking an *existing*
         account, and is explicitly PR7 scope -- see org_saml_service's
         module docstring and OrganizationSAMLConfig's own class
         docstring. Still 501, not 200/400: the assertion and the
         identity it carries are both genuinely valid, this deployment
         just cannot complete authentication for a never-seen-before
         identity yet.

    This SP's identity model is NameID-based (declared NameIDFormat is
    "emailAddress" -- see org_saml_service's _NAME_ID_FORMAT), so
    identity.name_id doubles as both provider_user_id (the stable
    per-IdP identifier oauth_service scopes lookups by) and email (what
    find_user_by_email/OAuthAccount.email need) -- exactly the shape
    OrganizationSAMLConfig.attribute_mapping's own example ("email":
    "NameID") already documented. A NameID that isn't actually an email
    address is rejected outright rather than silently used as one: it
    would never coincidentally match a real user's email either, but a
    non-email string has no business landing in the `email` column or
    driving an email-collision check at all.
    """
    if "@" not in identity.name_id:
        raise HTTPException(400, "SAML authentication failed")
    email = identity.name_id

    linked_user = oauth_service.find_linked_user(
        db, "saml", identity.name_id, organization_saml_config_id=config.id
    )
    if linked_user:
        org_service.jit_provision_membership(db, org.id, linked_user.id)
        result = _issue_tokens_or_challenge(db, linked_user, auth_method="saml", idp_org_id=org.id)
        if result["mfa_required"]:
            return {"status": "mfa_required", "mfa_required": True, "challenge_token": result["challenge_token"], "methods": result["methods"]}
        return {"status": "ok", "access_token": result["access_token"], "refresh_token": result["refresh_token"], "token_type": "bearer"}

    existing_user = oauth_service.find_user_by_email(db, email)
    if existing_user:
        link_token = oauth_service.issue_link_confirmation(
            existing_user, "saml", identity.name_id, email,
            organization_saml_config_id=config.id, idp_org_id=org.id,
        )
        return {"status": "link_required", "link_token": link_token, "provider": "saml", "email": email}

    raise HTTPException(
        501,
        "SAML authentication is not yet available for new accounts in this "
        "organization -- assertion validation and identity linking "
        "succeeded, but automatic account provisioning is not implemented "
        "in this deployment.",
    )


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

    PR6 replaces PR5's original unconditional 501 with a real login
    outcome for a *recognized* identity (already linked, or a
    password-confirmed link to an existing account) -- see
    _complete_saml_login's own docstring for the full decision tree and
    for why a never-seen-before identity still stops at 501.
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
