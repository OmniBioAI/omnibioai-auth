"""SAML SSO PR3+PR4+PR5: SP metadata endpoint (PR3), SP-initiated login
(PR4), and ACS/assertion validation (PR5). No identity linking, JIT
provisioning, JWT issuance from SAML, CRUD, admin UI, or SLO yet -- see
app/services/org_saml_service.py's module docstring for the full
roadmap and for PR5's own hard architectural boundary (why a
successfully validated assertion still cannot complete authentication
today).
"""
from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.core.jwt import create_saml_relay_state_token, decode_token
from app.db.session import get_db
from app.services import org_saml_service, org_service

router = APIRouter(prefix="/auth/saml", tags=["saml"])


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


@router.post("/{org_slug}/acs")
def saml_acs(
    org_slug: str,
    SAMLResponse: str = Form(...),
    RelayState: str | None = Form(None),
    db: Session = Depends(get_db),
):
    """Assertion Consumer Service (PR5) -- consumes the IdP's SAMLResponse
    from the PR4 login redirect. Form fields, not JSON: SAML's HTTP-POST
    binding is defined as application/x-www-form-urlencoded (same
    convention already established by routes_oauth_token.py's
    client_credentials grant, the one other form-encoded endpoint in
    this service).

    RelayState is verified BEFORE the SAMLResponse itself is touched --
    org/config resolution must be unforgeable and server-side first, so
    that org_saml_service.validate_saml_response is always called with
    the correct, already-verified OrganizationSAMLConfig (the trust
    anchor for signature validation), never one an attacker could steer
    by supplying an arbitrary org_slug alongside someone else's
    SAMLResponse.

    Error handling fails closed and stays generic on purpose: no
    certificate, no raw SAMLResponse, no assertion contents, and no
    internal exception detail from python3-saml is ever included in a
    response -- see org_saml_service.SAMLAssertionError's own docstring
    for why every validation failure collapses into one exception type
    before it ever reaches this route.

    PR5's own hard boundary: a SAMLResponse that fully validates still
    does not produce a JWT here -- see org_saml_service's module
    docstring and this function's own final HTTPException for why
    (persisting/linking the validated identity needs OAuthAccount schema
    work that is explicitly PR6/PR7 scope, not invented in this PR).
    """
    _org, config, relay_payload = _verify_saml_relay_state(db, org_slug, RelayState)

    try:
        identity = org_saml_service.validate_saml_response(
            org_slug, config, SAMLResponse, RelayState, relay_payload["request_id"],
        )
    except org_saml_service.SAMLAssertionError:
        raise HTTPException(400, "SAML authentication failed")

    if not identity.name_id:
        raise HTTPException(400, "SAML authentication failed")

    raise HTTPException(
        501,
        "SAML authentication is not yet available for this organization -- "
        "assertion validation succeeded, but account linking is not "
        "implemented in this deployment.",
    )
