"""SAML SSO PR3+PR4: SP metadata endpoint (PR3) and SP-initiated login
(PR4). No ACS endpoint yet (PR5), no SLO (PR11) -- see
app/services/org_saml_service.py's module docstring for the full
roadmap.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.orm import Session

from app.core.jwt import create_saml_relay_state_token
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

    relay_state = create_saml_relay_state_token(org.id, config.id)
    try:
        redirect_url = org_saml_service.build_authn_request_url(org_slug, config, relay_state)
    except org_saml_service.SAMLLoginError as e:
        raise HTTPException(500, str(e))

    return RedirectResponse(redirect_url)
