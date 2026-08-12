"""SAML SSO PR3: SP metadata endpoint only. No login/ACS endpoint exists
yet (PR4/PR5), no SLO (PR11) -- see app/services/org_saml_service.py's
module docstring for the full roadmap and for why metadata is the first
piece implemented.
"""
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session

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
