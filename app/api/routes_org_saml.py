"""PR8 (SAML Organization Configuration CRUD). Structurally mirrors
app/api/routes_org_sso.py deliberately closely -- same permission
(manage_sso, reused rather than a parallel manage_saml -- see
app/core/permission_names.py's own comment on that entry), same
platform-admin-aware dependency, same 404/409 shape, same "never expose
internal DB errors" posture. No override/break-glass endpoint here:
OrganizationSAMLConfig has no `enforced`-style enforcement flag with a
lockout guard the way OrganizationSSOConfig/OrganizationMFAPolicy do, so
there is nothing for a break-glass bypass to suspend.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, OrganizationSAMLConfig
from app.db.session import get_db
from app.rbac import require_org_permission_or_platform_admin
from app.schemas.org_saml import (
    OrgSAMLConfigCreate,
    OrgSAMLConfigOut,
    OrgSAMLConfigUpdate,
)
from app.services import org_saml_service

router = APIRouter(prefix="/orgs/{org_id}/saml", tags=["org-saml"])

MANAGE_SSO = "manage_sso"


def _to_out(config: OrganizationSAMLConfig) -> OrgSAMLConfigOut:
    return OrgSAMLConfigOut(
        entity_id=config.entity_id,
        sso_url=config.sso_url,
        x509_certificate=config.x509_certificate,
        attribute_mapping=config.attribute_mapping,
        enabled=bool(config.enabled),
        status=config.status,
        created_at=config.created_at,
        updated_at=config.updated_at,
    )


def _get_or_404(db: Session, org_id: int) -> OrganizationSAMLConfig:
    config = org_saml_service.get_saml_config(db, org_id)
    if not config:
        raise HTTPException(404, "No SAML configuration for this organization")
    return config


@router.post("", response_model=OrgSAMLConfigOut, status_code=201)
def create_saml_config(
    org_id: int,
    body: OrgSAMLConfigCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    try:
        config = org_saml_service.create_saml_config(
            db, org_id, body.entity_id, body.sso_url, body.x509_certificate,
            body.attribute_mapping, membership.user_id,
        )
    except org_saml_service.SAMLConfigValidationError as e:
        raise HTTPException(422, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _to_out(config)


@router.get("", response_model=OrgSAMLConfigOut)
def get_saml_config(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    return _to_out(_get_or_404(db, org_id))


@router.patch("", response_model=OrgSAMLConfigOut)
def update_saml_config(
    org_id: int,
    body: OrgSAMLConfigUpdate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    config = _get_or_404(db, org_id)
    try:
        config = org_saml_service.update_saml_config(
            db, config, membership.user_id,
            entity_id=body.entity_id,
            sso_url=body.sso_url,
            x509_certificate=body.x509_certificate,
            attribute_mapping=body.attribute_mapping,
            enabled=body.enabled,
            status=body.status,
        )
    except org_saml_service.SAMLConfigValidationError as e:
        raise HTTPException(422, str(e))
    return _to_out(config)


@router.delete("", status_code=204)
def delete_saml_config(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    config = _get_or_404(db, org_id)
    org_saml_service.delete_saml_config(db, config)
