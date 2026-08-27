"""PR8 (SAML Organization Configuration CRUD). Structurally mirrors
app/api/routes_org_sso.py deliberately closely -- same permission
(manage_sso, reused rather than a parallel manage_saml -- see
app/core/permission_names.py's own comment on that entry), same
platform-admin-aware dependency, same 404/409 shape, same "never expose
internal DB errors" posture.

#263: OrganizationSAMLConfig now has an `enforced`-style enforcement
flag with a lockout guard (org_saml_service.set_enforced), the same as
OrganizationSSOConfig/OrganizationMFAPolicy -- this module's own PATCH
endpoint below applies it, mirroring routes_org_sso.py's identical
"call set_enforced only if changed" pattern.

#67: this module now also has a break-glass override endpoint, ported
from routes_org_sso.py's identical one. Deliberately reuses that
module's OVERRIDE_SSO_ENFORCEMENT permission and SSOOverrideRequest
schema as-is rather than minting SAML-specific equivalents -- the rule
being followed, made explicit here so the next IdP type has a clear
precedent to extend: permissions and request/response shapes are
shared across SSO mechanisms (they're provider-agnostic capabilities --
"suspend enforcement, org-scoped, global-admin-only" means the same
thing regardless of protocol), while audit events stay provider-
specific (SAML_OVERRIDE_CREATED/REMOVED, not a reuse of
SSO_OVERRIDE_CREATED/REMOVED -- see audit_service.py's own comment),
since an audit trail needs to identify which config was actually
affected.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.routes_org_sso import OVERRIDE_SSO_ENFORCEMENT
from app.db.models import OrganizationMembership, OrganizationSAMLConfig
from app.db.session import get_db
from app.rbac import require_org_permission_or_platform_admin, require_permission
from app.schemas.org_saml import (
    OrgSAMLConfigCreate,
    OrgSAMLConfigOut,
    OrgSAMLConfigUpdate,
)
from app.schemas.org_sso import SSOOverrideRequest
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
        slo_url=config.slo_url,
        allowed_domains=config.allowed_domains or [],
        enforced=bool(config.enforced),
        sso_override_active=config.sso_override_at is not None,
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
            body.attribute_mapping, body.allowed_domains, membership.user_id,
            slo_url=body.slo_url,
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
            slo_url=body.slo_url,
            allowed_domains=body.allowed_domains,
        )
        # #263: applied after the other fields, on the freshest config row
        # -- same ordering/reasoning routes_org_sso.py's identical PATCH
        # endpoint already established for OIDC.
        if body.enforced is not None and body.enforced != config.enforced:
            config = org_saml_service.set_enforced(db, config, body.enforced, membership.user_id)
    except org_saml_service.SAMLConfigValidationError as e:
        raise HTTPException(422, str(e))
    except ValueError as e:
        # set_enforced's lockout guard.
        raise HTTPException(400, str(e))
    return _to_out(config)


@router.delete("", status_code=204)
def delete_saml_config(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    config = _get_or_404(db, org_id)
    org_saml_service.delete_saml_config(db, config)


# ---------------- BREAK-GLASS OVERRIDE (global-admin only) ----------------
# #67: mirrors routes_org_sso.py's identical endpoints -- same permission,
# same request schema, same response shape. See this module's own
# docstring for the shared-permission/provider-specific-audit-event rule.


@router.post("/override", response_model=OrgSAMLConfigOut)
def override_saml_enforcement(
    org_id: int,
    body: SSOOverrideRequest,
    db: Session = Depends(get_db),
    user=Depends(require_permission(OVERRIDE_SSO_ENFORCEMENT)),
):
    config = _get_or_404(db, org_id)
    config = org_saml_service.set_saml_override(db, config, body.reason, int(user["sub"]))
    return _to_out(config)


@router.delete("/override", response_model=OrgSAMLConfigOut)
def clear_saml_override(
    org_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_permission(OVERRIDE_SSO_ENFORCEMENT)),
):
    config = _get_or_404(db, org_id)
    config = org_saml_service.clear_saml_override(db, config, actor_user_id=int(user["sub"]))
    return _to_out(config)
