from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, OrganizationSSOConfig
from app.db.session import get_db
from app.rbac import require_org_permission_or_platform_admin, require_permission
from app.schemas.org_sso import (
    OrgSSOConfigCreate,
    OrgSSOConfigOut,
    OrgSSOConfigUpdate,
    SSOOverrideRequest,
)
from app.services import org_sso_service

router = APIRouter(prefix="/orgs/{org_id}/sso", tags=["org-sso"])

MANAGE_SSO = "manage_sso"
# Phase 2 PR5. Deliberately require_permission (global, JWT-claim-based),
# not require_org_permission -- this is a platform-operator break-glass
# tool, not an org-admin capability, so it must work even if the org's
# own admin is the one locked out.
OVERRIDE_SSO_ENFORCEMENT = "override_sso_enforcement"


def _to_out(config: OrganizationSSOConfig) -> OrgSSOConfigOut:
    return OrgSSOConfigOut(
        issuer=config.issuer,
        client_id=config.client_id,
        provider_type=config.provider_type,
        allowed_domains=config.allowed_domains or [],
        status=config.status,
        created_at=config.created_at,
        updated_at=config.updated_at,
        enforced=bool(config.enforced),
        sso_override_active=config.sso_override_at is not None,
    )


def _get_or_404(db: Session, org_id: int) -> OrganizationSSOConfig:
    config = org_sso_service.get_sso_config(db, org_id)
    if not config:
        raise HTTPException(404, "No SSO configuration for this organization")
    return config


@router.post("", response_model=OrgSSOConfigOut, status_code=201)
async def create_sso_config(
    org_id: int,
    body: OrgSSOConfigCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    try:
        config = await org_sso_service.configure_sso(
            db, org_id, body.issuer, body.client_id, body.client_secret,
            body.allowed_domains, membership.user_id,
        )
    except org_sso_service.SSODiscoveryError as e:
        raise HTTPException(400, str(e))
    except ValueError as e:
        raise HTTPException(409, str(e))
    except RuntimeError as e:
        # crypto.encrypt() raises RuntimeError when CONFIG_ENCRYPTION_KEY
        # isn't set -- same handling as routes_config.py's update_config:
        # a deliberate 500 with a clear message, never a silently
        # plaintext-stored secret.
        raise HTTPException(500, str(e))
    return _to_out(config)


@router.get("", response_model=OrgSSOConfigOut)
def get_sso_config(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    return _to_out(_get_or_404(db, org_id))


@router.patch("", response_model=OrgSSOConfigOut)
async def update_sso_config(
    org_id: int,
    body: OrgSSOConfigUpdate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    config = _get_or_404(db, org_id)
    try:
        config = await org_sso_service.update_sso_config(
            db, config, membership.user_id,
            issuer=body.issuer,
            client_id=body.client_id,
            client_secret=body.client_secret,
            allowed_domains=body.allowed_domains,
        )
        # Applied after the issuer/client fields, on the freshest config
        # row, so it observes any status="active" reset an issuer change
        # above just performed -- not that a lockout-guard-passing org
        # would ever have a stale issuer, but ordering shouldn't matter
        # by accident.
        if body.enforced is not None and body.enforced != config.enforced:
            config = org_sso_service.set_enforced(db, config, body.enforced, membership.user_id)
    except org_sso_service.SSODiscoveryError as e:
        raise HTTPException(400, str(e))
    except ValueError as e:
        # set_enforced's lockout guard.
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    return _to_out(config)


@router.delete("", status_code=204)
def delete_sso_config(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    config = _get_or_404(db, org_id)
    org_sso_service.delete_sso_config(db, config)


# ---------------- BREAK-GLASS OVERRIDE (global-admin only) ----------------


@router.post("/override", response_model=OrgSSOConfigOut)
def override_sso_enforcement(
    org_id: int,
    body: SSOOverrideRequest,
    db: Session = Depends(get_db),
    user=Depends(require_permission(OVERRIDE_SSO_ENFORCEMENT)),
):
    config = _get_or_404(db, org_id)
    config = org_sso_service.set_sso_override(db, config, body.reason, int(user["sub"]))
    return _to_out(config)


@router.delete("/override", response_model=OrgSSOConfigOut)
def clear_sso_override(
    org_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_permission(OVERRIDE_SSO_ENFORCEMENT)),
):
    config = _get_or_404(db, org_id)
    config = org_sso_service.clear_sso_override(db, config)
    return _to_out(config)
