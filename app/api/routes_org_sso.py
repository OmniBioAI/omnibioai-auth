from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OrganizationMembership, OrganizationSSOConfig
from app.db.session import get_db
from app.rbac import require_org_permission
from app.schemas.org_sso import OrgSSOConfigCreate, OrgSSOConfigOut, OrgSSOConfigUpdate
from app.services import org_sso_service

router = APIRouter(prefix="/orgs/{org_id}/sso", tags=["org-sso"])

MANAGE_SSO = "manage_sso"


def _to_out(config: OrganizationSSOConfig) -> OrgSSOConfigOut:
    return OrgSSOConfigOut(
        issuer=config.issuer,
        client_id=config.client_id,
        provider_type=config.provider_type,
        allowed_domains=config.allowed_domains or [],
        status=config.status,
        created_at=config.created_at,
        updated_at=config.updated_at,
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
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_SSO)),
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
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_SSO)),
):
    return _to_out(_get_or_404(db, org_id))


@router.patch("", response_model=OrgSSOConfigOut)
async def update_sso_config(
    org_id: int,
    body: OrgSSOConfigUpdate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_SSO)),
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
    except org_sso_service.SSODiscoveryError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    return _to_out(config)


@router.delete("", status_code=204)
def delete_sso_config(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission(MANAGE_SSO)),
):
    config = _get_or_404(db, org_id)
    org_sso_service.delete_sso_config(db, config)
