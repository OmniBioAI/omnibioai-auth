"""
OmniBioAI app.api.routes_organization_config.

Purpose:
    Defines HTTP route handlers for app.api.routes_organization_config, including get_provider_key, put_provider_key, delete_provider_key and reveal_provider_key.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.models import OrganizationMembership, User
from app.db.session import get_db
from app.rbac import require_org_permission_or_platform_admin
from app.schemas.organization_config import ProviderKeyIn, ProviderKeyOut, ProviderKeyRevealOut
from app.services import organization_config_service

# BYOK provider-key storage (design audit gap #4). Gated on manage_org --
# an org-wide, billing-adjacent infrastructure setting, the same
# administrative character as manage_billing/manage_teams, not a
# literature-API self-service action, so it is deliberately NOT one of
# the public literature:read/usage:read scopes a self-service key can
# be issued with (see routes_apikeys.py's PUBLIC_SCOPE_TO_PERMISSION).
router = APIRouter(prefix="/orgs/{org_id}/provider-keys", tags=["provider-keys"])

# M16: service-to-service only, shared-secret gated -- never reachable
# by a user or API-key token, the same shape routes_apikeys.py's own
# exchange_router already established for POST /auth/api-keys/exchange.
# Deliberately no org-membership/manage_org dependency: the question
# this endpoint answers is "does this organization have a key
# configured for this provider", not "may this particular caller manage
# it" -- any authenticated member of the org can trigger a
# /v1/literature/answers call that uses the org's own already-configured
# key, the same way any member can spend the org's own quota today.
# manage_org still gates *setting*/*clearing* the key above; using it is
# a different, already-answered question by the time a call gets here.
reveal_router = APIRouter(prefix="/internal/organizations/{org_id}/provider-keys", tags=["provider-keys"])

MANAGE_ORG = "manage_org"


def _to_out(db: Session, config) -> ProviderKeyOut:
    updated_by_email = None
    if config and config.updated_by_user_id:
        user = db.query(User).filter(User.id == config.updated_by_user_id).first()
        updated_by_email = user.email if user else None

    return ProviderKeyOut(
        provider=config.llm_provider if config else None,
        has_key=bool(config and config.llm_api_key_encrypted),
        updated_at=config.updated_at.isoformat() if config and config.updated_at else None,
        updated_by_email=updated_by_email,
    )


@router.get("", response_model=ProviderKeyOut)
def get_provider_key(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    return _to_out(db, organization_config_service.get_organization_config(db, org_id))


@router.put("/{provider}", response_model=ProviderKeyOut)
def put_provider_key(
    org_id: int,
    provider: str,
    body: ProviderKeyIn,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    try:
        config = organization_config_service.set_provider_key(
            db, org_id, provider, body.api_key, updated_by_user_id=membership.user_id,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        # crypto.encrypt() raises when CONFIG_ENCRYPTION_KEY isn't set --
        # a loud, deliberate 500, never a silently-dropped or plaintext-
        # stored credential (same contract routes_config.py's own
        # update_config endpoint follows for the platform-wide key).
        raise HTTPException(500, str(e))
    return _to_out(db, config)


@router.delete("/{provider}", response_model=ProviderKeyOut)
def delete_provider_key(
    org_id: int,
    provider: str,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    try:
        config = organization_config_service.clear_provider_key(
            db, org_id, provider, updated_by_user_id=membership.user_id,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    if config is None:
        raise HTTPException(404, f"No {provider} key is configured for this organization.")
    return _to_out(db, config)


@reveal_router.post("/{provider}/reveal", response_model=ProviderKeyRevealOut)
def reveal_provider_key(
    org_id: int,
    provider: str,
    db: Session = Depends(get_db),
    x_provider_key_reveal_secret: str = Header(default=""),
):
    """Gateway-only: decrypt this organization's stored key for `provider`
    for one outbound provider API call. Every failure is framed the
    same way exchange_api_key's own docstring explains: never leak
    *which* precondition failed (wrong secret vs. no key configured)
    beyond what the status code itself already implies.
    """
    expected = settings.PROVIDER_KEY_REVEAL_SECRET
    if not expected:
        raise HTTPException(503, "Provider key reveal is not configured")
    if not hmac.compare_digest(x_provider_key_reveal_secret.encode(), expected.encode()):
        raise HTTPException(403, "Forbidden")
    try:
        api_key = organization_config_service.reveal_provider_key(db, org_id, provider)
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    if api_key is None:
        raise HTTPException(404, f"No {provider} key is configured for this organization.")
    return ProviderKeyRevealOut(provider=provider, api_key=api_key)
