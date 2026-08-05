"""PR11.5.5 (Enterprise Organization MFA Policy). Structurally mirrors
app/api/routes_org_sso.py deliberately closely -- same CRUD/override
split, same permission split (org-scoped for CRUD, global for
override), same no-op-avoidance/actor-target audit shape. See
docs/pr11-mfa-org-policy-discovery.md for the full design and why
manage_sso/manage_all_orgs are reused here instead of a new
permission.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import OrganizationMFAPolicy, OrganizationMembership, User
from app.db.session import get_db
from app.rbac import require_org_permission_or_platform_admin, require_permission
from app.schemas.org_mfa import (
    OrgMFAOverrideRequest,
    OrgMFAPolicyCreate,
    OrgMFAPolicyOut,
    OrgMFAPolicyUpdate,
)
from app.services import mfa_service

router = APIRouter(prefix="/orgs/{org_id}/mfa-policy", tags=["org-mfa-policy"])

MANAGE_SSO = "manage_sso"
# PR11.5.5. Deliberately require_permission (global, JWT-claim-based),
# not require_org_permission -- same reasoning
# routes_org_sso.py's OVERRIDE_SSO_ENFORCEMENT already gives: a
# platform-operator break-glass tool, must work even if the org's own
# admin is the one locked out. Reuses the existing manage_all_orgs
# rather than introducing a parallel override_mfa_enforcement -- this
# PR is explicitly constrained to manage_sso/manage_all_orgs only, see
# the discovery doc SS6.
OVERRIDE_MFA_POLICY = "manage_all_orgs"


def _to_out(db: Session, policy: OrganizationMFAPolicy) -> OrgMFAPolicyOut:
    # PR11.5.6: a single, already-by-id lookup (never a list query) --
    # this is a one-org detail response, so no N+1 risk the way a list
    # endpoint would need to guard against. None if never enabled or the
    # user no longer exists, same "don't fabricate" convention every
    # other display-resolution field in this codebase already follows
    # (e.g. audit_service.resolve_display_fields).
    enabled_by_email = None
    if policy.enabled_by_user_id is not None:
        enabled_by = db.query(User).filter(User.id == policy.enabled_by_user_id).first()
        enabled_by_email = enabled_by.email if enabled_by else None

    return OrgMFAPolicyOut(
        required=bool(policy.required),
        created_at=policy.created_at,
        updated_at=policy.updated_at,
        enabled_at=policy.enabled_at,
        enabled_by_email=enabled_by_email,
        override_active=bool(policy.override_active),
        override_reason=policy.override_reason if policy.override_active else None,
    )


def _get_or_404(db: Session, org_id: int) -> OrganizationMFAPolicy:
    policy = mfa_service.get_org_mfa_policy(db, org_id)
    if not policy:
        raise HTTPException(404, "No MFA policy configured for this organization")
    return policy


@router.post("", response_model=OrgMFAPolicyOut, status_code=201)
def create_org_mfa_policy(
    org_id: int,
    body: OrgMFAPolicyCreate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    try:
        policy = mfa_service.create_org_mfa_policy(db, org_id, body.required, membership.user_id)
    except ValueError as e:
        raise HTTPException(409, str(e))
    return _to_out(db, policy)


@router.get("", response_model=OrgMFAPolicyOut)
def get_org_mfa_policy(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    return _to_out(db, _get_or_404(db, org_id))


@router.patch("", response_model=OrgMFAPolicyOut)
def update_org_mfa_policy(
    org_id: int,
    body: OrgMFAPolicyUpdate,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_SSO)),
):
    policy = _get_or_404(db, org_id)
    if body.required is not None:
        policy = mfa_service.set_org_mfa_required(
            db, policy, body.required, membership.user_id, reason=body.reason
        )
    return _to_out(db, policy)


# ---------------- BREAK-GLASS OVERRIDE (global-admin only) ----------------


@router.post("/override", response_model=OrgMFAPolicyOut)
def override_org_mfa_policy(
    org_id: int,
    body: OrgMFAOverrideRequest,
    db: Session = Depends(get_db),
    user=Depends(require_permission(OVERRIDE_MFA_POLICY)),
):
    policy = _get_or_404(db, org_id)
    policy = mfa_service.set_org_mfa_override(db, policy, body.reason, int(user["sub"]))
    return _to_out(db, policy)


@router.delete("/override", response_model=OrgMFAPolicyOut)
def clear_org_mfa_policy_override(
    org_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_permission(OVERRIDE_MFA_POLICY)),
):
    policy = _get_or_404(db, org_id)
    policy = mfa_service.clear_org_mfa_override(db, policy, actor_user_id=int(user["sub"]))
    return _to_out(db, policy)
