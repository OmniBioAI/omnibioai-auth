from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import Organization, OrganizationMembership, User
from app.db.session import get_db
from app.rbac import (
    MANAGE_ALL_ORGS,
    get_current_user,
    get_org_membership_or_platform_admin,
    require_org_permission_or_platform_admin,
)
from app.schemas.orgs import (
    InviteRequest,
    MemberOut,
    MemberRolesOut,
    MemberRolesUpdate,
    OrganizationCreate,
    OrganizationOut,
    OrganizationUpdate,
)
from app.services import org_service, role_service

router = APIRouter(prefix="/orgs", tags=["orgs"])

MANAGE_ORG = "manage_org"


def _org_out(org: Organization) -> OrganizationOut:
    return OrganizationOut(
        id=org.id,
        slug=org.slug,
        name=org.name,
        plan=org.plan,
        status=org.status,
        status_changed_at=org.status_changed_at,
        status_changed_reason=org.status_changed_reason,
        status_changed_by_user_id=org.status_changed_by_user_id,
    )


def _member_out(membership: OrganizationMembership, email: str) -> MemberOut:
    return MemberOut(
        user_id=membership.user_id,
        email=email,
        status=membership.status,
        roles=sorted(r.name for r in membership.roles),
    )


@router.post("", response_model=OrganizationOut, status_code=201)
def create_org(
    body: OrganizationCreate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
):
    if org_service.get_organization_by_slug(db, body.slug):
        raise HTTPException(409, "Organization slug already exists")
    creator = db.query(User).filter(User.id == int(user["sub"])).first()
    org = org_service.create_organization(db, body.name, body.slug, creator)
    return _org_out(org)


@router.get("", response_model=list[OrganizationOut])
def list_my_orgs(db: Session = Depends(get_db), user=Depends(get_current_user)):
    orgs = org_service.list_organizations_for_user(db, int(user["sub"]))
    return [_org_out(o) for o in orgs]


@router.get("/{org_id}", response_model=OrganizationOut)
def get_org(
    org_id: int,
    membership: OrganizationMembership = Depends(get_org_membership_or_platform_admin),
):
    return _org_out(membership.organization)


@router.patch("/{org_id}", response_model=OrganizationOut)
def update_org(
    org_id: int,
    body: OrganizationUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    # Phase 3 PR2: status changes (suspend/reactivate) are platform-admin
    # only, checked independently of the membership/MANAGE_ORG gate above
    # -- a real org_admin holds manage_org over their own org, but that
    # must keep meaning "can rename/manage this org," not "can suspend
    # it." membership shape alone can't distinguish a real org_admin from
    # PR0.4's synthetic platform-admin membership (that's by design), so
    # this checks the caller's own global permissions claim directly.
    if body.status is not None and MANAGE_ALL_ORGS not in (user.get("permissions") or []):
        raise HTTPException(403, "Only platform admins can change organization status")

    try:
        org = org_service.update_organization(
            db,
            membership.organization,
            body.name,
            status=body.status,
            status_reason=body.status_reason,
            actor_user_id=int(user["sub"]),
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _org_out(org)


@router.get("/{org_id}/members", response_model=list[MemberOut])
def list_members(
    org_id: int,
    db: Session = Depends(get_db),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    members = org_service.list_members(db, org_id)
    return [_member_out(m, m.user.email) for m in members]


@router.post("/{org_id}/invite", response_model=MemberOut, status_code=201)
def invite_member(
    org_id: int,
    body: InviteRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    inviter = db.query(User).filter(User.id == int(user["sub"])).first()
    invited = org_service.invite_member(db, membership.organization, body.email, inviter)
    if invited is None:
        raise HTTPException(404, "No account exists for that email yet")
    return _member_out(invited, body.email)


@router.put("/{org_id}/members/{user_id}/roles", response_model=MemberRolesOut)
def update_member_roles(
    org_id: int,
    user_id: int,
    body: MemberRolesUpdate,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    caller_membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    target = org_service.get_membership(db, org_id, user_id)
    if not target:
        raise HTTPException(404, "User is not a member of this organization")

    try:
        new_roles = role_service.resolve_roles(db, body.roles)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Self-escalation guard, mirroring routes_roles.py's existing pattern:
    # acting on your own org membership can only ever be neutral-or-narrowing
    # in effective permissions, never widening -- even if you hold
    # manage_org over other members.
    is_self = str(target.user_id) == str(user.get("sub"))
    if is_self:
        current_perms = org_service.permissions_for_membership(target)
        requested_perms = role_service.permissions_for_roles(new_roles)
        if not requested_perms.issubset(current_perms):
            raise HTTPException(
                403,
                "Cannot modify your own org roles to grant yourself additional permissions",
            )

    updated = org_service.set_member_roles(db, target, new_roles)
    return MemberRolesOut(user_id=updated.user_id, roles=sorted(r.name for r in updated.roles))
