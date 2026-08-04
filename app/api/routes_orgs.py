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
from app.schemas.role_admin import OrganizationRoleAssignment, RoleAssignRequest, RoleSummary
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

    updated = org_service.set_member_roles(db, target, new_roles, actor_user_id=int(user.get("sub")))
    return MemberRolesOut(user_id=updated.user_id, roles=sorted(r.name for r in updated.roles))


# ---------------------------------------------------------------------------
# Phase 3 PR3B: single-role add/remove + role catalog listing, alongside
# (not replacing) update_member_roles' full-replace PUT above. Same
# authorization as every other route in this file:
# require_org_permission_or_platform_admin(MANAGE_ORG) -- a platform admin
# can manage any organization's roles via the synthetic membership bypass
# (PR0.4), a real org_admin only their own, and a caller with neither gets
# the same 404 ("Organization not found") or 403 that dependency already
# produces for every other route here. No new authorization dependency
# was introduced for this PR.
# ---------------------------------------------------------------------------


@router.get("/{org_id}/roles", response_model=list[RoleSummary])
def list_org_roles(
    org_id: int,
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    # Role/Permission remain a single global catalog shared across every
    # organization (see db/models.py's own comment on membership_roles) --
    # this returns the same catalog every org draws from, not an org-
    # specific subset. No such subset concept exists in this schema, and
    # this PR does not invent one ("do not redesign RBAC").
    return [
        RoleSummary(id=r.id, name=r.name, description=r.description, permissions=sorted(p.name for p in r.permissions))
        for r in role_service.list_roles(db)
    ]


@router.get("/{org_id}/members/{user_id}/roles", response_model=OrganizationRoleAssignment)
def get_member_roles(
    org_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    target = org_service.get_membership(db, org_id, user_id)
    if not target:
        raise HTTPException(404, "User is not a member of this organization")
    return OrganizationRoleAssignment(
        organization_id=org_id, user_id=user_id, roles=sorted(r.name for r in target.roles)
    )


@router.post("/{org_id}/members/{user_id}/roles", response_model=OrganizationRoleAssignment, status_code=201)
def assign_member_role(
    org_id: int,
    user_id: int,
    body: RoleAssignRequest,
    db: Session = Depends(get_db),
    user=Depends(get_current_user),
    caller_membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    target = org_service.get_membership(db, org_id, user_id)
    if not target:
        raise HTTPException(404, "User is not a member of this organization")

    role = role_service.get_role_by_name(db, body.role)
    if not role:
        raise HTTPException(400, f"Unknown role: {body.role!r}")

    # Self-escalation guard, mirroring update_member_roles' own pattern
    # above: granting yourself an org role that adds a permission you
    # don't already hold in this org is rejected, even if you hold
    # manage_org over other members. Removing a role can only ever narrow
    # permissions, so no equivalent guard is needed on DELETE below.
    is_self = str(target.user_id) == str(user.get("sub"))
    if is_self:
        current_perms = org_service.permissions_for_membership(target)
        new_perms = role_service.permissions_for_roles([role])
        if not new_perms.issubset(current_perms):
            raise HTTPException(
                403,
                "Cannot assign yourself an org role that grants additional permissions",
            )

    org_service.add_member_role(db, target, role, actor_user_id=int(user.get("sub")))
    return OrganizationRoleAssignment(
        organization_id=org_id, user_id=user_id, roles=sorted(r.name for r in target.roles)
    )


@router.delete("/{org_id}/members/{user_id}/roles/{role_id}", status_code=204)
def remove_member_role(
    org_id: int,
    user_id: int,
    role_id: int,
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(require_org_permission_or_platform_admin(MANAGE_ORG)),
):
    target = org_service.get_membership(db, org_id, user_id)
    if not target:
        raise HTTPException(404, "User is not a member of this organization")

    role = role_service.get_role(db, role_id)
    if not role:
        raise HTTPException(404, "Role not found")

    if role not in target.roles:
        raise HTTPException(404, "Role is not assigned to this user in this organization")

    org_service.remove_member_role(db, target, role, actor_user_id=caller_membership.user_id)
