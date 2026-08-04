"""PR7 (Enterprise IAM Foundation): Organization Role Assignment API.

The first consumer of PR4's Permission Registry, PR5's read API, and PR6's
RBAC management layer from the organization side. Deliberately a new,
additive `/organizations/{organization_id}/...` surface, not a modification
of the legacy `/orgs/{org_id}/...` endpoints in routes_orgs.py (which stay
completely untouched) -- same "parallel, richer, purpose-specific surface"
pattern this codebase already used for /platform/roles alongside /roles
(Phase 3 PR3B) and /platform/permissions alongside nothing (PR5/PR6). The
legacy /orgs endpoints only ever return role/permission *names*; this
surface returns full Permission Registry metadata per role/permission.

No new authorization model: every route below reuses
require_org_permission_or_platform_admin(MANAGE_ORG) -- the exact
dependency routes_orgs.py already uses for every member/role-management
route, unmodified. app/rbac.py's get_org_membership_or_platform_admin
resolves its org_id from a path parameter literally named `org_id`
(FastAPI binds dependency parameters to path parameters by name); since
this PR's paths use `{organization_id}` instead (per spec), a thin local
wrapper below renames the parameter and delegates -- it changes no
authorization logic, it only relabels which path segment supplies it.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY
from app.db.models import OrganizationMembership
from app.db.session import get_db
from app.rbac import get_current_user, get_org_membership_or_platform_admin
from app.schemas.organization_roles import (
    EffectivePermissionOut,
    OrganizationMemberDetailOut,
    OrganizationMemberRoleOut,
)
from app.schemas.permissions import RolePermissionOut
from app.schemas.role_admin import RoleDetailOut
from app.services import org_service, role_service

logger = logging.getLogger("omnibioai.auth.organization_roles")

router = APIRouter(prefix="/organizations", tags=["organizations"])

MANAGE_ORG = "manage_org"


def _require_org_manager(
    organization_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
) -> OrganizationMembership:
    """organization_id-named adapter over
    get_org_membership_or_platform_admin -- see module docstring. Reuses
    that function's exact membership-resolution/platform-admin-bypass
    logic and its own permission check below, which mirrors
    require_org_permission_or_platform_admin's wrapper body exactly."""
    membership = get_org_membership_or_platform_admin(org_id=organization_id, db=db, user=user)
    perms = {p.name for role in membership.roles for p in role.permissions}
    if MANAGE_ORG not in perms:
        raise HTTPException(403, "Forbidden")
    return membership


def _permission_out_or_500(name: str) -> RolePermissionOut:
    """Strict lookup for single-member-scoped detail views (role
    inspection, effective-permissions) -- mirrors routes_platform_roles.py
    ._permission_out_or_500 exactly. Registry/database drift is a
    deployment error; a caller inspecting one specific member's roles gets
    a hard, loud signal about it."""
    perm = REGISTRY.get(name)
    if perm is None:
        raise HTTPException(
            500,
            f"Registry drift: permission {name!r} exists on this member's roles in "
            "the database but is not present in the Permission Registry.",
        )
    return RolePermissionOut(**perm.as_dict())


def _permission_out_or_none(name: str) -> RolePermissionOut | None:
    """Lenient lookup for the bulk members list -- mirrors
    routes_platform_roles.py._permission_out_or_none exactly, for the same
    reason: one unrelated member's drifted permission must not take down
    every other member's visibility in a bulk listing. Logged loudly,
    omitted from just that member's expanded entry. In real deployments
    this is unreachable -- role_service.assert_no_unregistered_permissions
    already refuses to let the app start if any drift exists."""
    perm = REGISTRY.get(name)
    if perm is None:
        logger.warning("registry_drift_in_org_member_listing permission_name=%s", name)
        return None
    return RolePermissionOut(**perm.as_dict())


def _role_detail(role) -> RoleDetailOut:
    return RoleDetailOut(
        id=role.id,
        name=role.name,
        description=role.description,
        permissions=[_permission_out_or_500(p.name) for p in sorted(role.permissions, key=lambda p: p.name)],
    )


def _member_role_out(target: OrganizationMembership, organization_id: int) -> OrganizationMemberRoleOut:
    return OrganizationMemberRoleOut(
        organization_id=organization_id,
        user_id=target.user_id,
        email=target.user.email,
        status=target.status,
        roles=[_role_detail(r) for r in sorted(target.roles, key=lambda r: r.name)],
    )


def _get_target_membership(db: Session, organization_id: int, user_id: int) -> OrganizationMembership:
    target = org_service.get_membership(db, organization_id, user_id)
    if not target:
        raise HTTPException(404, "User is not a member of this organization")
    return target


# ---------------------------------------------------------------------------
# 1. Member role inspection -- full registry metadata per role.
# ---------------------------------------------------------------------------


@router.get("/{organization_id}/members/{user_id}/roles", response_model=OrganizationMemberRoleOut)
def get_organization_member_roles(
    organization_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(_require_org_manager),
):
    target = _get_target_membership(db, organization_id, user_id)
    return _member_role_out(target, organization_id)


# ---------------------------------------------------------------------------
# 2. Assign organization roles (full replace).
# ---------------------------------------------------------------------------


class OrganizationRolesAssignRequest(BaseModel):
    """Kept local, not in schemas/organization_roles.py -- a plain request
    body (roles: list[str]) with no response-side metadata, matching
    schemas/orgs.py's own MemberRolesUpdate shape exactly; a separate
    module for a single-field request schema would be unnecessary
    indirection."""
    roles: list[str]


@router.post("/{organization_id}/members/{user_id}/roles", response_model=OrganizationMemberRoleOut, status_code=201)
def assign_organization_member_roles(
    organization_id: int,
    user_id: int,
    body: OrganizationRolesAssignRequest,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
    caller_membership: OrganizationMembership = Depends(_require_org_manager),
):
    target = _get_target_membership(db, organization_id, user_id)

    if len(body.roles) != len(set(body.roles)):
        raise HTTPException(400, "Duplicate role name in request")

    try:
        new_roles = role_service.resolve_roles(db, body.roles)
    except ValueError as e:
        raise HTTPException(400, str(e))
    # Every permission on every resolved Role is already registry-valid --
    # role_service.create_role/update_role_permissions (PR4) reject an
    # unregistered permission name at role-creation time, so a Role that
    # exists in the catalog at all can never carry one. No separate
    # per-permission registry check is needed here.

    # Self-escalation guard, mirroring routes_orgs.py's update_member_roles
    # (the existing full-replace PUT) exactly: this endpoint performs the
    # identical replace operation under a new path, so it must carry the
    # identical guard -- omitting it here would let a caller bypass the
    # existing endpoint's protection simply by using this one instead.
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
    return _member_role_out(updated, organization_id)


# ---------------------------------------------------------------------------
# 3. Remove a single role assignment, by role name.
# ---------------------------------------------------------------------------


@router.delete("/{organization_id}/members/{user_id}/roles/{role_name}", status_code=204)
def remove_organization_member_role(
    organization_id: int,
    user_id: int,
    role_name: str,
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(_require_org_manager),
):
    target = _get_target_membership(db, organization_id, user_id)

    role = role_service.get_role_by_name(db, role_name)
    if not role:
        raise HTTPException(404, "Role not found")

    if role not in target.roles:
        raise HTTPException(404, "Role is not assigned to this member in this organization")

    org_service.remove_member_role(db, target, role)


# ---------------------------------------------------------------------------
# 4. List organization members with roles + effective permissions.
# ---------------------------------------------------------------------------


@router.get("/{organization_id}/members", response_model=list[OrganizationMemberDetailOut])
def list_organization_members(
    organization_id: int,
    expand_permissions: bool = Query(
        False, description="If true, return full registry metadata per permission instead of plain names."
    ),
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(_require_org_manager),
):
    members = org_service.list_members(db, organization_id)

    if expand_permissions:
        expanded = []
        for m in members:
            perm_names = sorted(org_service.permissions_for_membership(m))
            expanded.append(
                {
                    "user_id": m.user_id,
                    "email": m.user.email,
                    "status": m.status,
                    "roles": sorted(r.name for r in m.roles),
                    "permissions": [
                        out.model_dump(mode="json")
                        for out in (_permission_out_or_none(n) for n in perm_names)
                        if out is not None
                    ],
                }
            )
        return JSONResponse(expanded)

    return [
        OrganizationMemberDetailOut(
            user_id=m.user_id,
            email=m.user.email,
            status=m.status,
            roles=sorted(r.name for r in m.roles),
            permissions=sorted(org_service.permissions_for_membership(m)),
        )
        for m in members
    ]


# ---------------------------------------------------------------------------
# 5. Effective permissions for one member -- names + full registry metadata.
# ---------------------------------------------------------------------------


@router.get(
    "/{organization_id}/members/{user_id}/effective-permissions",
    response_model=EffectivePermissionOut,
)
def get_organization_member_effective_permissions(
    organization_id: int,
    user_id: int,
    db: Session = Depends(get_db),
    caller_membership: OrganizationMembership = Depends(_require_org_manager),
):
    target = _get_target_membership(db, organization_id, user_id)
    names = sorted(org_service.permissions_for_membership(target))
    return EffectivePermissionOut(
        organization_id=organization_id,
        user_id=user_id,
        permission_names=names,
        # _permission_out_or_500 returns RolePermissionOut, a PermissionOut
        # subclass -- satisfies EffectivePermissionOut.permissions'
        # list[PermissionOut] directly, no separate lookup needed.
        permissions=[_permission_out_or_500(n) for n in names],
    )
