"""Phase 3 PR3B: platform-admin role management.

New file, not an extension of routes_platform_users.py (that file's own
concern is the user directory + status; this one is roles) or the legacy
routes_roles.py (that file stays completely untouched -- see this PR's
implementation report for why a parallel, platform-admin-gated surface
was built rather than reusing the manage_roles-gated legacy endpoints).

Same prefix pattern routes_platform_admin.py already established: /platform
with full sub-paths declared per route, not a narrower /platform/roles-only
prefix, since /platform/users/{user_id}/roles also lives here.

Every route depends on require_permission(MANAGE_ALL_ORGS) -- the same
permission PR1's org directory and PR3A's user directory already use, not
a new manage_all_users-style permission (see this PR's report for that
tradeoff, inherited unchanged from PR3A's own reasoning).
"""
from fastapi import APIRouter, Depends, HTTPException

from sqlalchemy.orm import Session

from app.db.models import Role, User
from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, get_current_user, require_permission
from app.schemas.role_admin import RoleAssignRequest, RoleSummary, UserRoleAssignment
from app.services import role_service

router = APIRouter(prefix="/platform", tags=["platform-admin"])

_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


def _role_summary(role: Role) -> RoleSummary:
    return RoleSummary(
        id=role.id,
        name=role.name,
        description=role.description,
        permissions=sorted(p.name for p in role.permissions),
    )


def _user_role_assignments(user: User) -> list[UserRoleAssignment]:
    # assigned_at/assigned_by are always None -- see role_admin.py's
    # UserRoleAssignment docstring and 0010_role_description's migration
    # docstring for why this PR does not add that tracking.
    return [UserRoleAssignment(user_id=user.id, role=r.name) for r in sorted(user.roles, key=lambda r: r.name)]


@router.get("/roles", response_model=list[RoleSummary])
def list_platform_roles(
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    return [_role_summary(r) for r in role_service.list_roles(db)]


@router.get("/users/{user_id}/roles", response_model=list[UserRoleAssignment])
def get_platform_user_roles(
    user_id: int,
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    target = role_service.get_user(db, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    return _user_role_assignments(target)


@router.post("/users/{user_id}/roles", response_model=list[UserRoleAssignment], status_code=201)
def assign_platform_user_role(
    user_id: int,
    body: RoleAssignRequest,
    db: Session = Depends(get_db),
    caller=Depends(get_current_user),
    _admin=Depends(_require_platform_admin),
):
    target = role_service.get_user(db, user_id)
    if not target:
        raise HTTPException(404, "User not found")

    role = role_service.get_role_by_name(db, body.role)
    if not role:
        raise HTTPException(400, f"Unknown role: {body.role!r}")

    # Self-escalation guard, mirroring routes_roles.py's existing
    # update_user_roles pattern: granting yourself a role that adds a
    # permission you don't already hold is rejected, even for a platform
    # admin acting on their own account. Removing a role can only ever
    # narrow permissions, so no equivalent guard is needed on DELETE below.
    is_self = str(target.id) == str(caller.get("sub"))
    if is_self:
        current_perms = role_service.permissions_for_roles(target.roles)
        new_perms = role_service.permissions_for_roles([role])
        if not new_perms.issubset(current_perms):
            raise HTTPException(
                403,
                "Cannot assign yourself a role that grants additional permissions",
            )

    role_service.add_user_role(db, target, role)
    return _user_role_assignments(target)


@router.delete("/users/{user_id}/roles/{role_id}", status_code=204)
def remove_platform_user_role(
    user_id: int,
    role_id: int,
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    target = role_service.get_user(db, user_id)
    if not target:
        raise HTTPException(404, "User not found")

    role = role_service.get_role(db, role_id)
    if not role:
        raise HTTPException(404, "Role not found")

    if role not in target.roles:
        raise HTTPException(404, "Role is not assigned to this user")

    role_service.remove_user_role(db, target, role)
