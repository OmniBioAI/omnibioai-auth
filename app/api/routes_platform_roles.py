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
import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from sqlalchemy.orm import Session

from app.core.permission_names import REGISTRY
from app.db.models import Role, User
from app.db.session import get_db
from app.rbac import MANAGE_ALL_ORGS, get_current_user, require_permission
from app.schemas.permissions import RolePermissionOut
from app.schemas.role_admin import RoleAssignRequest, RoleDetailOut, RoleSummary, UserRoleAssignment
from app.services import role_service

logger = logging.getLogger("omnibioai.auth.platform_roles")

router = APIRouter(prefix="/platform", tags=["platform-admin"])

_require_platform_admin = require_permission(MANAGE_ALL_ORGS)


def _role_summary(role: Role) -> RoleSummary:
    return RoleSummary(
        id=role.id,
        name=role.name,
        description=role.description,
        permissions=sorted(p.name for p in role.permissions),
    )


def _permission_out_or_500(name: str) -> RolePermissionOut:
    """PR6: look up full registry metadata for a Permission row already
    attached to a role. If the name isn't in the registry, that's
    registry/database drift -- a deployment error (see role_service
    .assert_no_unregistered_permissions, checked once at startup), not a
    request-time condition a caller can fix, hence 500 rather than 404/400."""
    perm = REGISTRY.get(name)
    if perm is None:
        raise HTTPException(
            500,
            f"Registry drift: permission {name!r} exists on this role in the "
            "database but is not present in the Permission Registry.",
        )
    return RolePermissionOut(**perm.as_dict())


def _role_detail(role: Role) -> RoleDetailOut:
    return RoleDetailOut(
        id=role.id,
        name=role.name,
        description=role.description,
        permissions=[_permission_out_or_500(p.name) for p in sorted(role.permissions, key=lambda p: p.name)],
    )


def _permission_out_or_none(name: str) -> RolePermissionOut | None:
    """Lenient counterpart to _permission_out_or_500, used only by the bulk
    expand_permissions=true list below. In real deployments this can never
    actually differ from the strict version -- role_service
    .assert_no_unregistered_permissions already refuses to let the
    application start if any drift exists, and every validated write path
    (create_role/update_role_permissions) rejects an unregistered name --
    so this only matters as defense in depth for a listing surface that
    must stay available. A single unrelated role's drifted permission must
    not take down every other role's visibility in a bulk admin listing;
    it's logged loudly and omitted from just that one role's entry instead
    -- the same "log it, never silently pretend it isn't different, but
    don't crash an unrelated read path either" precedent
    permission_parity.py already established for the legacy/org permission
    comparison. A caller who wants a hard failure on this exact role's
    drift can still get one via GET /platform/roles/{role_name}."""
    perm = REGISTRY.get(name)
    if perm is None:
        logger.warning("registry_drift_in_role_listing permission_name=%s", name)
        return None
    return RolePermissionOut(**perm.as_dict())


def _role_detail_lenient(role: Role) -> RoleDetailOut:
    permissions = [
        out for out in (
            _permission_out_or_none(p.name) for p in sorted(role.permissions, key=lambda p: p.name)
        )
        if out is not None
    ]
    return RoleDetailOut(id=role.id, name=role.name, description=role.description, permissions=permissions)


def _user_role_assignments(user: User) -> list[UserRoleAssignment]:
    # assigned_at/assigned_by are always None -- see role_admin.py's
    # UserRoleAssignment docstring and 0010_role_description's migration
    # docstring for why this PR does not add that tracking.
    return [UserRoleAssignment(user_id=user.id, role=r.name) for r in sorted(user.roles, key=lambda r: r.name)]


@router.get("/roles", response_model=list[RoleSummary])
def list_platform_roles(
    expand_permissions: bool = Query(
        False, description="If true, return full registry metadata per permission instead of plain names."
    ),
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    roles = role_service.list_roles(db)
    if expand_permissions:
        # PR6: a distinct response shape (permissions carry full registry
        # metadata, not just names) -- returning a Response subclass here
        # bypasses this route's declared response_model entirely, so the
        # default (expand_permissions=false) path above keeps its original,
        # unmodified response_model validation/shape with zero risk of the
        # expanded branch silently reshaping it. Uses the lenient variant,
        # not _role_detail -- see _role_detail_lenient's docstring.
        expanded = [_role_detail_lenient(r) for r in roles]
        return JSONResponse([r.model_dump(mode="json") for r in expanded])
    return [_role_summary(r) for r in roles]


@router.get("/roles/{role_name}", response_model=RoleDetailOut)
def get_platform_role_detail(
    role_name: str,
    db: Session = Depends(get_db),
    user=Depends(_require_platform_admin),
):
    role = role_service.get_role_by_name(db, role_name)
    if not role:
        raise HTTPException(404, "Role not found")
    return _role_detail(role)


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

    role_service.add_user_role(db, target, role, actor_user_id=int(caller.get("sub")))
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

    role_service.remove_user_role(db, target, role, actor_user_id=int(user.get("sub")))
