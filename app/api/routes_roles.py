from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import Role
from app.rbac import require_permission
from app.schemas.roles import (
    RoleCreate,
    RoleDetailOut,
    RoleOut,
    RoleUpdate,
    UserRolesOut,
    UserRolesUpdate,
)
from app.services import role_service

router = APIRouter(tags=["roles"])

MANAGE_ROLES = "manage_roles"


def _role_out(role: Role) -> RoleOut:
    return RoleOut(
        id=role.id,
        name=role.name,
        permission_count=len(role.permissions),
        user_count=len(role.users),
    )


def _role_detail_out(role: Role) -> RoleDetailOut:
    return RoleDetailOut(
        id=role.id,
        name=role.name,
        permissions=sorted(p.name for p in role.permissions),
    )


@router.get("/roles", response_model=list[RoleOut])
def list_roles(
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_ROLES)),
):
    return [_role_out(r) for r in role_service.list_roles(db)]


@router.post("/roles", response_model=RoleDetailOut, status_code=201)
def create_role(
    body: RoleCreate,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_ROLES)),
):
    if role_service.get_role_by_name(db, body.name):
        raise HTTPException(409, "Role already exists")
    role = role_service.create_role(db, body.name, body.permissions)
    return _role_detail_out(role)


@router.get("/roles/{role_id}", response_model=RoleDetailOut)
def get_role(
    role_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_ROLES)),
):
    role = role_service.get_role(db, role_id)
    if not role:
        raise HTTPException(404, "Role not found")
    return _role_detail_out(role)


@router.put("/roles/{role_id}", response_model=RoleDetailOut)
def update_role(
    role_id: int,
    body: RoleUpdate,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_ROLES)),
):
    role = role_service.get_role(db, role_id)
    if not role:
        raise HTTPException(404, "Role not found")
    role = role_service.update_role_permissions(db, role, body.permissions)
    return _role_detail_out(role)


@router.delete("/roles/{role_id}", status_code=204)
def delete_role(
    role_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_ROLES)),
):
    role = role_service.get_role(db, role_id)
    if not role:
        raise HTTPException(404, "Role not found")
    if role_service.role_in_use(db, role_id):
        raise HTTPException(409, "Role is assigned to one or more users")
    role_service.delete_role(db, role)


@router.get("/users/{user_id}/roles", response_model=UserRolesOut)
def get_user_roles(
    user_id: int,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_ROLES)),
):
    target = role_service.get_user(db, user_id)
    if not target:
        raise HTTPException(404, "User not found")
    return UserRolesOut(user_id=target.id, roles=[r.name for r in target.roles])


@router.put("/users/{user_id}/roles", response_model=UserRolesOut)
def update_user_roles(
    user_id: int,
    body: UserRolesUpdate,
    db: Session = Depends(get_db),
    current_user=Depends(require_permission(MANAGE_ROLES)),
):
    target = role_service.get_user(db, user_id)
    if not target:
        raise HTTPException(404, "User not found")

    try:
        new_roles = role_service.resolve_roles(db, body.roles)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Self-escalation guard: acting on your own account can only ever be
    # neutral-or-narrowing in effective permissions, never widening — even
    # if you hold manage_roles permission over other users.
    is_self = str(target.id) == str(current_user.get("sub"))
    if is_self:
        current_perms = role_service.permissions_for_roles(target.roles)
        requested_perms = role_service.permissions_for_roles(new_roles)
        if not requested_perms.issubset(current_perms):
            raise HTTPException(
                403,
                "Cannot modify your own roles to grant yourself additional permissions",
            )

    role_service.set_user_roles(db, target, new_roles)
    return UserRolesOut(user_id=target.id, roles=[r.name for r in target.roles])
