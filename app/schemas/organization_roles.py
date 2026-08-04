"""PR7 (Enterprise IAM Foundation): response shapes for the Organization
Role Assignment API (routes_organization_roles.py) -- the first consumer
of PR4's Permission Registry / PR5's read API / PR6's RBAC management
layer from the organization side. Reuses RoleDetailOut (PR6) and
PermissionOut (PR5) directly wherever full permission metadata is
needed -- nothing here redefines what a role's or a permission's fields
are.
"""
from pydantic import BaseModel

from app.schemas.permissions import PermissionOut
from app.schemas.role_admin import RoleDetailOut


class OrganizationMemberRoleOut(BaseModel):
    """Backs GET/POST /organizations/{organization_id}/members/{user_id}/roles.
    `roles` carries full registry-backed permission metadata per role (via
    RoleDetailOut), unlike schemas/role_admin.py's existing
    OrganizationRoleAssignment (role names only, still used unmodified by
    the legacy /orgs/{org_id}/members/{user_id}/roles GET)."""
    organization_id: int
    user_id: int
    email: str
    status: str
    roles: list[RoleDetailOut]


class OrganizationMemberDetailOut(BaseModel):
    """Backs GET /organizations/{organization_id}/members. `permissions`
    is this member's flattened effective permission set (names only) --
    see EffectivePermissionOut below for the full-metadata equivalent, and
    this endpoint's own ?expand_permissions=true for the same expansion
    inline on the list."""
    user_id: int
    email: str
    status: str
    roles: list[str]
    permissions: list[str]


class EffectivePermissionOut(BaseModel):
    """Backs GET /organizations/{organization_id}/members/{user_id}/effective-permissions.
    Exposes exactly what current RBAC already grants this member -- a read
    view over org_service.permissions_for_membership's existing
    computation, no new authorization logic."""
    organization_id: int
    user_id: int
    permission_names: list[str]
    permissions: list[PermissionOut]
