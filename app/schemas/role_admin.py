"""Phase 3 PR3B: role management response/request shapes for the
platform-admin and org-scoped role APIs. Deliberately separate from
schemas/roles.py (the legacy manage_roles-gated global CRUD surface,
untouched by this PR) -- this module's schemas are for the new
/platform/roles and /orgs/{org_id}/roles surfaces, matching the naming
convention schemas/user_admin.py already established in PR3A.
"""
from datetime import datetime

from pydantic import BaseModel

from app.schemas.permissions import RolePermissionOut


class RoleDetailOut(BaseModel):
    """PR6: full role detail with complete registry metadata per
    permission (not just names, unlike RoleSummary below). Backs `GET
    /platform/roles/{role_name}` and, when `?expand_permissions=true`,
    `GET /platform/roles`'s expanded list items too -- same shape, so no
    second schema was introduced for that variant."""
    id: int
    name: str
    description: str | None = None
    permissions: list[RolePermissionOut]
    # PR13: None = platform-wide role, otherwise the owning org's id.
    organization_id: int | None = None


class RoleSummary(BaseModel):
    id: int
    name: str
    description: str | None = None
    permissions: list[str]
    # PR13: None = platform-wide role, otherwise the owning org's id.
    organization_id: int | None = None


class RoleAssignRequest(BaseModel):
    role: str


class RoleCreateRequest(BaseModel):
    """PR13: body for POST /platform/roles and POST
    /organizations/{organization_id}/roles. `organization_id` is never a
    field here -- the route derives it (None for the platform surface, the
    path parameter for the org surface), so a caller can never request a
    role in a scope other than the one the URL/permission check already
    authorized them for."""
    name: str
    permissions: list[str] = []
    description: str | None = None


class RolePermissionsUpdateRequest(BaseModel):
    """PR13: body for PUT /platform/roles/{role_id} and PUT
    /organizations/{organization_id}/roles/{role_id}. `description=None`
    means "leave unchanged", matching role_service.update_role_permissions'
    existing contract."""
    permissions: list[str]
    description: str | None = None


class UserRoleAssignment(BaseModel):
    """One row per role a user holds. `assigned_at`/`assigned_by` are
    always None today -- `user_roles` is a bare many-to-many association
    table with no per-row metadata (see 0010_role_description's migration
    docstring for why this PR does not add it). The fields are present in
    the shape now so a future PR can populate them without a breaking
    response-schema change, exactly the same "field exists, not yet
    populated" pattern org_sso_configs' verification_error column already
    used (Phase 2 PR3)."""
    user_id: int
    role: str
    assigned_at: datetime | None = None
    assigned_by: str | None = None


class OrganizationRoleAssignment(BaseModel):
    organization_id: int
    user_id: int
    roles: list[str]
