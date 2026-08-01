"""Phase 3 PR3B: role management response/request shapes for the
platform-admin and org-scoped role APIs. Deliberately separate from
schemas/roles.py (the legacy manage_roles-gated global CRUD surface,
untouched by this PR) -- this module's schemas are for the new
/platform/roles and /orgs/{org_id}/roles surfaces, matching the naming
convention schemas/user_admin.py already established in PR3A.
"""
from datetime import datetime

from pydantic import BaseModel


class RoleSummary(BaseModel):
    id: int
    name: str
    description: str | None = None
    permissions: list[str]


class RoleAssignRequest(BaseModel):
    role: str


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
