from pydantic import BaseModel


class RoleCreate(BaseModel):
    name: str
    permissions: list[str] = []
    # Phase 3 PR3B: optional, additive -- surfaced read-only via the new
    # platform-admin/org-scoped RoleSummary (schemas/role_admin.py).
    description: str | None = None


class RoleUpdate(BaseModel):
    permissions: list[str]
    description: str | None = None


class RoleOut(BaseModel):
    id: int
    name: str
    permission_count: int
    user_count: int


class RoleDetailOut(BaseModel):
    id: int
    name: str
    description: str | None = None
    permissions: list[str]


class UserRolesOut(BaseModel):
    user_id: int
    roles: list[str]


class UserRolesUpdate(BaseModel):
    roles: list[str]
