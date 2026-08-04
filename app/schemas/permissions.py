"""PR5 (Enterprise IAM Foundation): response shape for the read-only
Permission Registry API (routes_platform_permissions.py). Mirrors
PermissionDef.as_dict() field-for-field -- this schema is the wire format
for that dict, not an independent definition of what a permission looks
like, matching schemas/role_admin.py's own "separate module per new
platform-admin surface" convention.
"""
from pydantic import BaseModel


class PermissionOut(BaseModel):
    name: str
    resource: str
    action: str
    scope: str
    category: str
    description: str
    legacy: bool
    deprecated: bool
    deprecated_reason: str | None = None


class RolePermissionOut(PermissionOut):
    """PR6: identical shape to PermissionOut -- a subclass, not a
    redefinition, so a role's permission list can never drift from the
    registry's own wire format. Exists as a distinct name only so
    RoleDetailOut's `permissions` field reads clearly as "this role's
    permissions, with full registry metadata" rather than reusing
    PermissionOut's more generic name in a role-specific response."""


class PermissionStatsOut(BaseModel):
    total_permissions: int
    legacy_permissions: int
    future_permissions: int
    by_scope: dict[str, int]
    by_category: dict[str, int]
    deprecated_permissions: int
