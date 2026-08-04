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
