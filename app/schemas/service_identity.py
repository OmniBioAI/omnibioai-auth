"""PR9 (Enterprise IAM Foundation): response shape for the Service
Identity API (routes_service_identity.py). `permissions` is `list[str]` by
default and becomes `list[PermissionOut]` (PR5, reused unmodified) when
the caller asks for `?expand_permissions=true` -- see
routes_service_identity.py for how that variant is served without a
second top-level schema, mirroring routes_identity.py's own pattern (PR8).
"""
from datetime import datetime

from pydantic import BaseModel


class ServiceIdentityOut(BaseModel):
    client_id: str
    name: str | None = None
    organization_id: int
    permissions: list[str]
    created_at: datetime | None = None
    active: bool
