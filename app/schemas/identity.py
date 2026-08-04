"""PR8 (Enterprise IAM Foundation): response shapes for the Identity &
Effective Authorization API (routes_identity.py). `global_permissions` and
each organization's `effective_permissions` are `list[str]` by default and
become `list[PermissionOut]` (PR5, reused unmodified) when the caller asks
for `?expand_permissions=true` -- see routes_identity.py for how that
variant is served without a second top-level schema.
"""
from datetime import datetime

from pydantic import BaseModel


class CurrentUserOut(BaseModel):
    id: int
    email: str
    status: str
    created_at: datetime | None = None


class GlobalRoleOut(BaseModel):
    """A global role this user holds -- id/name/description only, no
    permissions field: permissions are already flattened separately at
    IdentityOut.global_permissions, so repeating them per-role here would
    be the exact duplicate-metadata this PR is instructed not to
    introduce."""
    id: int
    name: str
    description: str | None = None


class OrganizationIdentityOut(BaseModel):
    organization_id: int
    organization_name: str
    roles: list[str]
    effective_permissions: list[str]


class IdentityOut(BaseModel):
    """The canonical identity + effective-authorization projection --
    backs both GET /me and GET /platform/users/{user_id}/identity, which
    return byte-identical shapes for different subjects."""
    user: CurrentUserOut
    global_roles: list[GlobalRoleOut]
    global_permissions: list[str]
    organizations: list[OrganizationIdentityOut]
