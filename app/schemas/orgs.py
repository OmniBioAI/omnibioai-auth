from datetime import datetime

from pydantic import BaseModel

# Phase 3 PR2. A platform admin (manage_all_orgs) may suspend/reactivate
# any organization; toggling back to "active" is always allowed -- the
# same "restricting is guarded, relaxing is not" asymmetry Phase 2 PR5
# used for SSO enforcement, applied here to org status instead of SSO.
ALLOWED_ORG_STATUSES = {"active", "suspended"}


class OrganizationCreate(BaseModel):
    name: str
    slug: str


class OrganizationOut(BaseModel):
    id: int
    slug: str
    name: str
    plan: str
    status: str
    # Additive -- Phase 3 PR2. None for every org that has never had its
    # status changed via the new platform-admin action below; existing
    # clients reading only id/slug/name/plan/status are unaffected.
    status_changed_at: datetime | None = None
    status_changed_reason: str | None = None
    status_changed_by_user_id: int | None = None


class OrganizationUpdate(BaseModel):
    name: str | None = None
    # Phase 3 PR2: platform-admin-only (manage_all_orgs) -- see
    # routes_orgs.py's update_org. A regular org_admin including this in
    # their own PATCH body is rejected (403), not silently ignored, so a
    # confused/misbehaving client finds out immediately rather than
    # believing a status change succeeded when it didn't.
    status: str | None = None
    status_reason: str | None = None


class InviteRequest(BaseModel):
    email: str


class MemberOut(BaseModel):
    user_id: int
    email: str
    status: str
    roles: list[str]


class MemberRolesUpdate(BaseModel):
    roles: list[str]


class MemberRolesOut(BaseModel):
    user_id: int
    roles: list[str]
