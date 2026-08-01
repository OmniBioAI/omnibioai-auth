from datetime import datetime

from pydantic import BaseModel

# Phase 3 PR3A. Suspending/reactivating a user reuses the same two-value
# vocabulary org status already uses (Phase 3 PR2) -- no new status model
# invented for this resource.
ALLOWED_USER_STATUSES = {"active", "suspended"}


class PlatformUserSummary(BaseModel):
    """Lightweight, list-view row -- counts and global roles only, no
    nested membership details (those are the detail endpoint's job), so
    this stays cheap regardless of how many orgs a user belongs to."""
    id: int
    email: str
    status: str
    created_at: datetime | None
    global_roles: list[str]
    org_count: int


class PlatformUserListOut(BaseModel):
    items: list[PlatformUserSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class OrgMembershipSummary(BaseModel):
    """One row per organization the user belongs to -- the "org
    membership display" the detail endpoint exists to provide."""
    organization_id: int
    organization_name: str
    organization_slug: str
    roles: list[str]
    status: str
    joined_at: datetime | None


class PlatformUserDetailOut(BaseModel):
    id: int
    email: str
    status: str
    created_at: datetime | None
    global_roles: list[str]
    memberships: list[OrgMembershipSummary]
    status_changed_at: datetime | None = None
    status_changed_reason: str | None = None
    status_changed_by_email: str | None = None


class UserStatusUpdate(BaseModel):
    status: str
    reason: str | None = None
