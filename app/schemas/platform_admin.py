from datetime import datetime

from pydantic import BaseModel


class PlatformOrgSummary(BaseModel):
    """Lightweight, list-view row -- deliberately no nested members/teams/
    keys, only counts, so this stays cheap regardless of an org's size."""
    id: int
    name: str
    status: str
    created_at: datetime
    owner_email: str | None
    member_count: int
    team_count: int
    api_key_count: int
    oauth_client_count: int
    license_count: int
    sso_enabled: bool


class PlatformOrgListOut(BaseModel):
    items: list[PlatformOrgSummary]
    total: int
    page: int
    page_size: int
    total_pages: int


class ResourceCountSummary(BaseModel):
    """Generic count breakdown reused across members/teams/api-keys/
    oauth-clients/licenses in the detail endpoint -- fields that don't
    apply to a given resource (e.g. `invited` for API keys) stay None
    rather than each summary type needing its own bespoke shape."""
    total: int
    active: int | None = None
    invited: int | None = None
    revoked: int | None = None
    most_recent_at: datetime | None = None


class SSOConfigSummary(BaseModel):
    configured: bool
    provider_type: str | None = None
    issuer: str | None = None
    status: str | None = None
    enforced: bool = False
    override_active: bool = False


class RecentActivity(BaseModel):
    """Best-effort recency signals derived from existing timestamped rows
    -- not a real activity/audit feed (omnibioai-security-audit's sink is
    still print()-only as of this writing), so this is intentionally
    limited to "when was X last created/joined," not "what did anyone
    actually do."""
    org_created_at: datetime | None
    most_recent_member_joined_at: datetime | None
    most_recent_api_key_created_at: datetime | None
    most_recent_oauth_client_created_at: datetime | None


class PlatformOrgDetailOut(BaseModel):
    id: int
    slug: str
    name: str
    plan: str
    status: str
    created_at: datetime
    owner_user_id: int | None
    owner_email: str | None
    member_summary: ResourceCountSummary
    team_summary: ResourceCountSummary
    api_key_summary: ResourceCountSummary
    oauth_client_summary: ResourceCountSummary
    license_summary: ResourceCountSummary
    sso: SSOConfigSummary
    recent_activity: RecentActivity
    # Phase 3 PR2, additive: who/why/when for the current status
    # (routes_orgs.py's PATCH /orgs/{org_id} status field, platform-admin
    # only). None until a platform admin has changed this org's status
    # at least once.
    status_changed_at: datetime | None = None
    status_changed_reason: str | None = None
    status_changed_by_email: str | None = None
