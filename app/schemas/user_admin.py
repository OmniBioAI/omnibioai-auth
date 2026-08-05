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
    # PR11.1: null for any user who predates this migration or has never
    # logged in since -- never fabricated. See User.last_login_at's own
    # comment in app/db/models.py for where these are written.
    last_login_at: datetime | None = None
    authentication_method: str | None = None
    # PR11.5.6 (Admin Console Security UI, discovery §6.1): a live column
    # on User (PR11.5.1), not a derivation -- lets the Security Dashboard
    # compute MFA-adoption stats by paging this list, with no new
    # aggregation endpoint (see docs/pr11-5-6-security-ui-discovery.md
    # SS7, omnibioai-control-center).
    mfa_enabled: bool = False


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


class PlatformMFADeviceSummary(BaseModel):
    """PR11.5.6 (Admin Console Security UI). Deliberately not MFADeviceOut
    (app/schemas/mfa.py) reused verbatim -- that schema's `id` is meant
    for a self-service caller to pass back to their own
    DELETE /users/me/mfa/devices/{id}; a platform admin viewing a
    *different* user's devices here has no matching admin-scoped delete
    endpoint (this PR adds none), so omitting `id` means this schema
    can't be mistaken for one, or wired to a delete action that doesn't
    exist. No encrypted_secret field, same as MFADeviceOut."""
    device_type: str
    label: str | None
    created_at: datetime
    last_used_at: datetime | None


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
    # PR11.1: same null-means-no-data convention as PlatformUserSummary above.
    last_login_at: datetime | None = None
    authentication_method: str | None = None
    # PR11.5.6 (discovery §6.1): live columns on User (PR11.5.1) plus two
    # small, already-scoped (user_id-filtered) queries against
    # MFADevice/MFARecoveryCode -- never a TOTP secret or a recovery
    # code, only counts/metadata. See
    # docs/pr11-5-6-security-ui-discovery.md (omnibioai-control-center).
    mfa_enabled: bool = False
    mfa_status: str = "disabled"
    mfa_primary_method: str | None = None
    mfa_enabled_at: datetime | None = None
    mfa_last_verified_at: datetime | None = None
    mfa_devices: list[PlatformMFADeviceSummary] = []
    mfa_recovery_codes_remaining: int = 0


class UserStatusUpdate(BaseModel):
    status: str
    reason: str | None = None
