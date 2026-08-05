from datetime import datetime

from pydantic import BaseModel


class OrgMFAPolicyCreate(BaseModel):
    required: bool = False


class OrgMFAPolicyUpdate(BaseModel):
    required: bool | None = None
    # PR11.5.5: optional -- a routine toggle doesn't always warrant one,
    # but it's carried into MFA_POLICY_ENABLED/MFA_POLICY_DISABLED's
    # audit metadata whenever supplied. See
    # docs/pr11-mfa-org-policy-discovery.md SS7.
    reason: str | None = None


class OrgMFAPolicyOut(BaseModel):
    required: bool
    created_at: datetime | None
    updated_at: datetime | None
    enabled_at: datetime | None
    # PR11.5.6 (Admin Console Security UI): the admin who most recently
    # flipped required False->True, resolved to an email the same
    # display-friendly way audit_service.resolve_display_fields already
    # does for actor_email elsewhere -- never just the raw id, and never
    # a password/credential of any kind. None whenever enabled_at is
    # None (never enabled) or that user no longer exists.
    enabled_by_email: str | None = None
    # True when a global-admin break-glass override is currently
    # suspending enforcement for this org -- surfaced so an org admin
    # isn't left guessing why required=true isn't taking effect, same
    # reasoning OrgSSOConfigOut.sso_override_active already gives.
    override_active: bool
    # PR11.5.6: the outgoing override's own stated reason -- already
    # persisted (OrganizationMFAPolicy.override_reason) but not
    # previously returned by this endpoint. None whenever no override is
    # active. Not a secret -- free-text justification an admin typed,
    # same category SSOOverrideRequest's own reason already is.
    override_reason: str | None = None


class OrgMFAOverrideRequest(BaseModel):
    reason: str
