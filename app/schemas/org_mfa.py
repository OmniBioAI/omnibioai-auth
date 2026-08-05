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
    # True when a global-admin break-glass override is currently
    # suspending enforcement for this org -- surfaced so an org admin
    # isn't left guessing why required=true isn't taking effect, same
    # reasoning OrgSSOConfigOut.sso_override_active already gives.
    override_active: bool


class OrgMFAOverrideRequest(BaseModel):
    reason: str
