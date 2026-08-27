from datetime import datetime

from pydantic import BaseModel


class OrgSSOConfigCreate(BaseModel):
    issuer: str
    client_id: str
    client_secret: str
    allowed_domains: list[str] = []


class OrgSSOConfigUpdate(BaseModel):
    issuer: str | None = None
    client_id: str | None = None
    client_secret: str | None = None
    allowed_domains: list[str] | None = None
    # Phase 2 PR5. Setting True is rejected (400) unless the org has at
    # least one completed SSO login already -- see
    # org_sso_service.set_enforced's lockout guard.
    enforced: bool | None = None


class OrgSSOConfigOut(BaseModel):
    issuer: str
    client_id: str
    provider_type: str
    allowed_domains: list[str]
    status: str
    created_at: datetime | None
    updated_at: datetime | None
    # Phase 2 PR5.
    enforced: bool
    # True when a global-admin break-glass override is currently
    # suspending enforcement for this org -- surfaced so an org admin
    # isn't left guessing why enforced=true isn't taking effect.
    sso_override_active: bool
    # Never client_secret or client_secret_encrypted -- see
    # app/services/org_sso_service.py and routes_org_sso.py's _to_out.


# #67: reused verbatim by routes_org_saml.py's override endpoints too,
# not forked into a SAML-specific schema -- a break-glass reason string
# is a provider-agnostic shape, the same rule that keeps
# override_sso_enforcement (app/api/routes_org_sso.py) as the one
# permission gating both. See routes_org_saml.py's module docstring for
# the full reasoning, including why audit events are the one thing that
# stays provider-specific.
class SSOOverrideRequest(BaseModel):
    reason: str
