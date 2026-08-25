from datetime import datetime

from pydantic import BaseModel


class OrgSAMLConfigCreate(BaseModel):
    entity_id: str
    sso_url: str
    x509_certificate: str
    attribute_mapping: dict[str, str] | None = None
    # PR11 (SLO): the IdP's SingleLogoutService endpoint -- optional,
    # since not every IdP supports or needs SLO configured to use SAML
    # login at all. See OrganizationSAMLConfig.slo_url's own comment for
    # why this is a genuinely separate field from sso_url.
    slo_url: str | None = None
    # #263: same shape/default as OrgSSOConfigCreate.allowed_domains --
    # the domain-to-org lookup per-org SAML enforcement needs.
    allowed_domains: list[str] = []


class OrgSAMLConfigUpdate(BaseModel):
    entity_id: str | None = None
    sso_url: str | None = None
    x509_certificate: str | None = None
    attribute_mapping: dict[str, str] | None = None
    enabled: bool | None = None
    # Restricted to the model's own 3 documented values (see
    # OrganizationSAMLConfig.status's own comment) -- "active" is what
    # the ACS/login path actually reads (saml_acs -> _verify_saml_
    # relay_state), so this is the real, working way to disable/
    # re-enable a config without deleting it.
    status: str | None = None
    slo_url: str | None = None
    # #263: same shape as OrgSSOConfigUpdate.allowed_domains.
    allowed_domains: list[str] | None = None
    # #263: same shape as OrgSSOConfigUpdate.enforced -- setting True is
    # rejected (400) unless the org has at least one completed SAML login
    # already, see org_saml_service.set_enforced's lockout guard.
    enforced: bool | None = None


class OrgSAMLConfigOut(BaseModel):
    entity_id: str
    sso_url: str
    # A public IdP signing certificate, not a secret -- unlike
    # OrgSSOConfigOut's deliberate omission of client_secret, this is
    # safe and expected to round-trip so an admin can verify what's
    # actually stored.
    x509_certificate: str
    attribute_mapping: dict[str, str] | None
    # Persisted for schema completeness (mirrors OrganizationSSOConfig's
    # own enabled/enforced-shaped column), but not currently read by any
    # SAML login/ACS code path -- only `status` gates whether a login can
    # succeed. See app/services/org_saml_service.py's create/update
    # docstrings for this discovered, disclosed gap. NOT to be confused
    # with `enforced` below (#263) -- a separate, genuinely-read field.
    enabled: bool
    status: str
    slo_url: str | None
    # #263: same shape as OrgSSOConfigOut.allowed_domains/enforced. No
    # sso_override_active-equivalent field -- SAML has no break-glass
    # override mechanism (out of scope for #263, see org_saml_service.py's
    # own section comment on set_enforced).
    allowed_domains: list[str]
    enforced: bool
    created_at: datetime | None
    updated_at: datetime | None
