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
    # docstrings for this discovered, disclosed gap.
    enabled: bool
    status: str
    slo_url: str | None
    created_at: datetime | None
    updated_at: datetime | None
