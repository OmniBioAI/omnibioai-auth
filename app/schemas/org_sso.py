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


class OrgSSOConfigOut(BaseModel):
    issuer: str
    client_id: str
    provider_type: str
    allowed_domains: list[str]
    status: str
    created_at: datetime | None
    updated_at: datetime | None
    # Never client_secret or client_secret_encrypted -- see
    # app/services/org_sso_service.py and routes_org_sso.py's _to_out.
