from datetime import datetime

from pydantic import BaseModel


class LicenseValidateRequest(BaseModel):
    key: str
    email: str
    platform: str = "web"  # web | desktop | both


class LicenseValidateResponse(BaseModel):
    valid: bool
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    user_info: dict | None = None
    reason: str | None = None  # populated only when valid is False


class LicenseGenerateRequest(BaseModel):
    email: str
    plan: str = "beta"
    platform: str = "both"
    expires_days: int | None = None
    max_uses: int = 1


class LicenseGenerateResponse(BaseModel):
    key: str
    email: str
    plan: str
    platform: str
    expires_at: datetime | None
    max_uses: int


class LicenseStatusResponse(BaseModel):
    key: str
    plan: str
    platform: str
    expires_at: datetime | None
    usage_count: int
    max_uses: int
    last_used_at: datetime | None
    revoked: bool


class LicenseRevokeRequest(BaseModel):
    key: str
    reason: str | None = None


class LicenseRevokeResponse(BaseModel):
    success: bool
