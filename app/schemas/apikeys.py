from datetime import datetime

from pydantic import BaseModel


class ApiKeyCreate(BaseModel):
    name: str
    scopes: list[str] = []
    expires_at: datetime | None = None  # M9: optional, self-service-settable; None = no expiry
    test: bool = False  # M13: omni_sk_test_ instead of omni_sk_live_; see apikey_service.is_test_key


class ApiKeyRename(BaseModel):
    name: str


class ApiKeyCreated(BaseModel):
    id: int
    name: str | None
    key_prefix: str
    scopes: list[str]
    expires_at: datetime | None = None
    test: bool = False
    key: str  # full plaintext key -- returned exactly once, at creation


class ApiKeyOut(BaseModel):
    id: int
    name: str | None
    key_prefix: str
    scopes: list[str]
    status: str
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None
    test: bool = False


class ApiKeyExchangeIn(BaseModel):
    api_key: str


class ApiKeyExchangeOut(BaseModel):
    access_token: str
    expires_in: int
    api_key_id: int
    organization_id: int
    user_id: int
    permissions: list[str]
    test_mode: bool = False
