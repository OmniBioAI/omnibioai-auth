from datetime import datetime

from pydantic import BaseModel


class ApiKeyCreate(BaseModel):
    name: str
    scopes: list[str] = []


class ApiKeyCreated(BaseModel):
    id: int
    name: str | None
    key_prefix: str
    scopes: list[str]
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


class ApiKeyExchangeIn(BaseModel):
    api_key: str


class ApiKeyExchangeOut(BaseModel):
    access_token: str
    expires_in: int
    api_key_id: int
    organization_id: int
    user_id: int
    permissions: list[str]
