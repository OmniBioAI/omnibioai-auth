from datetime import datetime

from pydantic import BaseModel


class OAuthClientCreate(BaseModel):
    name: str
    scopes: list[str] = []


class OAuthClientCreated(BaseModel):
    id: int
    name: str | None
    client_id: str
    scopes: list[str]
    client_secret: str  # plaintext -- returned exactly once, at creation


class OAuthClientOut(BaseModel):
    id: int
    name: str | None
    client_id: str
    scopes: list[str]
    status: str
    created_at: datetime | None
    expires_at: datetime | None
    last_used_at: datetime | None


class ClientCredentialsTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    scope: str
