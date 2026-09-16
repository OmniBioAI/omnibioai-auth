from pydantic import BaseModel, Field


class DelegatedExecutionTokenRequest(BaseModel):
    """A TES service token authorizes the request; this is the verified user bearer."""
    initiating_token: str = Field(min_length=1)
    organization_id: int
    permissions: list[str] = Field(min_length=1)
    audience: str


class DelegatedExecutionTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class DelegatedExecutionIntrospectionRequest(BaseModel):
    token: str = Field(min_length=1)


class DelegatedExecutionIntrospectionOut(BaseModel):
    valid: bool
    client_id: str | None = None
    user_id: str | None = None
    organization_id: str | None = None
    permissions: list[str] = []
    delegation_id: str | None = None
