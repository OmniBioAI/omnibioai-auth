"""
OmniBioAI app.schemas.delegated_execution.

Purpose:
    Defines DelegatedExecutionTokenRequest, DelegatedExecutionTokenOut, DelegatedExecutionIntrospectionRequest and DelegatedExecutionIntrospectionOut for app.schemas.delegated_execution.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from pydantic import BaseModel, ConfigDict, Field


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


class ArtifactEntitlementContextRequest(BaseModel):
    """A proof only: caller-supplied ownership, plan and scope are forbidden."""
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=1, max_length=32768, repr=False)


class DelegatedExecutionIntrospectionOut(BaseModel):
    valid: bool
    client_id: str | None = None
    user_id: str | None = None
    organization_id: str | None = None
    permissions: list[str] = []
    delegation_id: str | None = None


class ArtifactDelegationTokenRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    initiating_token: str = Field(min_length=1, repr=False)
    organization_id: int = Field(gt=0)
    project_id: str = Field(min_length=1, max_length=255)
    run_id: str = Field(min_length=1, max_length=255)
    output_ids: list[str] = Field(default_factory=list, max_length=100)
    artifact_ids: list[str] = Field(default_factory=list, max_length=100)
    source_delegation_token: str | None = Field(default=None, max_length=32768, repr=False)
    permissions: list[str] = Field(min_length=1)
    audience: str


class ArtifactDelegationTokenOut(DelegatedExecutionTokenOut):
    delegation_id: str
    organization_id: str
    project_id: str
    run_id: str
    user_id: str
    artifact_ids: list[str]
    permissions: list[str]
    audience: str


class ArtifactDelegationIntrospectionOut(BaseModel):
    valid: bool
    issuer: str | None = None
    client_id: str | None = None
    user_id: str | None = None
    organization_id: str | None = None
    project_id: str | None = None
    run_id: str | None = None
    output_ids: list[str] = []
    artifact_ids: list[str] = []
    permissions: list[str] = []
    delegation_id: str | None = None


class ToolServerRegistrationTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class ToolServerRegistrationIntrospectionOut(BaseModel):
    valid: bool
    client_id: str | None = None
    organization_id: str | None = None
    scopes: list[str] = []
    registration_id: str | None = None
