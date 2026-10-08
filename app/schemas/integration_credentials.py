"""Write-only integration credential API schemas."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class CredentialWriteIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credentials: dict[str, str]
    display_metadata: dict[str, str] | None = None


class CredentialMetadataOut(BaseModel):
    provider_id: str
    scope: str
    configured: bool
    status: str
    masked_hint: str | None
    display_metadata: dict[str, str] | None
    created_at: str
    updated_at: str


class CredentialReferenceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consumer: Literal["workbench"] = "workbench"
    purpose: Literal["integration_execution"] = "integration_execution"


class CredentialReferenceOut(BaseModel):
    provider_id: str
    resolved_scope: str
    credential_ref: str | None
    expires_at: str | None


class CredentialResolveIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    credential_ref: str = Field(min_length=32, max_length=256)
    provider_id: str = Field(pattern=r"^[a-z0-9_]{1,64}$")
    consumer: Literal["workbench"]
    purpose: Literal["integration_execution"]


class CredentialResolveOut(BaseModel):
    provider_id: str
    scope: str
    credentials: dict[str, str]


class ConnectionTestOut(BaseModel):
    provider_id: str
    status: Literal["TEST_NOT_SUPPORTED"]
