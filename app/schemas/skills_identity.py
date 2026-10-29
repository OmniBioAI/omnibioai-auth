"""Versioned Track B Skills identity verification contract."""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field


class SkillsIdentityRequest(BaseModel):
    credential_handle: str = Field(min_length=1, max_length=255)
    expected_tenant_id: str = Field(min_length=1, max_length=255)
    correlation_id: str = Field(min_length=1, max_length=255)
    audience: Literal["omnibioai-skills"] = "omnibioai-skills"
    delegation_id: str | None = Field(default=None, min_length=1, max_length=64)


class SkillsVerifiedIdentity(BaseModel):
    principal_id: str
    tenant_id: str
    permissions: list[str]
    identity_id: str
    issued_at: datetime
    expires_at: datetime
    revocation_checked_at: datetime
    delegation_id: str | None = None
    actor_client_id: str | None = None
    schema_version: Literal["skills.iam/v1"] = "skills.iam/v1"
    authority: Literal["omnibioai-auth"] = "omnibioai-auth"
    verification_reference: str


class SkillsDelegationRequest(BaseModel):
    subject_credential_handle: str = Field(min_length=1, max_length=255)
    expected_tenant_id: str = Field(min_length=1, max_length=255)
    permissions: list[str] = Field(min_length=1)
    audience: Literal["omnibioai-skills"] = "omnibioai-skills"
