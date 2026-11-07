"""
OmniBioAI app.schemas.service_mint.

Purpose:
    Defines MintUserTokenRequest and MintUserTokenOut for app.schemas.service_mint.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import re
from typing import Literal

from pydantic import BaseModel, Field, field_validator

_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

# #96: how the calling service verified that its user owns `email`. A new
# method is added here (and to the caller) only when a caller has one.
VerificationMethod = Literal["allauth_verified_primary"]


class MintUserTokenRequest(BaseModel):
    email: str = Field(max_length=255)
    # #96: the caller states that it verified the address. Missing or false
    # is a 422. This is the caller's statement, recorded in the audit event;
    # auth itself has no verification record to check it against.
    email_verified: Literal[True]
    verification_method: VerificationMethod
    # #96: mint for this org instead of the user's primary one. Only an org
    # the user is an active member of; never a fallback to the primary org.
    org_id: int | None = Field(default=None, ge=1)

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, value: str) -> str:
        value = value.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError("invalid email address")
        return value


# Mirrors AuthorizationCodeTokenResponse/ClientCredentialsTokenResponse's
# shape (app/schemas/oauth_client.py) -- the established "here is a bearer
# token" response convention in this repo. No `scope` field: unlike those
# two, the minted token's permissions come entirely from the target
# user's own real role/membership (build_user_claims), never from a
# scope negotiated on this request.
class MintUserTokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
