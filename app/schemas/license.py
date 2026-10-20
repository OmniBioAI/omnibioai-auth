"""
OmniBioAI app.schemas.license.

Purpose:
    Defines LicenseValidateRequest, LicenseValidateResponse, LicenseGenerateRequest and LicenseGenerateResponse for app.schemas.license.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from datetime import datetime

from typing import Literal

from pydantic import BaseModel, Field


class LicenseValidateRequest(BaseModel):
    key: str
    # Compatibility hint only. Authorization uses the authenticated
    # identity, never this caller-controlled value or key possession.
    email: str | None = None
    platform: str = "web"  # web | desktop | both
    # Bound to the license on first use, same as license_server.py did --
    # informational device pinning, not an enforced device-count limit
    # (see LicenseKey.max_devices, still unused/reserved).
    machine_id: str | None = None


class LicenseValidateResponse(BaseModel):
    valid: bool
    access_token: str | None = None
    refresh_token: str | None = None
    token_type: str = "bearer"
    user_info: dict | None = None
    reason: str | None = None  # populated only when valid is False

    # Phase 1 PR3 -- additive superset, ahead of the eventual Electron
    # cutover (Phase 1 PR4) onto this endpoint. Field names deliberately
    # match what omnibioai-studio/src/ui/components/LicenseGate.jsx already
    # reads from the currently-separate license_server.py response
    # (`license.tier`, `license.expiry`, `license.days_remaining`), so that
    # cutover is a pure URL change on the client side, not a response-shape
    # migration too.
    tier: str | None = None
    expiry: str | None = None
    days_remaining: int | None = None
    org_id: int | None = None

    # PR11.5.3 (Enterprise MFA Login Challenge) -- additive, all optional
    # with defaults, same pattern every field above already established.
    # Non-MFA response is unchanged: these three simply stay at their
    # defaults, indistinguishable from before this PR to any consumer
    # that doesn't look for them. See
    # docs/pr11-mfa-login-challenge-discovery.md SS9.
    mfa_required: bool = False
    challenge_token: str | None = None
    methods: list[str] | None = None


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
    key: str | None = None
    key_prefix: str | None = None
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


class LicensePullTokenRequest(BaseModel):
    key: str
    email: str | None = None
    machine_id: str | None = None


class LicensePullTokenResponse(BaseModel):
    ghcr_token: str


LicensePersona = Literal["developer", "application_user"]


class ManualLicenseIssueRequest(BaseModel):
    full_name: str = Field(min_length=1, max_length=255)
    email: str = Field(min_length=3, max_length=255)
    persona: LicensePersona
    validity_days: int = Field(gt=0)
    organization_id: int = Field(gt=0)
    confirm_role_change: bool = False
    confirm_replace_existing: bool = False


class ManualLicenseMetadata(BaseModel):
    id: int
    key_prefix: str
    masked_key: str
    recipient_name: str | None
    email: str
    user_id: int | None
    organization_id: int | None
    persona: LicensePersona | None
    iam_role: str | None
    plan: str
    platform: str
    created_at: datetime
    expires_at: datetime | None
    renewed_at: datetime | None
    last_used_at: datetime | None
    revoked_at: datetime | None
    revoked_reason: str | None
    status: Literal["active", "expired", "revoked"]


class ManualLicenseIssueResponse(BaseModel):
    license: ManualLicenseMetadata
    key: str | None = None
    one_time_display: bool = True
    idempotent_replay: bool = False


class ManualLicenseListResponse(BaseModel):
    items: list[ManualLicenseMetadata]
    total: int


class ManualLicensePolicyResponse(BaseModel):
    validity_days: list[int]
    personas: list[LicensePersona]
    issuance_enabled: bool
    unknown_identity_action: Literal["provisioning_required"] = "provisioning_required"


class ManualLicenseRevokeRequest(BaseModel):
    reason: str = Field(min_length=1, max_length=255)


class ManualLicenseRenewRequest(BaseModel):
    validity_days: int = Field(gt=0)


class LicenseHistoryItem(BaseModel):
    id: int
    event_type: str
    actor_user_id: int | None
    created_at: datetime | None
    before_state: dict | None
    after_state: dict | None
    metadata: dict | None


class LicenseHistoryResponse(BaseModel):
    items: list[LicenseHistoryItem]
