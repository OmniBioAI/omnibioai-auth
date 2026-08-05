from datetime import datetime

from pydantic import BaseModel


class LicenseValidateRequest(BaseModel):
    key: str
    # Optional as of Phase 1 PR4: the Electron client (LicenseGate.jsx) only
    # ever collects a license key, never an email -- the desktop activation
    # flow the now-decommissioned license_server.py served. When omitted,
    # the license's own stored email is used for user lookup/creation and
    # the email-match check is skipped entirely; the web redemption flow
    # (email present) is unchanged.
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


class LicensePullTokenRequest(BaseModel):
    key: str
    machine_id: str | None = None


class LicensePullTokenResponse(BaseModel):
    ghcr_token: str
