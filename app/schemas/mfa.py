from datetime import datetime

from pydantic import BaseModel


class TOTPEnrollOut(BaseModel):
    """Response for POST /users/me/mfa/totp/enroll. The otpauth_uri
    embeds the plaintext secret -- returned exactly once, here, and
    never persisted or logged anywhere (see
    docs/pr11-totp-enrollment-discovery.md SS3)."""
    device_id: int
    otpauth_uri: str


class TOTPVerifyIn(BaseModel):
    device_id: int
    code: str


class MFADeviceOut(BaseModel):
    """Safe metadata only -- no encrypted_secret field, ever, mirroring
    GlobalConfigOut's own "has_* flag, never the credential" shape
    (app/schemas/config.py)."""
    id: int
    device_type: str
    label: str | None
    created_at: datetime
    verified_at: datetime | None
    last_used_at: datetime | None


class MFAChallengeVerifyIn(BaseModel):
    """PR11.5.3 (Enterprise MFA Login Challenge). challenge_token is
    itself the credential proving primary auth already succeeded -- see
    docs/pr11-mfa-login-challenge-discovery.md SS8 for why this endpoint,
    unlike its siblings above, is not gated by get_current_user."""
    challenge_token: str
    code: str


class RecoveryCodesOut(BaseModel):
    """PR11.5.4. Returned only once, at generation/regeneration time --
    no endpoint ever returns plaintext codes again afterward (see
    docs/pr11-mfa-recovery-codes-discovery.md)."""
    codes: list[str]


class RecoveryCodesStatusOut(BaseModel):
    """PR11.5.4. Count only -- codes themselves are never retrievable
    after generation."""
    remaining: int


class MFAResetOut(BaseModel):
    """PR11.5.4. Response for the admin reset endpoint
    (POST /platform/users/{user_id}/mfa/reset)."""
    user_id: int
    mfa_enabled: bool
    mfa_status: str
