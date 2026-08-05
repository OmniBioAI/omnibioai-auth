"""PR11.5.2 (Enterprise TOTP MFA Enrollment) + PR11.5.3 (Enterprise MFA
Login Challenge). Self-service, own-account only -- bare
get_current_user, no permission required, same shape routes_config.py's
GET /auth/config already uses (see
docs/pr11-totp-enrollment-discovery.md SS1) -- with one deliberate
exception: POST /challenge below, which authenticates via its request
body instead (see docs/pr11-mfa-login-challenge-discovery.md SS8). All
mutation/audit logic lives in app/services/mfa_service.py; this module
only translates its exceptions to HTTP status codes.
"""
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.api.routes_auth import _set_session_cookie
from app.db.models import MFADevice
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.auth import TokenResponse
from app.schemas.mfa import MFAChallengeVerifyIn, MFADeviceOut, TOTPEnrollOut, TOTPVerifyIn
from app.services import mfa_service

router = APIRouter(prefix="/users/me/mfa", tags=["mfa"])


def _device_out(device: MFADevice) -> MFADeviceOut:
    return MFADeviceOut(
        id=device.id,
        device_type=device.device_type,
        label=device.label,
        created_at=device.created_at,
        verified_at=device.verified_at,
        last_used_at=device.last_used_at,
    )


@router.post("/totp/enroll", response_model=TOTPEnrollOut, status_code=201)
def start_totp_enrollment(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    try:
        device, uri = mfa_service.start_totp_enrollment(db, int(user["sub"]), user["email"])
    except RuntimeError as e:
        # crypto.encrypt() raises RuntimeError when CONFIG_ENCRYPTION_KEY
        # isn't set -- same handling as routes_config.py's update_config:
        # a loud, clear 500, never a silently-stored plaintext secret.
        raise HTTPException(500, str(e))
    return TOTPEnrollOut(device_id=device.id, otpauth_uri=uri)


@router.post("/totp/verify", response_model=MFADeviceOut)
def verify_totp_enrollment(
    body: TOTPVerifyIn,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    try:
        device = mfa_service.verify_totp_enrollment(db, int(user["sub"]), body.device_id, body.code)
    except LookupError:
        raise HTTPException(404, "MFA device not found")
    except ValueError as e:
        raise HTTPException(400, str(e))
    return _device_out(device)


@router.get("/devices", response_model=list[MFADeviceOut])
def list_mfa_devices(
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return [_device_out(d) for d in mfa_service.list_devices(db, int(user["sub"]))]


@router.delete("/devices/{device_id}", status_code=204)
def remove_mfa_device(
    device_id: int,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    try:
        mfa_service.remove_device(db, int(user["sub"]), device_id)
    except LookupError:
        raise HTTPException(404, "MFA device not found")


@router.post("/challenge", response_model=TokenResponse)
def verify_mfa_challenge(
    body: MFAChallengeVerifyIn,
    response: Response,
    db: Session = Depends(get_db),
):
    """PR11.5.3. Deliberately NOT gated by get_current_user, unlike every
    other route in this file -- the caller has no access token yet at
    this point (that's the entire premise: they're one step before ever
    having one). body.challenge_token is itself the credential, already
    scoped to exactly one user by construction (see
    app/core/jwt.py::create_mfa_challenge_token) -- there is no
    cross-user ambiguity for get_current_user to resolve here."""
    try:
        access, refresh = mfa_service.verify_mfa_challenge(db, body.challenge_token, body.code)
    except mfa_service.MFAChallengeError as e:
        raise HTTPException(401, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Same cookie helper /auth/login itself uses -- imported rather than
    # reimplemented so domain/secure/httponly/samesite/max-age stay in
    # exact lockstep with that route's own policy.
    _set_session_cookie(response, refresh)
    return TokenResponse(access_token=access, refresh_token=refresh)
