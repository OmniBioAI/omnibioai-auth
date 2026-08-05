"""PR11.5.2 (Enterprise TOTP MFA Enrollment). Self-service, own-account
only -- bare get_current_user, no permission required, same shape
routes_config.py's GET /auth/config already uses (see
docs/pr11-totp-enrollment-discovery.md SS1). All mutation/audit logic
lives in app/services/mfa_service.py; this module only translates its
exceptions to HTTP status codes.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.models import MFADevice
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.mfa import MFADeviceOut, TOTPEnrollOut, TOTPVerifyIn
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
