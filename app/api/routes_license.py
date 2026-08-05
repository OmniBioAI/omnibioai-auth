from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.rbac import get_current_user, require_permission
from app.schemas.license import (
    LicenseGenerateRequest,
    LicenseGenerateResponse,
    LicensePullTokenRequest,
    LicensePullTokenResponse,
    LicenseRevokeRequest,
    LicenseRevokeResponse,
    LicenseStatusResponse,
    LicenseValidateRequest,
    LicenseValidateResponse,
)
from app.services import license_service, org_service
from app.services.auth_service import MFAEnrollmentRequiredError, generate_tokens_or_mfa_challenge

router = APIRouter(prefix="/license", tags=["license"])

MANAGE_LICENSES = "manage_licenses"


# ---------------- VALIDATE ----------------
@router.post("/validate", response_model=LicenseValidateResponse)
def validate_license(req: LicenseValidateRequest, db: Session = Depends(get_db)):
    license_key, reason = license_service.validate_and_consume(
        db, req.key, req.email, req.platform
    )
    if not license_key:
        return LicenseValidateResponse(valid=False, reason=reason)

    user = license_service.get_or_create_user_for_email(db, req.email or license_key.email)
    license_service.mark_used(db, license_key, user)
    if req.machine_id:
        license_service.bind_machine_id(db, license_key, req.machine_id)

    days_remaining = None
    expiry = None
    if license_key.expires_at:
        days_remaining = max((license_key.expires_at - datetime.utcnow()).days, 0)
        expiry = license_key.expires_at.date().isoformat()

    membership = org_service.resolve_primary_membership(db, user.id)
    user_info = {"id": user.id, "email": user.email, "plan": license_key.plan}

    # PR11.5.3: single shared MFA decision point, see
    # docs/pr11-mfa-login-challenge-discovery.md SS2. The license itself
    # is already valid/consumed regardless of this branch -- only token
    # issuance is gated.
    # PR11.5.5: org-required MFA the user hasn't personally enrolled --
    # same 403 shape every other login route uses. Confirms this route
    # was never a bypass path: it already funnels through the shared
    # decision point since PR11.5.3, so org policy applies here for
    # free -- see docs/pr11-mfa-org-policy-discovery.md SS5.
    try:
        result = generate_tokens_or_mfa_challenge(db, user, auth_method="license")
    except MFAEnrollmentRequiredError:
        raise HTTPException(403, detail={
            "error": "mfa_enrollment_required",
            "message": "Your organization requires MFA enrollment",
        })
    if result["mfa_required"]:
        return LicenseValidateResponse(
            valid=True,
            mfa_required=True,
            challenge_token=result["challenge_token"],
            methods=result["methods"],
            user_info=user_info,
            tier=license_key.plan,
            expiry=expiry,
            days_remaining=days_remaining,
            org_id=membership.organization_id if membership else None,
        )

    return LicenseValidateResponse(
        valid=True,
        access_token=result["access_token"],
        refresh_token=result["refresh_token"],
        user_info=user_info,
        tier=license_key.plan,
        expiry=expiry,
        days_remaining=days_remaining,
        org_id=membership.organization_id if membership else None,
    )


# ---------------- PULL-TOKEN ----------------
@router.post("/pull-token", response_model=LicensePullTokenResponse)
def pull_token(req: LicensePullTokenRequest, db: Session = Depends(get_db)):
    """Separate from /validate so the GHCR credential is only ever handed to
    a client that is specifically about to pull private images (Docker
    startup), not returned on every routine license check -- same split
    license_server.py used, now folded into this service (Phase 1 PR4).
    Key-only lookup (no email), same as Electron's /validate calls; does
    not consume a use or issue tokens, purely a validity + credential
    check.
    """
    license_key, reason = license_service.validate_and_consume(db, req.key, None, "desktop")
    if not license_key:
        status_code = 404 if reason == "invalid_key" else 403
        raise HTTPException(status_code, reason)
    if req.machine_id:
        license_service.bind_machine_id(db, license_key, req.machine_id)
    return LicensePullTokenResponse(ghcr_token=settings.GHCR_PULL_TOKEN)


# ---------------- GENERATE (admin) ----------------
@router.post("/generate", response_model=LicenseGenerateResponse)
def generate_license(
    req: LicenseGenerateRequest,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_LICENSES)),
):
    license_key = license_service.create_license(
        db,
        email=req.email,
        plan=req.plan,
        platform=req.platform,
        expires_days=req.expires_days,
        max_uses=req.max_uses,
    )
    return LicenseGenerateResponse(
        key=license_key.key,
        email=license_key.email,
        plan=license_key.plan,
        platform=license_key.platform,
        expires_at=license_key.expires_at,
        max_uses=license_key.max_uses,
    )


# ---------------- STATUS ----------------
@router.get("/status", response_model=LicenseStatusResponse)
def license_status(db: Session = Depends(get_db), user=Depends(get_current_user)):
    license_key = license_service.get_status_for_user(db, int(user["sub"]))
    if not license_key:
        raise HTTPException(404, "No license found for this account")
    return LicenseStatusResponse(
        key=license_key.key,
        plan=license_key.plan,
        platform=license_key.platform,
        expires_at=license_key.expires_at,
        usage_count=license_key.usage_count,
        max_uses=license_key.max_uses,
        last_used_at=license_key.last_used_at,
        revoked=license_key.revoked_at is not None,
    )


# ---------------- REVOKE (admin) ----------------
@router.post("/revoke", response_model=LicenseRevokeResponse)
def revoke_license(
    req: LicenseRevokeRequest,
    db: Session = Depends(get_db),
    user=Depends(require_permission(MANAGE_LICENSES)),
):
    success = license_service.revoke(db, req.key, req.reason)
    if not success:
        raise HTTPException(404, "License key not found")
    return LicenseRevokeResponse(success=success)
