"""
OmniBioAI app.api.routes_license.

Purpose:
    Defines HTTP route handlers for app.api.routes_license, including validate_license, pull_token, generate_license and license_status.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.db.models import User
from app.rbac import get_current_user, get_optional_current_user, require_permission
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
from app.services import audit_service, license_service, org_service
from app.services.audit_service import AuditEventType

router = APIRouter(prefix="/license", tags=["license"])

MANAGE_LICENSES = "manage_licenses"


# ---------------- VALIDATE ----------------
@router.post("/activate", response_model=LicenseValidateResponse)
@router.post("/validate", response_model=LicenseValidateResponse)
def validate_license(
    req: LicenseValidateRequest,
    db: Session = Depends(get_db),
    identity=Depends(get_optional_current_user),
):
    presented = license_service.lookup_license(db, req.key, lock=True)
    if presented is None:
        return LicenseValidateResponse(valid=False, reason="invalid_key")

    activation_without_session = identity is None
    if activation_without_session:
        if not req.email:
            raise HTTPException(422, "Email is required for license activation")
        authenticated_user = (
            db.query(User).filter(User.id == presented.user_id).first()
            if presented.user_id is not None
            else db.query(User).filter(User.email == presented.email).first()
        )
        if authenticated_user is None or authenticated_user.status != "active":
            return LicenseValidateResponse(valid=False, reason="owner_unavailable")
    else:
        authenticated_user = db.query(User).filter(User.id == int(identity["sub"])).first()

    license_key, reason = license_service.authorize_for_identity(db, req.key, authenticated_user, req.platform)
    if not license_key:
        return LicenseValidateResponse(valid=False, reason=reason)
    if req.email is not None and req.email.strip().lower() != authenticated_user.email.lower():
        return LicenseValidateResponse(valid=False, reason="identity_mismatch")

    first_activation = license_service.mark_used(db, license_key, authenticated_user, commit=False)
    if req.machine_id:
        license_service.bind_machine_id(db, license_key, req.machine_id, commit=False)

    audit_service.log_event(
        db,
        AuditEventType.LICENSE_ACTIVATED if first_activation else AuditEventType.LICENSE_VALIDATED,
        actor_user_id=authenticated_user.id,
        target_user_id=authenticated_user.id,
        organization_id=license_key.organization_id,
        resource_type="license",
        resource_id=license_key.id,
        after_state={"status": "active", "platform": req.platform},
        metadata={"activation_without_session": activation_without_session},
        commit=False,
    )
    db.commit()

    days_remaining = None
    expiry = None
    if license_key.expires_at:
        days_remaining = max((license_key.expires_at - license_service.utc_now()).days, 0)
        expiry = license_key.expires_at.date().isoformat()

    membership = org_service.resolve_primary_membership(db, authenticated_user.id)
    user_info = {
        "id": authenticated_user.id,
        "email": authenticated_user.email,
        "plan": license_key.plan,
    }

    response = LicenseValidateResponse(
        valid=True,
        user_info=user_info,
        tier=license_key.plan,
        expiry=expiry,
        days_remaining=days_remaining,
        org_id=membership.organization_id if membership else None,
    )
    return response


# ---------------- PULL-TOKEN ----------------
@router.post("/pull-token", response_model=LicensePullTokenResponse)
def pull_token(
    req: LicensePullTokenRequest,
    db: Session = Depends(get_db),
    identity=Depends(get_optional_current_user),
):
    """Separate from /validate so the GHCR credential is only ever handed to
    a client that is specifically about to pull private images (Docker
    startup), not returned on every routine license check -- same split
    license_server.py used, now folded into this service (Phase 1 PR4).
    Requires the same independently authenticated owner identity as
    /validate. It does not consume a use or issue identity tokens.
    """
    presented = license_service.lookup_license(db, req.key)
    if presented is None:
        raise HTTPException(404, "invalid_key")
    if identity is not None:
        authenticated_user = db.query(User).filter(User.id == int(identity["sub"])).first()
    else:
        if not req.email:
            raise HTTPException(422, "Email is required")
        authenticated_user = (
            db.query(User).filter(User.id == presented.user_id).first()
            if presented.user_id is not None
            else db.query(User).filter(User.email == presented.email).first()
        )
    if authenticated_user is None or authenticated_user.status != "active":
        raise HTTPException(403, "owner_unavailable")
    if req.email is not None and req.email.strip().lower() != authenticated_user.email.lower():
        raise HTTPException(403, "identity_mismatch")
    license_key, reason = license_service.authorize_for_identity(
        db, req.key, authenticated_user, "desktop"
    )
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
    raise HTTPException(410, "Use the idempotent /platform/licenses issuance API")


# ---------------- STATUS ----------------
@router.get("/status", response_model=LicenseStatusResponse)
def license_status(db: Session = Depends(get_db), user=Depends(get_current_user)):
    license_key = license_service.get_status_for_user(db, int(user["sub"]))
    if not license_key:
        raise HTTPException(404, "No license found for this account")
    return LicenseStatusResponse(
        key=None,
        key_prefix=license_key.key_prefix or ((license_key.key or "")[:9]),
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
