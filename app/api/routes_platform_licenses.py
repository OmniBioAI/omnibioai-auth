"""Privileged manual-license administration for the Control Center."""
from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.models import User
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.license import (
    LicenseHistoryItem,
    LicenseHistoryResponse,
    ManualLicenseIssueRequest,
    ManualLicenseIssueResponse,
    ManualLicenseListResponse,
    ManualLicenseMetadata,
    ManualLicensePolicyResponse,
    ManualLicenseRenewRequest,
    ManualLicenseRevokeRequest,
)
from app.services import manual_license_service
from app.services.manual_license_service import ManualLicenseError

router = APIRouter(prefix="/platform/licenses", tags=["platform-licenses"])
ADMIN_ROLE = "admin"
PLATFORM_OWNER_ROLE = "platform_admin"
DESIGNATED_ADMIN_USER_ID = 1


def authorized_license_admin(identity=Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    user = db.query(User).filter(User.id == int(identity["sub"]), User.status == "active").first()
    if user is None:
        raise HTTPException(403, "Forbidden")
    roles = {role.name for role in user.roles}
    is_owner = {PLATFORM_OWNER_ROLE, ADMIN_ROLE}.issubset(roles)
    is_designated_admin = user.id == DESIGNATED_ADMIN_USER_ID and ADMIN_ROLE in roles
    if not (is_owner or is_designated_admin):
        raise HTTPException(403, "Manual license administration is restricted")
    return user


def _raise(error: ManualLicenseError) -> None:
    raise HTTPException(error.status_code, detail={"code": error.code, "message": str(error)})


@router.get("/policy", response_model=ManualLicensePolicyResponse)
def policy(_actor: User = Depends(authorized_license_admin)):
    validities = list(manual_license_service.configured_validities())
    return ManualLicensePolicyResponse(
        validity_days=validities,
        personas=["developer", "application_user"],
        issuance_enabled=bool(validities),
    )


@router.post("", response_model=ManualLicenseIssueResponse)
def issue_license(
    request: ManualLicenseIssueRequest,
    idempotency_key: str = Header(alias="Idempotency-Key"),
    db: Session = Depends(get_db),
    actor: User = Depends(authorized_license_admin),
):
    kwargs = dict(
        actor_user_id=actor.id, idempotency_key=idempotency_key,
        full_name=request.full_name, email=request.email, persona=request.persona,
        validity_days=request.validity_days, organization_id=request.organization_id,
        confirm_role_change=request.confirm_role_change,
        confirm_replace_existing=request.confirm_replace_existing,
    )
    try:
        license_key, key, replayed = manual_license_service.issue(db, **kwargs)
    except IntegrityError:
        db.rollback()
        try:
            license_key, key, replayed = manual_license_service.issue(db, **kwargs)
        except ManualLicenseError as error:
            _raise(error)
    except ManualLicenseError as error:
        db.rollback()
        _raise(error)
    return ManualLicenseIssueResponse(
        license=ManualLicenseMetadata(**manual_license_service.metadata_for(db, license_key)),
        key=key,
        idempotent_replay=replayed,
    )


@router.get("", response_model=ManualLicenseListResponse)
def list_licenses(
    organization_id: int | None = Query(default=None, gt=0),
    db: Session = Depends(get_db),
    _actor: User = Depends(authorized_license_admin),
):
    rows = manual_license_service.list_licenses(db, organization_id=organization_id)
    return ManualLicenseListResponse(
        items=[ManualLicenseMetadata(**manual_license_service.metadata_for(db, row)) for row in rows],
        total=len(rows),
    )


@router.get("/{license_id}", response_model=ManualLicenseMetadata)
def get_license(license_id: int, db: Session = Depends(get_db), _actor: User = Depends(authorized_license_admin)):
    row = manual_license_service.get_license(db, license_id)
    if row is None:
        raise HTTPException(404, "License not found")
    return ManualLicenseMetadata(**manual_license_service.metadata_for(db, row))


@router.post("/{license_id}/revoke", response_model=ManualLicenseMetadata)
def revoke_license(
    license_id: int,
    request: ManualLicenseRevokeRequest,
    db: Session = Depends(get_db),
    actor: User = Depends(authorized_license_admin),
):
    row = manual_license_service.get_license(db, license_id, lock=True)
    if row is None:
        raise HTTPException(404, "License not found")
    row = manual_license_service.revoke(db, row, actor_user_id=actor.id, reason=request.reason)
    return ManualLicenseMetadata(**manual_license_service.metadata_for(db, row))


@router.post("/{license_id}/renew", response_model=ManualLicenseMetadata)
def renew_license(
    license_id: int,
    request: ManualLicenseRenewRequest,
    db: Session = Depends(get_db),
    actor: User = Depends(authorized_license_admin),
):
    row = manual_license_service.get_license(db, license_id, lock=True)
    if row is None:
        raise HTTPException(404, "License not found")
    try:
        row = manual_license_service.renew(db, row, actor_user_id=actor.id, validity_days=request.validity_days)
    except ManualLicenseError as error:
        db.rollback()
        _raise(error)
    return ManualLicenseMetadata(**manual_license_service.metadata_for(db, row))


@router.get("/{license_id}/history", response_model=LicenseHistoryResponse)
def license_history(license_id: int, db: Session = Depends(get_db), _actor: User = Depends(authorized_license_admin)):
    if manual_license_service.get_license(db, license_id) is None:
        raise HTTPException(404, "License not found")
    return LicenseHistoryResponse(items=[
        LicenseHistoryItem(
            id=item.id, event_type=item.event_type, actor_user_id=item.actor_user_id,
            created_at=item.created_at, before_state=item.before_state,
            after_state=item.after_state, metadata=item.event_metadata,
        )
        for item in manual_license_service.history(db, license_id)
    ])
