"""Generic write-only integration credential lifecycle APIs."""

import hmac

from fastapi import APIRouter, Depends, Header, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.rbac import get_current_user
from app.schemas.integration_credentials import (
    ConnectionTestOut,
    CredentialMetadataOut,
    CredentialReferenceIn,
    CredentialReferenceOut,
    CredentialResolveIn,
    CredentialResolveOut,
    CredentialWriteIn,
)
from app.services import integration_credential_service as service

router = APIRouter(prefix="/integrations/credentials", tags=["integration-credentials"])
internal_router = APIRouter(prefix="/internal/integration-credentials", tags=["integration-credentials"])


def _call(operation):
    try:
        return operation()
    except service.CredentialError as exc:
        raise HTTPException(exc.status_code, str(exc)) from None
    except RuntimeError as exc:
        # Encryption unavailable is a deployment error. Never fall back to
        # plaintext or include submitted values in the error.
        raise HTTPException(503, "Credential encryption is unavailable.") from exc


@router.get("", response_model=list[CredentialMetadataOut])
def list_credentials(db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    return service.list_metadata(db, user)


@router.get("/{provider_id}/status")
def credential_status(provider_id: str, db: Session = Depends(get_db), user: dict = Depends(get_current_user)):
    return _call(lambda: service.status(db, provider_id, user))


@router.put("/{provider_id}/{scope}", response_model=CredentialMetadataOut)
def put_credential(
    provider_id: str,
    scope: str,
    body: CredentialWriteIn,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    row = _call(lambda: service.set_credential(
        db, provider_id, scope, body.credentials, body.display_metadata, user
    ))
    return service.metadata(row)


@router.delete("/{provider_id}/{scope}", status_code=204)
def delete_credential(
    provider_id: str,
    scope: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    _call(lambda: service.revoke_credential(db, provider_id, scope, user))
    return Response(status_code=204)


@router.post("/{provider_id}/references", response_model=CredentialReferenceOut)
def issue_credential_reference(
    provider_id: str,
    body: CredentialReferenceIn,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return _call(lambda: service.issue_reference(db, provider_id, body.consumer, body.purpose, user))


@router.post("/{provider_id}/test", response_model=ConnectionTestOut)
def test_connection(
    provider_id: str,
    db: Session = Depends(get_db),
    user: dict = Depends(get_current_user),
):
    return _call(lambda: service.connection_test(db, provider_id, user))


@internal_router.post("/resolve", response_model=CredentialResolveOut)
def resolve_credential_reference(
    body: CredentialResolveIn,
    db: Session = Depends(get_db),
    x_integration_credential_service_secret: str = Header(default=""),
):
    expected = settings.INTEGRATION_CREDENTIAL_SERVICE_SECRET
    if not expected:
        raise HTTPException(503, "Credential resolution is not configured.")
    if not hmac.compare_digest(x_integration_credential_service_secret.encode(), expected.encode()):
        raise HTTPException(403, "Forbidden.")
    return _call(lambda: service.resolve_reference(
        db, body.credential_ref, body.provider_id, body.consumer, body.purpose
    ))
