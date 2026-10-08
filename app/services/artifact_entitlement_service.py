"""Live Billing context validation using the existing OAuth and Artifact grant.

This is not a user-token exchange. The service bearer retains the existing
platform audience; the separate proof retains its Artifact-only audience.
Only explicitly provisioned, organization-bound OAuth clients may use it.
"""
from fastapi import HTTPException

from app.core.config import settings
from app.core.token_revocation import assert_token_usable
from app.db.models import Organization
from app.services import artifact_delegation_service, delegated_execution_service

ENTITLEMENT_SCOPE = "billing.artifact_entitlements"


def context(db, *, service_token: str, artifact_token: str) -> dict:
    payload, caller = delegated_execution_service._active_service(db, service_token, ENTITLEMENT_SCOPE)
    # The generic decoder tolerates pre-migration claims. This new boundary does not.
    if (payload.get("iss") != settings.JWT_ISSUER or
            payload.get("aud") != settings.JWT_AUDIENCE or
            payload.get("type") != "access" or
            type(payload.get("exp")) is not int or not payload.get("jti") or
            "sub" in payload or "email" in payload):
        raise HTTPException(401, "Invalid service credential")
    assert_token_usable(payload, db)
    identity = artifact_delegation_service.introspect(db, artifact_token)
    if identity is None or str(caller.organization_id) != identity["organization_id"]:
        raise HTTPException(403, "Artifact entitlement context unavailable")
    if not db.query(Organization).filter_by(id=caller.organization_id, status="active").first():
        raise HTTPException(403, "Artifact entitlement context unavailable")
    return {**identity, "service_client_id": caller.client_id,
            "service_audience": settings.JWT_AUDIENCE, "scope": ENTITLEMENT_SCOPE}
