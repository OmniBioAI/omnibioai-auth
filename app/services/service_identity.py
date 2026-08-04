"""PR9 (Enterprise IAM Foundation): service identity resolution -- the
machine-to-machine counterpart to identity_service.py (PR8). Constructs
the projection shared by GET /service/me and
GET /platform/services/{client_id}: same shape (schemas.service_identity
.ServiceIdentityOut), so routes stay thin and there is no duplicated
permission-aggregation logic between the two.

Two distinct resolution paths, deliberately not unified into one function:

- identity_from_token_payload: reflects *this specific token's* granted
  scopes (the JWT's own "scopes" claim) -- mirrors identity_service
  .build_identity's "global_permissions must match the caller's own JWT"
  contract from PR8. A client's configured scopes can change after a
  token was issued (or the client can be revoked entirely); this function
  also re-checks the client's current status in the database on every
  call, closing a real gap user tokens don't have otherwise: unlike user
  sessions (checked live via assert_token_usable on every request), a
  bare service JWT's signature alone says nothing about whether the
  issuing client is still active.
- identity_for_client_id: a platform-admin lookup by public client_id,
  with no token payload involved -- reflects the client's *current*
  database-configured scopes, not any particular past token's.
"""
from sqlalchemy.orm import Session

from app.db.models import OAuthClient


def _service_identity_dict(client: OAuthClient, permissions: list[str]) -> dict:
    return {
        "client_id": client.client_id,
        "name": client.name,
        "organization_id": client.organization_id,
        "permissions": sorted(permissions),
        "created_at": client.created_at,
        "active": client.status == "active",
    }


def identity_from_token_payload(db: Session, payload: dict) -> dict | None:
    """None if the client_id in the token no longer exists, or is no
    longer active -- the caller (routes_service_identity.py) maps that to
    a 403, distinct from an outright invalid/malformed token (401)."""
    client_id = payload.get("client_id")
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if client is None or client.status != "active":
        return None
    return _service_identity_dict(client, payload.get("scopes", []))


def identity_for_client_id(db: Session, client_id: str) -> dict | None:
    """None if no such client -- the caller maps that to a 404. Unlike
    identity_from_token_payload, an inactive/revoked client is still
    returned here (active=False) rather than treated as absent -- a
    platform admin looking a client up by id is diagnosing it, not
    authenticating as it, so a revoked client's record should stay
    visible, not disappear."""
    client = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
    if client is None:
        return None
    return _service_identity_dict(client, client.scopes or [])
