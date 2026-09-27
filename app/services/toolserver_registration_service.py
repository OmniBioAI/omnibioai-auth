"""Service-only issuance and live validation for TES -> ToolServer tool registration.

Sibling of delegated_execution_service, not an extension of it: a delegated
execution credential always acts for an initiating user (TES + user + org),
while tool registration happens at TES startup with no user at all. Reusing
the delegation path would mean inventing a user to act for; instead this is a
separate, narrower credential:

- issued only to an active client_credentials identity whose client *and*
  presented token both carry `toolserver.register`;
- ToolServer audience, type `toolserver_registration`, no `sub`/`email`;
- short-lived (TOOLSERVER_REGISTRATION_TOKEN_EXPIRE_MINUTES);
- validated live by introspection, so revoking/expiring the client or
  removing the scope takes effect immediately.

It grants registration only: ToolServer's run/validate routes keep requiring a
`delegated_execution` credential, which this token can never satisfy.
"""
import uuid
from datetime import datetime

from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.jwt import (
    create_toolserver_registration_token,
    decode_token,
    decode_token_for_audience,
)
from app.core.token_revocation import assert_token_usable
from app.db.models import OAuthClient

TOOLSERVER_AUDIENCE = "omnibioai-toolserver"
REGISTRATION_SCOPE = "toolserver.register"
TOKEN_TYPE = "toolserver_registration"


def _client_is_active(client: OAuthClient | None) -> bool:
    if client is None or client.status != "active":
        return False
    return not (client.expires_at and client.expires_at < datetime.utcnow())


def issue(db: Session, *, service_token: str) -> tuple[str, OAuthClient, str]:
    """Returns (registration token, client, registration_id)."""
    try:
        payload = decode_token(service_token)
        assert_token_usable(payload, db)
    except Exception as exc:
        raise HTTPException(401, "Invalid service token") from exc
    if payload.get("auth_method") != "client_credentials" or payload.get("sub") is not None:
        raise HTTPException(403, "Service token required")
    client = db.query(OAuthClient).filter(OAuthClient.client_id == payload.get("client_id")).first()
    if not _client_is_active(client):
        raise HTTPException(403, "Service identity is inactive")
    if str(payload.get("org_id")) != str(client.organization_id):
        raise HTTPException(403, "Service identity mismatch")
    if REGISTRATION_SCOPE not in set(payload.get("scopes") or []) or REGISTRATION_SCOPE not in set(client.scopes or []):
        raise HTTPException(403, "Service registration not authorized")
    registration_id = str(uuid.uuid4())
    token = create_toolserver_registration_token(
        client_id=client.client_id, organization_id=client.organization_id, registration_id=registration_id,
    )
    return token, client, registration_id


def introspect(db: Session, token: str) -> dict | None:
    try:
        payload = decode_token_for_audience(token, TOOLSERVER_AUDIENCE)
        if payload.get("aud") != TOOLSERVER_AUDIENCE or payload.get("type") != TOKEN_TYPE:
            return None
        if payload.get("sub") is not None or payload.get("email") is not None:
            return None
        if payload.get("scopes") != [REGISTRATION_SCOPE] or not payload.get("jti"):
            return None
        assert_token_usable(payload, db)
        client = db.query(OAuthClient).filter(OAuthClient.client_id == payload.get("client_id")).first()
        if not _client_is_active(client):
            return None
        if str(payload.get("org_id")) != str(client.organization_id):
            return None
        if REGISTRATION_SCOPE not in set(client.scopes or []):
            return None
        return {"client_id": client.client_id, "organization_id": str(client.organization_id),
                "scopes": [REGISTRATION_SCOPE], "registration_id": str(payload["jti"])}
    except Exception:
        return None
