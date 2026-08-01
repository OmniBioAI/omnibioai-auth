from fastapi import APIRouter, Depends, Form, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.jwt import create_service_access_token
from app.db.session import get_db
from app.schemas.oauth_client import ClientCredentialsTokenResponse
from app.services import oauth_client_service

router = APIRouter(prefix="/oauth", tags=["oauth-token"])

# Optional -- RFC 6749 SS2.3.1 allows client_id/client_secret via HTTP Basic
# instead of the request body. auto_error=False so a request that instead
# supplies them as form fields isn't rejected before the handler runs.
_basic = HTTPBasic(auto_error=False)


@router.post("/token", response_model=ClientCredentialsTokenResponse)
def issue_client_credentials_token(
    grant_type: str = Form(...),
    client_id: str | None = Form(None),
    client_secret: str | None = Form(None),
    scope: str | None = Form(None),
    basic: HTTPBasicCredentials | None = Depends(_basic),
    db: Session = Depends(get_db),
):
    if grant_type != "client_credentials":
        raise HTTPException(400, "unsupported_grant_type")

    # HTTP Basic takes precedence over body fields when both are present --
    # a caller sending both is almost certainly a client library defaulting
    # to Basic while also filling out the form struct; Basic is the more
    # deliberate signal.
    if basic is not None:
        client_id, client_secret = basic.username, basic.password

    if not client_id or not client_secret:
        raise HTTPException(400, "invalid_request -- client_id and client_secret are required")

    oauth_client = oauth_client_service.verify_client_credentials(db, client_id, client_secret)
    if not oauth_client:
        # RFC 6749 SS5.2: invalid_client covers unknown/revoked/expired/
        # wrong-secret alike -- never distinguish these to the caller.
        raise HTTPException(401, "invalid_client")

    granted_scopes = set(oauth_client.scopes or [])
    if scope:
        requested_scopes = set(scope.split())
        if not requested_scopes <= granted_scopes:
            raise HTTPException(400, "invalid_scope")
        token_scopes = sorted(requested_scopes)
    else:
        token_scopes = sorted(granted_scopes)

    oauth_client_service.mark_used(db, oauth_client)

    access_token = create_service_access_token(
        {
            "org_id": oauth_client.organization_id,
            "client_id": oauth_client.client_id,
            "scopes": token_scopes,
            "auth_method": "client_credentials",
        },
        expires_minutes=settings.CLIENT_CREDENTIALS_TOKEN_EXPIRE_MINUTES,
    )

    return ClientCredentialsTokenResponse(
        access_token=access_token,
        expires_in=settings.CLIENT_CREDENTIALS_TOKEN_EXPIRE_MINUTES * 60,
        scope=" ".join(token_scopes),
    )
