"""#443: POST /service/mint-user-token -- lets a trusted internal service
mint a real, short-lived access token for an already-authenticated user
of that service, so a downstream system (TES, via api-gateway) sees the
real user's identity instead of the calling service's own shared one.

Reuses `service_token.mint`, a new, deliberately narrow permission
(app/core/permission_names.py) -- not model.use, not workflow.execute,
not anything the calling service already holds via its own role, and
not folded into `override_sso_enforcement` either despite the shared
`require_permission`/GLOBAL-scope shape: that permission means "suspend
an org's own enforced SSO", a completely different capability that
happens to be checked the same way. Granted to exactly one dedicated
role (`bio_agent_service`, see app/db/init_admin.py::ensure_bio_agent_
service_role), assigned to exactly one account (svc-bio-agent) -- never
to "scientist", the role that account also holds for its other
(workflow.execute-shaped) TES calls, so an ordinary scientist-role
holder never incidentally gains the ability to mint tokens for other
users.

Security posture, stated explicitly because it is the one thing this
endpoint cannot verify for itself: it trusts the caller's assertion of
`email` completely. There is no independent proof that the caller's own
upstream session actually belongs to that email -- that verification
must have already happened one layer up (e.g. bio_agent's own
allauth/OAuth login), before the caller (holding service_token.mint)
ever reaches this endpoint. This permission must never be granted to a
service that itself accepts an unverified, user-supplied email.
"""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.rbac import require_permission
from app.schemas.service_mint import MintUserTokenOut, MintUserTokenRequest
from app.services import service_mint_service

router = APIRouter(tags=["service-mint"])

MINT_USER_SERVICE_TOKEN = "service_token.mint"


@router.post("/service/mint-user-token", response_model=MintUserTokenOut)
def mint_user_token(
    body: MintUserTokenRequest,
    db: Session = Depends(get_db),
    caller: dict = Depends(require_permission(MINT_USER_SERVICE_TOKEN)),
):
    access_token, expires_in = service_mint_service.mint_user_service_token(
        db, body.email, actor_user_id=int(caller["sub"]),
    )
    return MintUserTokenOut(access_token=access_token, expires_in=expires_in)
