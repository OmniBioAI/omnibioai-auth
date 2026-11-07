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

#96: the caller must also state how it verified the address
(`email_verified` + `verification_method`), and each caller gets a
fixed-window request budget (SERVICE_MINT_RATE_LIMIT per
SERVICE_MINT_RATE_WINDOW_SECONDS). Every refusal for a target returns the
same 403, so the response never says why; the reason is in the audit event.
Accounts with admin or service permissions are refused unless the caller
also holds service_token.mint_privileged: those users sign in themselves
and use their own token.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core import rate_limit
from app.core.config import settings
from app.db.session import get_db
from app.rbac import require_permission
from app.schemas.service_mint import MintUserTokenOut, MintUserTokenRequest
from app.services import service_mint_service
from app.services.service_mint_service import MINT_PRIVILEGED_PERMISSION, MintRefused

router = APIRouter(tags=["service-mint"])

MINT_USER_SERVICE_TOKEN = "service_token.mint"
MINT_REFUSED_DETAIL = "Cannot mint a token for this user"


def _rate_limited(caller_id: str) -> tuple[bool, bool]:
    """Returns (limited, newly_limited). record_attempt locks once the
    count reaches max_attempts, so limit + 1 lets exactly `limit` through."""
    limit = settings.SERVICE_MINT_RATE_LIMIT
    window = settings.SERVICE_MINT_RATE_WINDOW_SECONDS
    key = str(caller_id)[:64]
    result = rate_limit.record_attempt(
        f"svc-mint:count:{key}", f"svc-mint:lock:{key}",
        window_seconds=window, max_attempts=limit + 1, lockout_seconds=window,
        fallback_window_seconds=window, fallback_max_attempts=limit + 1,
    )
    return result.locked, result.newly_locked


@router.post("/service/mint-user-token", response_model=MintUserTokenOut)
def mint_user_token(
    body: MintUserTokenRequest,
    db: Session = Depends(get_db),
    caller: dict = Depends(require_permission(MINT_USER_SERVICE_TOKEN)),
):
    actor_user_id = int(caller["sub"])
    limited, newly_limited = _rate_limited(caller["sub"])
    if limited:
        # One audit row when the limit is first hit, not one per request.
        if newly_limited:
            service_mint_service.log_denied(
                db, actor_user_id, "rate_limited", target_email=body.email,
                requested_org_id=body.org_id, verification_method=body.verification_method,
            )
        raise HTTPException(429, "Too many mint requests; try again later")

    try:
        access_token, expires_in = service_mint_service.mint_user_service_token(
            db, body.email, actor_user_id=actor_user_id,
            verification_method=body.verification_method, org_id=body.org_id,
            allow_privileged=MINT_PRIVILEGED_PERMISSION in caller.get("permissions", []),
        )
    except MintRefused:
        raise HTTPException(403, MINT_REFUSED_DETAIL) from None
    return MintUserTokenOut(access_token=access_token, expires_in=expires_in)
