import os

import redis as _redis_sync
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.db.models import RevokedToken, User

# Canonical home for the access-token blacklist client. `/auth/logout`
# (app/api/routes_auth.py) writes to this same object via
# `token_revocation._blacklist` (qualified attribute access, not a
# `from ... import _blacklist` rebinding) so tests can patch exactly one
# name and have both the write path (logout) and the read path
# (assert_token_usable, below) see the same mock.
_blacklist = _redis_sync.from_url(
    os.getenv("REDIS_URL", "redis://redis:6379"),
    decode_responses=True,
)


def assert_token_usable(payload: dict, db: Session) -> None:
    """Centralizes the revocation/suspension checks that used to live only
    inline in `/auth/validate` (app/api/routes_auth.py) -- Redis blacklist
    on `jti`, the `revoked_tokens` table on `jti`, and `User.status`. Before
    this existed, `get_current_user` (app/rbac.py) -- the dependency every
    route in this service actually depends on -- decoded a token's
    signature and expiry and nothing else, so logout/suspension/revocation
    had no effect on any direct caller of this service, only on callers
    that happened to go through `/auth/validate`'s remote-validation path.

    Raises HTTPException(401) on any failure. Callers that need a boolean
    instead of a raise (e.g. `/auth/validate`'s `{"valid": False}` contract)
    should catch the exception, not reimplement these checks.

    A payload with no `jti` or no `sub` (e.g. a client_credentials service
    token -- see app/core/jwt.py's create_service_access_token) is not an
    error here: those checks are simply skipped, the same way they were
    unreachable for such tokens before this function existed. Rejecting
    service tokens from user-identity checks remains get_current_user's own
    job (its existing `auth_method == "client_credentials"` check), not
    this function's.
    """
    jti = payload.get("jti")

    if jti:
        try:
            blacklisted = _blacklist.exists(f"blacklist:jti:{jti}")
        except Exception:
            # Fail open on Redis specifically -- matches this codebase's
            # own established philosophy for this exact blacklist
            # (_blacklist_access_token's "fail open -- never block
            # logout"). Without this, an unreachable Redis would raise
            # uncaught here and 500 every authenticated request in the
            # service (this function runs inside get_current_user, which
            # every route depends on) -- turning a transient Redis blip
            # into a full service outage, a strictly worse outcome than
            # temporarily not enforcing the blacklist. The RevokedToken
            # and User.status checks below are deliberately NOT wrapped
            # this way: the database is already a hard dependency for
            # every route in this service, so failing open there would
            # newly mask a real problem rather than avoid introducing one.
            blacklisted = False
        if blacklisted:
            raise HTTPException(401, "Token revoked")

    if jti and db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first():
        raise HTTPException(401, "Token revoked")

    sub = payload.get("sub")
    if sub is not None:
        user = db.query(User).filter(User.id == sub).first()
        if not user or user.status != "active":
            raise HTTPException(401, "User inactive")
