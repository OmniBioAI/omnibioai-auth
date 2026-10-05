"""
OmniBioAI app.core.token_revocation.

Purpose:
    Defines blacklist_access_token and assert_token_usable for app.core.token_revocation.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

import os
from datetime import datetime

import redis as _redis_sync
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.jwt import decode_token
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


def blacklist_access_token(access_token: str) -> None:
    """Store access token jti in Redis blacklist with remaining-lifetime
    TTL. Moved here from app/api/routes_auth.py's own (formerly private)
    `_blacklist_access_token` (PR11, SLO) -- this module already owns
    the Redis client every read of the blacklist (assert_token_usable,
    above) goes through, and the SAML SP-initiated logout endpoint
    (routes_saml.py) needs the identical behavior `/auth/logout` already
    has, not a second, parallel implementation. routes_auth.py's own
    /auth/logout now calls this public function directly instead of a
    module-private copy; behavior is byte-identical, only the home
    changed.
    """
    try:
        payload = decode_token(access_token)
    except Exception:
        # Malformed or expired input has no revocation entry to write.
        return

    jti = payload.get("jti")
    if not jti:
        return

    exp = payload.get("exp", 0)
    now = int(datetime.utcnow().timestamp())
    ttl = max(exp - now, 1)
    try:
        _blacklist.setex(f"blacklist:jti:{jti}", ttl, "1")
    except Exception:
        # A successful database/session revoke is not enough: the access
        # token remains usable unless its Redis blacklist write succeeds.
        # Surface dependency failure instead of reporting logout success.
        raise HTTPException(503, "Authentication state unavailable")


def assert_token_usable(payload: dict, db: Session) -> None:
    """Centralizes the revocation/suspension checks that used to live only
    inline in `/auth/validate` (app/api/routes_auth.py) -- Redis blacklist
    on `jti`, the `revoked_tokens` table on `jti`, and `User.status`. Before
    this existed, `get_current_user` (app/rbac.py) -- the dependency every
    route in this service actually depends on -- decoded a token's
    signature and expiry and nothing else, so logout/suspension/revocation
    had no effect on any direct caller of this service, only on callers
    that happened to go through `/auth/validate`'s remote-validation path.

    Raises HTTPException(401) for revoked/inactive tokens and HTTPException
    (503) when Redis-backed revocation state is unavailable. Callers that need a boolean
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
            # Revocation state is part of the authorization decision. An
            # unavailable or authentication-rejected Redis must never be
            # treated as an empty blacklist, because that would silently
            # make revoked access tokens usable again.
            raise HTTPException(503, "Authentication state unavailable")
        if blacklisted:
            raise HTTPException(401, "Token revoked")

    if jti and db.query(RevokedToken).filter(RevokedToken.token_jti == jti).first():
        raise HTTPException(401, "Token revoked")

    sub = payload.get("sub")
    if sub is not None:
        user = db.query(User).filter(User.id == sub).first()
        if not user or user.status != "active":
            raise HTTPException(401, "User inactive")
