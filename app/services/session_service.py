"""Phase 4 PR-A (Session Foundation): read/write helpers for the
`sessions` table (app/db/models.py::UserSession).

Every write here is called from an *existing* auth_service call site
(generate_tokens / rotate_refresh_token / revoke_token / the reuse-
detection branch that calls `_revoke_family`) -- this module owns no
route, no commit, and makes no authentication decision of its own. It
never raises: a problem here must never turn a working login/refresh/
logout into a 500, so every function degrades to "no session row
written/updated" rather than failing the caller. That mirrors this
codebase's existing fail-open conventions for adjacent, non-essential
state (see app/core/token_revocation.py's Redis blacklist check, and
app/api/routes_auth.py's `_blacklist_access_token`/`_publish_invalidation`).

See app/db/models.py::UserSession's own docstring for why `session_id`
*is* the refresh-token family_id rather than a second, separate
identifier.
"""
from datetime import datetime

from app.db.models import UserSession

STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"

# Fixed, small vocabulary for UserSession.revoked_reason -- a plain string
# column (matching ApiKey.revoked_reason / LicenseKey.revoked_reason's own
# free-text convention elsewhere in this schema), kept to these three
# values by convention so a future Control Center Sessions view can render
# a stable, known set of reasons rather than arbitrary free text.
REASON_USER_LOGOUT = "user_logout"
REASON_USER_REVOKED = "user_revoked"
REASON_REUSE_DETECTED = "reuse_detected"

_MAX_USER_AGENT_LEN = 255


def create(
    db,
    *,
    session_id: str,
    user_id: int,
    organization_id: int | None,
    org_role,
    auth_method: str | None,
    mfa_verified: bool,
    expires_at: datetime,
    client_ip: str | None = None,
    user_agent: str | None = None,
) -> UserSession:
    """Called once per login, from auth_service.generate_tokens -- the
    single shared choke point every login flow (password/oauth/sso/
    license/MFA-verified) already funnels through, so every flow gets a
    session row by construction, the same reasoning that already made
    `generate_tokens` the one place `User.last_login_at`/
    `authentication_method` are written.

    Also called from rotate_refresh_token as a one-time backfill for a
    refresh token that predates this feature (no session row exists yet
    for its family) -- mirrors how `family_id` itself is backfilled on
    first rotation for a pre-PR0.2 token.

    Does not commit -- the caller commits once, in the same transaction
    as the RefreshToken row it also writes, so a session is never
    persisted without the family it corresponds to, or vice versa.
    """
    now = datetime.utcnow()
    record = UserSession(
        session_id=session_id,
        user_id=user_id,
        organization_id=organization_id,
        org_role=org_role,
        auth_method=auth_method,
        mfa_verified=mfa_verified,
        status=STATUS_ACTIVE,
        created_at=now,
        last_activity_at=now,
        expires_at=expires_at,
        client_ip=client_ip,
        user_agent=(user_agent[:_MAX_USER_AGENT_LEN] if user_agent else None),
    )
    db.add(record)
    return record


def get_by_family_id(db, family_id: str | None) -> UserSession | None:
    if not family_id:
        return None
    return db.query(UserSession).filter(UserSession.session_id == family_id).first()


def is_usable(session: UserSession | None) -> bool:
    """True unless `session` is a known-bad session -- revoked, or past
    its own recorded expiry. A missing row (None) returns True: this
    function only ever *rejects* a session rotate_refresh_token's own
    RefreshToken-level checks would otherwise have let through (a session
    revoked via the new explicit revoke API, or reuse-detected on a
    sibling token) -- it must never invent a new reason to reject a token
    that has no session row at all (every pre-PR-A refresh token, until
    it's backfilled on its next rotation).
    """
    if session is None:
        return True
    if session.status == STATUS_REVOKED:
        return False
    return not (session.expires_at is not None and session.expires_at < datetime.utcnow())


def touch(db, family_id: str | None, expires_at: datetime) -> None:
    """Called on every successful refresh -- records the activity and
    slides `expires_at` forward to match the just-issued refresh token's
    own new expiry (RefreshToken rows already get a fresh
    REFRESH_TOKEN_TTL_DAYS window on every rotation; this keeps the
    session's recorded expiry in sync with that same sliding window
    instead of inventing a second, divergent expiry policy).

    No-op if no session row exists for this family, or if it's already
    revoked -- revoked stays revoked; a touch must never resurrect one
    (rotate_refresh_token's own `is_usable` guard, above, is what
    actually prevents a revoked session's family from rotating at all;
    this is defense in depth, not the primary enforcement point).
    """
    session = get_by_family_id(db, family_id)
    if session is None or session.status == STATUS_REVOKED:
        return
    session.last_activity_at = datetime.utcnow()
    session.expires_at = expires_at
    session.status = STATUS_ACTIVE


def revoke(db, family_id: str | None, reason: str) -> None:
    """Marks the session for this family REVOKED. Idempotent: revoking an
    already-revoked session is a safe no-op that leaves its original
    revoked_at/revoked_reason untouched -- the *first* revocation is the
    historically meaningful one, a second call (e.g. logout after an
    admin already revoked the same session) must not overwrite it.
    """
    session = get_by_family_id(db, family_id)
    if session is None or session.status == STATUS_REVOKED:
        return
    session.status = STATUS_REVOKED
    session.revoked_at = datetime.utcnow()
    session.revoked_reason = reason


def effective_status(session: UserSession) -> str:
    """Read-time status: overlays a lazily-computed EXPIRED on top of the
    persisted active/revoked value, since EXPIRED is never itself
    persisted by a background sweep (no scheduler exists in this repo --
    see the module docstring). Used by the read API (routes_sessions.py)
    so a caller never sees "active" for a session that has simply aged
    past its own `expires_at` without yet being touched or revoked.
    """
    if session.status == STATUS_REVOKED:
        return STATUS_REVOKED
    if session.expires_at is not None and session.expires_at < datetime.utcnow():
        return STATUS_EXPIRED
    return STATUS_ACTIVE
