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
from datetime import datetime, timedelta

from app.core.config import settings
from app.db.models import UserSession

STATUS_ACTIVE = "active"
STATUS_EXPIRED = "expired"
STATUS_REVOKED = "revoked"
# HIPAA Phase 1 PR3: two new *read-time-only* statuses, exactly the same
# "never persisted by a background sweep, computed in effective_status"
# treatment STATUS_EXPIRED already gets (see that function's own
# docstring) -- there is still no scheduler in this repo. Distinct from
# STATUS_EXPIRED so a Sessions UI can tell "this session's own token
# simply aged out" apart from "this session hit the idle/absolute
# security policy" without guessing from revoked_reason.
STATUS_IDLE_EXPIRED = "idle_expired"
STATUS_ABSOLUTE_EXPIRED = "absolute_expired"

# Fixed, small vocabulary for UserSession.revoked_reason -- a plain string
# column (matching ApiKey.revoked_reason / LicenseKey.revoked_reason's own
# free-text convention elsewhere in this schema), kept to these by
# convention so a future Control Center Sessions view can render a
# stable, known set of reasons rather than arbitrary free text.
REASON_USER_LOGOUT = "user_logout"
REASON_USER_REVOKED = "user_revoked"
REASON_REUSE_DETECTED = "reuse_detected"
# HIPAA Phase 1 PR3 additions.
REASON_IDLE_TIMEOUT = "idle_timeout"
REASON_ABSOLUTE_TIMEOUT = "absolute_timeout"
REASON_CONCURRENT_LIMIT = "concurrent_session_limit"
REASON_ACCOUNT_DISABLED = "account_disabled"

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


def check_timeout_policy(session: UserSession | None) -> str | None:
    """HIPAA Phase 1 PR3: the actual fix for the "sliding expires_at
    means a continuously-refreshed session never expires" gap -- see
    this module's REASON_IDLE_TIMEOUT/REASON_ABSOLUTE_TIMEOUT and
    config.py's SESSION_IDLE_TIMEOUT_SECONDS/SESSION_ABSOLUTE_TIMEOUT_
    SECONDS. Returns the violated reason string, or None if the session
    is within policy.

    Deliberately separate from `is_usable` above (revoked/hard-expiry --
    unchanged, still the primary defense-in-depth guard) rather than
    folded into it: `is_usable` answers "is this session dead," this
    answers "should this session be allowed to continue," a distinction
    `rotate_refresh_token` needs to know about (to attribute the correct
    revoked_reason and audit event) when it decides to reject and revoke.

    `session is None` returns None (no violation) for the identical
    reason `is_usable` returns True for it -- a pre-Phase-4-PR-A refresh
    token with no session row yet must not be rejected by a policy that
    has nothing to check it against; it gets a session row backfilled on
    its next rotation, same as today.

    Absolute is checked before idle so a session that has blown both
    limits is attributed to the harder ceiling, not whichever happened
    to be computed first.
    """
    if session is None:
        return None
    now = datetime.utcnow()
    if session.created_at + timedelta(seconds=settings.SESSION_ABSOLUTE_TIMEOUT_SECONDS) < now:
        return REASON_ABSOLUTE_TIMEOUT
    if session.last_activity_at + timedelta(seconds=settings.SESSION_IDLE_TIMEOUT_SECONDS) < now:
        return REASON_IDLE_TIMEOUT
    return None


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
    """Read-time status: overlays lazily-computed EXPIRED/IDLE_EXPIRED/
    ABSOLUTE_EXPIRED on top of the persisted active/revoked value, since
    none of the three are themselves persisted by a background sweep (no
    scheduler exists in this repo -- see the module docstring). Used by
    the read API (routes_sessions.py) so a caller never sees "active"
    for a session that has simply aged past its own `expires_at`, its
    idle-timeout window, or its absolute lifetime, without yet having
    been touched or explicitly revoked.

    HIPAA Phase 1 PR3: checked in the same priority order
    check_timeout_policy uses (absolute before idle, both before the
    older, coarser `expires_at` check) -- a session already past its
    absolute deadline is reported as such even if, e.g., `expires_at`
    hadn't yet caught up (it always should in practice; this is
    defense-in-depth ordering, not a case expected to occur).
    """
    if session.status == STATUS_REVOKED:
        return STATUS_REVOKED
    timeout_reason = check_timeout_policy(session)
    if timeout_reason == REASON_ABSOLUTE_TIMEOUT:
        return STATUS_ABSOLUTE_EXPIRED
    if timeout_reason == REASON_IDLE_TIMEOUT:
        return STATUS_IDLE_EXPIRED
    if session.expires_at is not None and session.expires_at < datetime.utcnow():
        return STATUS_EXPIRED
    return STATUS_ACTIVE
