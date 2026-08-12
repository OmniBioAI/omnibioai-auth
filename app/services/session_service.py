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
state (see app/core/token_revocation.py's Redis blacklist check
(`blacklist_access_token`, PR11) and app/api/routes_auth.py's own
`_publish_invalidation`).

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
    saml_name_id: str | None = None,
    saml_session_index: str | None = None,
    organization_saml_config_id: int | None = None,
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

    saml_name_id/saml_session_index/organization_saml_config_id (PR11,
    SLO): optional, default None -- every existing caller (password/
    oauth/oidc-sso/license, and rotate_refresh_token's backfill path)
    passes none of these and is completely unaffected, same backward-
    compatible convention client_ip/user_agent already established.
    Populated only by routes_saml.py's SAML login flow, so an
    IdP-initiated LogoutRequest (NameID + SessionIndex) can later find
    this exact row via find_active_by_saml_identity below.
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
        saml_name_id=saml_name_id,
        saml_session_index=saml_session_index,
        organization_saml_config_id=organization_saml_config_id,
    )
    db.add(record)
    return record


def get_by_family_id(db, family_id: str | None) -> UserSession | None:
    if not family_id:
        return None
    return db.query(UserSession).filter(UserSession.session_id == family_id).first()


def find_active_by_saml_identity(
    db, organization_saml_config_id: int, name_id: str, session_index: str | None = None
) -> list[UserSession]:
    """PR11 (SLO): resolves an IdP-initiated LogoutRequest's (NameID,
    SessionIndex) to the local session(s) it refers to -- the reverse of
    `create`'s own saml_name_id/saml_session_index write. Always scoped
    by organization_saml_config_id (the server-resolved config for the
    org_slug the LogoutRequest arrived at -- see routes_saml.py), never
    by name_id alone: two different orgs' IdPs can coincidentally issue
    the same NameID, and this is the one check standing between that and
    one org's LogoutRequest revoking a different org's session (same
    "config-scoped, not a bare identifier" reasoning
    oauth_service.find_linked_user's own organization_saml_config_id
    parameter already established for identity linking).

    session_index, if the LogoutRequest carried one, narrows to that
    exact session -- an IdP that issues a fresh SessionIndex per login
    can have several concurrent sessions open for the same NameID (e.g.
    two browsers), and a LogoutRequest naming one SessionIndex should
    only ever revoke that one, not all of them. If the LogoutRequest
    carried no SessionIndex at all (the SAML spec allows this -- it
    means "log out every session for this NameID"), every matching
    session for the NameID is returned instead.

    Only ever returns STATUS_ACTIVE sessions -- an already-revoked or
    expired session has nothing left for SLO to do to it, and returning
    it here would let a caller "re-revoke" it and overwrite a
    historically meaningful revoked_at/revoked_reason (see `revoke`'s
    own idempotency guarantee, which this function's caller relies on
    instead of duplicating that check itself).
    """
    query = db.query(UserSession).filter(
        UserSession.organization_saml_config_id == organization_saml_config_id,
        UserSession.saml_name_id == name_id,
        UserSession.status == STATUS_ACTIVE,
    )
    if session_index is not None:
        query = query.filter(UserSession.saml_session_index == session_index)
    return query.all()


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
