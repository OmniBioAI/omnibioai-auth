import hashlib
import uuid
from datetime import datetime, timedelta
from app.db.models import OrganizationMFAPolicy, User, RefreshToken, UserSession
from app.core.config import settings
from app.core.security import DUMMY_PASSWORD_HASH, hash_password, needs_rehash, verify_password
from app.core.jwt import create_access_token, create_mfa_challenge_token, create_refresh_token, decode_token
from app.services import audit_service, login_throttle_service, org_service, session_service, team_service
from app.services.audit_service import AuditEventType

REFRESH_TOKEN_TTL_DAYS = 7


def _hash_refresh_token(token: str) -> str:
    """0017: every RefreshToken row is now looked up by this hash, not
    the raw `token` column -- see that migration's docstring. Same
    hash-the-secret-for-lookup convention as apikey_service._hash_key /
    oauth_client_service._hash_secret."""
    return hashlib.sha256(token.encode()).hexdigest()


def _log_login_failure(db, email: str, user: User | None, reason: str) -> None:
    audit_service.log_event(
        db, AuditEventType.LOGIN_FAILURE,
        actor_user_id=user.id if user else None, target_user_id=user.id if user else None,
        resource_type="user", resource_id=user.id if user else None,
        metadata={"email": email, "reason": reason},
    )


def _log_session_revoked(db, user_id: int, session_id: str | None, reason: str, actor_user_id: int | None = None) -> None:
    """HIPAA Phase 1 PR3: the single place SESSION_REVOKED is emitted
    from -- see that event type's own docstring in audit_service.py for
    why session-lifecycle auditing didn't exist at all before this PR,
    and why this is one event type with `reason` in metadata rather than
    a family of new event-type constants. `actor_user_id` defaults to
    the affected user themselves (self-service logout/revoke -- the
    common case); callers acting on someone else's session (account
    disable, a future admin-revoke) pass the real actor explicitly.
    """
    audit_service.log_event(
        db, AuditEventType.SESSION_REVOKED,
        actor_user_id=actor_user_id if actor_user_id is not None else user_id,
        target_user_id=user_id,
        resource_type="session", resource_id=session_id,
        metadata={"reason": reason},
    )


def authenticate_user(db, email, password, client_ip: str | None = None):
    """PR9: emits exactly one login_success/login_failure audit event per
    call, on every return path -- password-based login only
    (/auth/login); OAuth/SSO logins have their own distinct flows and are
    not in this change's scope.

    HIPAA Phase 1 PR1: also the single place `login_throttle_service`'s
    record_failure/record_success are called from, for the identical
    reason build_user_claims/generate_tokens above already funnel every
    login flow through one place each -- every one of this function's
    three failure branches and its one success path is a real password
    attempt, so hooking here (rather than in routes_auth.py) keeps
    throttling behavior identical regardless of *why* verification
    failed, which is exactly what the enumeration-resistance requirement
    needs: an unknown email, a password-less OAuth-only account, and a
    genuinely wrong password all record an identical failure to the
    throttle layer. `client_ip` is optional/defaults to None so any other
    caller of this function is unaffected -- today there are none besides
    routes_auth.py's /auth/login, but this keeps the signature backward
    compatible regardless.

    HIPAA Phase 4: the first two failure branches below now also call
    `verify_password` -- against `DUMMY_PASSWORD_HASH`, a fixed
    placeholder, never a real credential -- purely to spend the same
    bcrypt-bound CPU time the third branch's own (real) verification
    already costs. This closes the timing side-channel identified but
    deliberately left open by HIPAA Phase 1 PR1 (see
    docs/security-auth-rate-limiting.md's own "Enumeration resistance"
    section and docs/security-login-timing-side-channel.md for the full
    discovery/threat-model/design writeup): previously, an unknown email
    or a password-less account returned near-instantly (no hashing work
    at all), while a real account with a merely wrong password paid a
    full bcrypt verification first -- a measurable response-time
    difference an attacker could use to enumerate which submitted emails
    correspond to real, password-protected accounts, independent of
    guessing the password itself. The dummy verification's boolean
    result is always discarded; it changes nothing about which branch is
    taken, only how much CPU time is spent getting there.
    """
    user = db.query(User).filter(User.email == email).first()

    if not user or user.status != "active":
        verify_password(password, DUMMY_PASSWORD_HASH)
        _log_login_failure(db, email, user, "unknown_user_or_inactive")
        login_throttle_service.record_failure(db, email, client_ip)
        return None

    if not user.hashed_password:
        verify_password(password, DUMMY_PASSWORD_HASH)
        _log_login_failure(db, email, user, "no_password_set")
        login_throttle_service.record_failure(db, email, client_ip)
        return None  # OAuth-only account — no password set

    if not verify_password(password, user.hashed_password):
        _log_login_failure(db, email, user, "invalid_password")
        login_throttle_service.record_failure(db, email, client_ip)
        return None

    # HIPAA Phase 1 PR2: opportunistic upgrade of a pre-PR2 plain-bcrypt
    # hash to bcrypt_sha256 (see security.py's pwd_context docstring) --
    # only reachable here, the moment the plaintext password is already
    # in hand from a *successful* verification, never eagerly and never
    # for a hash that already uses the current scheme (needs_rehash is
    # False for those). This is how "existing passwords continue to
    # function until changed/reset" (PR2's own requirement) becomes
    # "...and are transparently migrated the next time their owner logs
    # in" without a forced mass reset.
    if needs_rehash(user.hashed_password):
        user.hashed_password = hash_password(password)

    login_throttle_service.record_success(email, client_ip)
    audit_service.log_event(
        db, AuditEventType.LOGIN_SUCCESS, actor_user_id=user.id, target_user_id=user.id,
        resource_type="user", resource_id=user.id, metadata={"email": email},
    )
    return user


def build_user_claims(
    db, user, auth_method: str = "password", idp_org_id: int | None = None,
    requested_team_id: int | None = None,
) -> dict:
    """The single source of truth for what goes into a token's payload --
    shared by `generate_tokens` (login/OAuth/SSO/license) and PR0.2's
    `rotate_refresh_token`, so a refreshed access token reflects the same
    roles/permissions/org_id/org_role a fresh login would produce right
    now, never whatever was true when the *original* refresh token was
    issued. Previously this logic lived inline in `generate_tokens` only;
    `/auth/refresh` re-signed the old token's own payload verbatim instead
    of calling anything like this, which is the gap PR0.2 closes.

    `auth_method`/`idp_org_id` describe how this session *originated* --
    not something to re-derive from current state, so callers (both login
    and rotation) pass them through explicitly.

    Phase 1 PR3: payload gains org_id/org_role/auth_method/token_version=2,
    all additive -- sub/email/roles are computed exactly as before and
    never removed, so anything reading only those (existing require_role,
    existing /auth/validate consumers) is unaffected. org_id/org_role
    reflect the user's resolved primary org membership (None/[] if they
    don't have one yet -- a valid state, not an error, for any account
    that predates the Default Org backfill).

    PR13: `permissions` is now the union of the user's global-role
    permissions and their primary org membership's role permissions, not
    global-only as it was through PR12. This is the cutover
    app/services/permission_parity.py's docstring described as pending
    ("until PR4's cutover makes it load-bearing") -- that module existed
    solely to log drift between these two sets ahead of this merge, has
    nothing left to detect now that they're unioned by construction, and
    is removed as part of this change (see its own removal in this PR).
    Every existing GLOBAL-scope permission check (require_permission)
    still works exactly as before for a user with no org membership;
    for a user with one, they now also carry whatever ORG/BOTH-scope
    permissions their org role(s) grant -- e.g. a user assigned the
    org-scoped "scientist" role now has workflow.execute/dataset.read/
    model.use in their JWT, which is the whole point of this PR.

    Phase 2 PR4: idp_org_id additionally records which org's enterprise IdP
    authenticated this specific login (None for every other auth_method).
    Deliberately distinct from org_id above: org_id is the user's resolved
    *primary* membership (could be a different org for a multi-org user),
    while idp_org_id is the org whose IdP configuration this callback's
    token exchange actually validated against -- the two usually agree
    (JIT provisioning ensures the SSO org is a membership) but are tracked
    separately rather than conflated. Still additive: still token_version=2,
    not bumped, since /auth/validate's degradation is claim-presence-based,
    not version-number-based, and this is the same "additive superset"
    category PR3 already established for that version.

    PR11.5.3: mfa_verified is unconditionally True, not computed per-user
    here -- this function is only ever called from generate_tokens
    (either directly, for a user with no MFA, or from inside
    mfa_service.verify_mfa_challenge, only after a correct TOTP code) or
    from rotate_refresh_token (continuing a session that already cleared
    this bar once, at the original login). There is no calling path by
    which this function runs for a user who still owes a second factor,
    so the claim is provably always True at every point it's actually
    built -- see docs/pr11-mfa-login-challenge-discovery.md SS6.

    Team Management v0.8.0 Step 3 (Multi-user Workspaces, Mode B):
    `requested_team_id` is the caller's *candidate* active workspace --
    from `generate_tokens` this is whatever a fresh login should start in
    (None, i.e. the personal workspace, unless a future caller decides
    otherwise), from `rotate_refresh_token` it's whatever team_id the
    presented token already carried (plain /auth/refresh) or an explicit
    override (POST /auth/switch-team). Either way it's re-validated fresh
    against the database on every call via team_service.resolve_team_claim
    -- never trusted as-is -- the same "recompute, don't replay" posture
    org_id/org_role/permissions above already have. A candidate that no
    longer resolves (team deleted, membership revoked since the token was
    issued) silently degrades to (None, None) rather than failing the
    token operation, matching org_id's own "None is a valid state" design.
    """
    global_permissions = {p.name for r in user.roles for p in r.permissions}

    org_membership = org_service.resolve_primary_membership(db, user.id)
    org_id = org_membership.organization_id if org_membership else None
    org_role = sorted(r.name for r in org_membership.roles) if org_membership else []
    org_permissions = org_service.permissions_for_membership(org_membership) if org_membership else set()

    team_id, team_role = team_service.resolve_team_claim(db, org_id, requested_team_id, user.id)

    permissions = sorted(global_permissions | org_permissions)

    return {
        "sub": str(user.id),
        "email": user.email,
        "roles": [r.name for r in user.roles],
        "permissions": permissions,
        "org_id": org_id,
        "org_role": org_role,
        "team_id": team_id,
        "team_role": team_role,
        "auth_method": auth_method,
        "idp_org_id": idp_org_id,
        "token_version": 2,
        "mfa_verified": True,
    }


# PR11.1: the persisted `users.authentication_method` vocabulary is
# deliberately narrower than the JWT `auth_method` claim above --
# password/oauth/oidc/unknown only, matching what the admin console
# actually needs to display. "sso" (this service's internal name for
# enterprise OIDC login) maps to "oidc" for that display; "license" (a
# fourth real flow, routes_license.py) has no dedicated column value in
# the PR11.1 spec and maps to "unknown" rather than silently inventing a
# fifth displayed value. The JWT claim itself is untouched by this map --
# every existing consumer of `auth_method` in a token payload keeps
# seeing exactly what it always has.
#
# SAML PR6: "saml" gets its own dedicated value (not folded into "oidc")
# -- unlike enterprise OIDC SSO, which this service's login flow itself
# calls "sso" internally, SAML's own `auth_method` claim is already the
# literal string "saml" (see routes_saml.py), so mapping it to itself
# keeps the admin console able to tell the two enterprise IdP protocols
# apart instead of conflating them under one label.
_PERSISTED_AUTH_METHODS = {"password": "password", "oauth": "oauth", "sso": "oidc", "saml": "saml"}


def _persisted_auth_method(auth_method: str) -> str:
    return _PERSISTED_AUTH_METHODS.get(auth_method, "unknown")


def _evict_oldest_sessions_over_limit(db, user_id: int) -> None:
    """HIPAA Phase 1 PR3: enforces SESSION_MAX_CONCURRENT. Called from
    `generate_tokens` after the new RefreshToken row is flushed but
    before the new UserSession row is created, so the count evaluated
    here never includes the login currently in progress.

    Locks the user's own session rows (`with_for_update`) for the rest
    of this transaction -- the same transaction `generate_tokens`
    commits at the end of -- so two concurrent logins for the same user
    can't both read "N-1 active, room for one more" and both proceed,
    landing at N+1. A no-op on SQLite (used in tests): SQLite has no
    row-level locking, only whole-database write locking, so this
    degrades to "correct but coarser-grained" there rather than raising
    -- the real guarantee this exists for only matters under concurrent
    load, which the production database (MySQL/InnoDB) provides.

    The failure mode of a race slipping through here is bounded and
    non-security-critical -- occasionally one session over the
    configured limit, not an authentication bypass -- unlike PR1's
    login-rate-limit counters, which is why this uses ordinary
    transactional row locking rather than PR1's atomic-Redis-script
    approach: the two problems have different severity profiles.
    """
    candidates = (
        db.query(UserSession)
        .filter(UserSession.user_id == user_id, UserSession.status == session_service.STATUS_ACTIVE)
        .with_for_update()
        .order_by(UserSession.created_at.asc())
        .all()
    )
    # Effective-active only -- a persisted "active" row that's actually
    # idle/absolute-expired already doesn't count against the limit (it
    # isn't a real usable session anymore, even though nothing has
    # written REVOKED to it yet -- it will, the next time anyone tries
    # to refresh it, via rotate_refresh_token's own check).
    effectively_active = [
        s for s in candidates if session_service.effective_status(s) == session_service.STATUS_ACTIVE
    ]

    # +1: leaves room for the session this login is about to create.
    excess = len(effectively_active) - settings.SESSION_MAX_CONCURRENT + 1
    if excess <= 0:
        return

    for session in effectively_active[:excess]:
        _revoke_family(db, session.session_id)
        session_service.revoke(db, session.session_id, session_service.REASON_CONCURRENT_LIMIT)
        _log_session_revoked(db, user_id, session.session_id, session_service.REASON_CONCURRENT_LIMIT)


def generate_tokens(
    db,
    user,
    auth_method: str = "password",
    idp_org_id: int | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    saml_name_id: str | None = None,
    saml_session_index: str | None = None,
    organization_saml_config_id: int | None = None,
):
    """`auth_method` records which flow issued this token ("password" |
    "oauth" | "license" | "sso") -- purely informational, not used for any
    authorization decision. Claims themselves come from `build_user_claims`
    (above) -- see that docstring for what each field means.

    PR11.1: also the single place `users.last_login_at`/
    `authentication_method` are written, for exactly this reason -- every
    login flow (password/oauth/sso/license) already calls this function
    with the right `auth_method`, so hooking here keeps every flow in
    sync by construction rather than repeating the write at each of the
    seven call sites across routes_auth.py/routes_oauth.py/routes_sso.py/
    routes_license.py. Deliberately not in `build_user_claims`, which
    `rotate_refresh_token` also calls on every token refresh -- a refresh
    continues an existing session, it must not look like a new login.

    Phase 4 PR-A: also the single place a `UserSession` row is created,
    for the identical reason -- every login flow already funnels through
    here. `client_ip`/`user_agent` are optional and default to None so
    every existing caller (routes_oauth.py/routes_sso.py/routes_license.py/
    mfa_service.py, none of which pass them today) is completely
    unaffected; only routes_auth.py's password login currently supplies
    them. See app/services/session_service.py.

    PR11 (SLO): saml_name_id/saml_session_index/organization_saml_
    config_id are the identical optional/default-None convention --
    only routes_saml.py's SAML login flow (directly, or by way of
    mfa_service.verify_mfa_challenge for a SAML+personal-MFA user, see
    that module's own threading of these same three values through
    create_mfa_challenge_token) ever supplies them. Every other caller
    is unaffected, and every session these three describe a *SAML*
    login gets written with them so an IdP-initiated LogoutRequest can
    later find it (session_service.find_active_by_saml_identity).
    """
    user.last_login_at = datetime.utcnow()
    user.authentication_method = _persisted_auth_method(auth_method)

    payload = build_user_claims(db, user, auth_method=auth_method, idp_org_id=idp_org_id)

    access = create_access_token(payload)
    refresh = create_refresh_token(payload)

    # PR0.2: a fresh family_id per login -- every subsequent rotation of
    # this refresh token stays in the same family, so a reuse-of-rotated
    # token can revoke exactly the tokens descended from this one login,
    # not every session this user has ever had.
    family_id = str(uuid.uuid4())
    expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_TTL_DAYS)

    db_token = RefreshToken(
        user_id=user.id,
        token=refresh,
        token_hash=_hash_refresh_token(refresh),
        revoked=False,
        family_id=family_id,
        expires_at=expires_at,
    )

    db.add(db_token)

    # HIPAA Phase 1 PR3: enforce SESSION_MAX_CONCURRENT before the new
    # session row exists, so the count evaluated here never includes it.
    # `db.flush()` first so `db_token` above is visible to any query in
    # this same transaction (not required for the session-count query
    # itself, which only reads UserSession, but keeps this call site
    # consistent regardless of ordering changes later).
    db.flush()
    _evict_oldest_sessions_over_limit(db, user.id)

    session_service.create(
        db,
        session_id=family_id,
        user_id=user.id,
        organization_id=payload.get("org_id"),
        org_role=payload.get("org_role"),
        auth_method=auth_method,
        mfa_verified=payload.get("mfa_verified", True),
        expires_at=expires_at,
        client_ip=client_ip,
        user_agent=user_agent,
        saml_name_id=saml_name_id,
        saml_session_index=saml_session_index,
        organization_saml_config_id=organization_saml_config_id,
    )

    db.commit()

    return access, refresh


class MFAEnrollmentRequiredError(Exception):
    """PR11.5.5: raised by generate_tokens_or_mfa_challenge when the
    user's organization requires MFA (OrganizationMFAPolicy.required,
    no active override) but the user has not personally enrolled yet
    (User.mfa_enabled is False). No challenge token is issued, no
    tokens are issued -- routes catch this and return 403
    {"error": "mfa_enrollment_required", ...}, mirroring the existing
    "sso_required" 403 precedent in routes_auth.py::login. See
    docs/pr11-mfa-org-policy-discovery.md SS4."""


def generate_tokens_or_mfa_challenge(
    db,
    user,
    auth_method: str = "password",
    idp_org_id: int | None = None,
    client_ip: str | None = None,
    user_agent: str | None = None,
    saml_name_id: str | None = None,
    saml_session_index: str | None = None,
    organization_saml_config_id: int | None = None,
) -> dict:
    """PR11.5.3: the single shared MFA decision point every login flow
    (password/oauth/sso/license -- all seven generate_tokens call sites,
    see docs/pr11-mfa-login-challenge-discovery.md SS1-SS2) calls instead
    of generate_tokens directly. Exists so the `if user.mfa_enabled`
    branch lives in exactly one place, never duplicated per route.

    Phase 4 PR-A: `client_ip`/`user_agent` are passed straight through to
    `generate_tokens` on the no-MFA path only -- optional, default None,
    so only routes_auth.py's password login (the one caller that
    currently supplies them) is affected. The MFA-challenge branch below
    never reaches `generate_tokens` at all (no tokens exist yet), so a
    challenge-then-verify login's session is created later, from
    mfa_service.verify_mfa_challenge's own call to `generate_tokens`
    (without client metadata, for now -- see that module).

    Returns one of two shapes:
      {"mfa_required": False, "access_token": ..., "refresh_token": ...}
      {"mfa_required": True, "challenge_token": ..., "methods": ["totp"]}
    or raises MFAEnrollmentRequiredError (PR11.5.5, see above).

    Deliberately does NOT write last_login_at/authentication_method or
    emit any login-completion state when a challenge is issued -- the
    user hasn't finished authenticating yet. Those only happen inside
    generate_tokens itself, called either directly below (no MFA) or
    from mfa_service.verify_mfa_challenge on successful code
    verification -- the same, unchanged function either way, so a
    challenge-gated login and a direct one produce identical-shaped
    sessions.

    PR11.5.5: org policy is looked up here directly against
    OrganizationMFAPolicy (not via mfa_service.get_org_mfa_policy) --
    mfa_service.py already imports generate_tokens from this module, so
    importing back from mfa_service.py here would be circular. A
    3-line query duplicated once is a smaller cost than that cycle. See
    docs/pr11-mfa-org-policy-discovery.md SS3 for the full decision
    table this logic implements -- personal MFA (user.mfa_enabled)
    always wins regardless of org policy state; org policy only ever
    matters in the `not user.mfa_enabled` branch.
    """
    org_membership = org_service.resolve_primary_membership(db, user.id)
    organization_id = org_membership.organization_id if org_membership else None

    org_requires_mfa = False
    if organization_id is not None:
        policy = (
            db.query(OrganizationMFAPolicy)
            .filter(OrganizationMFAPolicy.organization_id == organization_id)
            .first()
        )
        if policy is not None and policy.required and not policy.override_active:
            org_requires_mfa = True

    if not user.mfa_enabled:
        if org_requires_mfa:
            raise MFAEnrollmentRequiredError()
        access, refresh = generate_tokens(
            db, user, auth_method=auth_method, idp_org_id=idp_org_id,
            client_ip=client_ip, user_agent=user_agent,
            saml_name_id=saml_name_id, saml_session_index=saml_session_index,
            organization_saml_config_id=organization_saml_config_id,
        )
        return {"mfa_required": False, "access_token": access, "refresh_token": refresh}

    challenge_token = create_mfa_challenge_token(
        user.id, auth_method=auth_method, idp_org_id=idp_org_id,
        saml_name_id=saml_name_id, saml_session_index=saml_session_index,
        organization_saml_config_id=organization_saml_config_id,
    )

    audit_service.log_event(
        db, AuditEventType.MFA_CHALLENGE_REQUIRED,
        actor_user_id=user.id, target_user_id=user.id,
        organization_id=organization_id,
        resource_type="user", resource_id=user.id,
        metadata={"authentication_method": auth_method},
    )

    return {"mfa_required": True, "challenge_token": challenge_token, "methods": ["totp"]}


def revoke_token(db, token):
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == _hash_refresh_token(token)).first()
    if db_token:
        db_token.revoked = True
        # Phase 4 PR-A: additive -- only writes the UserSession row for
        # this family, does not change what happens to `db_token` itself
        # (still exactly the single-row revoke this function has always
        # done; see its own module-level precedent notes in
        # app/db/models.py's RefreshToken/UserSession comments for why
        # revoking the one currently-live row is equivalent to revoking
        # the session).
        session_service.revoke(db, db_token.family_id, session_service.REASON_USER_LOGOUT)
        _log_session_revoked(db, db_token.user_id, db_token.family_id, session_service.REASON_USER_LOGOUT)
        db.commit()


def get_session_for_refresh_token(db, token: str):
    """PR11 (SLO): resolves the UserSession row a given (still-unrevoked
    or already-revoked -- this is a plain lookup, not a validity check)
    refresh token belongs to. Reuses the exact same token_hash lookup
    revoke_token itself uses, rather than a second hashing scheme.

    routes_saml.py's SP-initiated /logout endpoint calls this BEFORE
    calling revoke_token, to read the session's saml_name_id/
    saml_session_index/organization_saml_config_id (if any) while the
    row is still easy to find by its own family_id -- revoke_token only
    changes status/revoked_at/revoked_reason, never these three columns,
    so the order doesn't affect what's read, but reading first keeps the
    route's own logic linear (look up -> revoke -> maybe redirect to the
    IdP) rather than needing a second query after revocation.

    Returns None if the token doesn't hash-match any RefreshToken row,
    or if that row's family has no session (a token that predates Phase
    4 PR-A's session foundation) -- both are simply "nothing to build an
    IdP logout redirect from," not errors.
    """
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == _hash_refresh_token(token)).first()
    if not db_token:
        return None
    return session_service.get_by_family_id(db, db_token.family_id)


def revoke_session(db, session_id: str) -> bool:
    """Phase 4 PR-A: explicit, API-triggered revocation of one session by
    id (== the refresh-token family_id) -- distinct from `revoke_token`
    above (logout; revokes only the single currently-live token row) and
    from `_revoke_family`'s automatic reuse-detection response. Unlike
    plain logout, this revokes *every* row in the family via the same
    `_revoke_family` reuse-detection uses, not just the current one --
    deliberately more thorough, since this is a new capability (killing a
    session an admin or the user themselves identified out-of-band, not
    the token currently in hand) rather than a continuation of the
    existing logout code path.

    Returns True if a session with this id exists (whether or not it was
    already revoked -- both are treated as success by the caller, same
    "already gone is fine" idempotency as revoke_token). `_revoke_family`
    commits its own change immediately (existing behavior, unchanged
    here); the session-row mutation that follows still needs the caller
    (routes_sessions.py) to commit once more to persist.
    """
    session = session_service.get_by_family_id(db, session_id)
    if session is None:
        return False
    _revoke_family(db, session_id)
    session_service.revoke(db, session_id, session_service.REASON_USER_REVOKED)
    _log_session_revoked(db, session.user_id, session_id, session_service.REASON_USER_REVOKED)
    return True


def _revoke_family(db, family_id: str | None) -> None:
    """Revokes every refresh_tokens row descended from the same login as
    `family_id` -- the reuse-detection response. Deliberately revokes the
    *entire* family, including any token legitimately rotated after the
    one being replayed: once a token from this family has been presented
    twice, this service can no longer tell which presentation was the
    legitimate user and which was an attacker, so every descendant is
    treated as compromised and the whole family is forced back to login.
    A NULL family_id (a pre-PR0.2 row that was never rotated) has no
    siblings to revoke beyond itself, which the caller already handles.
    """
    if not family_id:
        return
    db.query(RefreshToken).filter(RefreshToken.family_id == family_id).update(
        {"revoked": True}
    )
    db.commit()


def revoke_all_sessions_for_user(db, user_id: int, reason: str, actor_user_id: int | None = None) -> int:
    """HIPAA Phase 1 PR3: called from user_admin_service.set_user_status
    on the active-\\>suspended transition -- see that function's own
    updated docstring for the gap this closes. `assert_token_usable`
    already live-checks `User.status` on every access-token use, and
    `rotate_refresh_token` already checks it too, so a suspended user's
    *next* authenticated request was already rejected before this PR --
    what was missing is that nothing ever marked the underlying
    RefreshToken/UserSession rows revoked, so **re-enabling the account
    silently made those old tokens valid again**. This function is what
    makes the revocation real and permanent rather than a live status
    check that a later re-enable quietly undoes.

    Every non-revoked session belonging to the user is revoked here --
    not just ones the read-time `effective_status()` would currently
    call "active" (an idle/absolute-expired-but-not-yet-touched session
    still has persisted status="active" until something writes to it;
    this is that something, for every one of them, in one pass).

    Returns the number of sessions actually revoked (0 is a normal,
    expected result for a user with no other active sessions -- not an
    error). Same never-raise posture as the rest of this module's
    session-revocation helpers: called from an admin route where the
    real mutation (the status flip) has already succeeded, so a problem
    revoking a session must not turn that into a failed request.
    """
    sessions = (
        db.query(UserSession)
        .filter(UserSession.user_id == user_id, UserSession.status != session_service.STATUS_REVOKED)
        .all()
    )
    revoked_count = 0
    for session in sessions:
        _revoke_family(db, session.session_id)
        session_service.revoke(db, session.session_id, reason)
        _log_session_revoked(db, user_id, session.session_id, reason, actor_user_id=actor_user_id)
        revoked_count += 1
    db.commit()
    return revoked_count


# Sentinel distinguishing "caller didn't pass team_id at all" (plain
# /auth/refresh -- carry the presented token's own team_id forward
# unchanged) from "caller explicitly passed team_id=None" (POST /auth/
# switch-team back to the personal workspace -- a real, meaningful
# request, not "no opinion"). Module-level singleton, not a mutable
# default argument, so identity comparison (`is _UNSET`) is safe.
_UNSET = object()


def rotate_refresh_token(db, presented_token: str, team_id=_UNSET):
    """Validates `presented_token` exactly as the old `validate_refresh_token`
    did, then additionally rotates it: the presented row is marked revoked
    + rotated_at, a new row is created in the same family, and the
    returned access token's claims are rebuilt fresh from the database via
    `build_user_claims` -- not replayed from the old token's own payload.

    Returns `(new_access_token, new_refresh_token)` on success, or `None`
    if the token is unknown, already revoked, expired, belongs to a
    no-longer-active user, -- the case PR0.2 adds -- is a replay of a
    token that was already rotated once (in which case, as a side effect,
    the whole family is revoked; see `_revoke_family`), or -- Phase 4
    PR-A adds -- belongs to a session that was independently revoked or
    has itself expired (see `session_service.is_usable`). This last check
    is defense in depth: today, the only way to reach it is a session
    revoked via the new `revoke_session`/`POST /sessions/{id}/revoke`
    path, which already revokes the entire RefreshToken family too (so
    `db_token.revoked` above would already have caught it) -- this guard
    exists so that guarantee holds even if a future revocation path ever
    updates the session without also updating every RefreshToken row.

    Team Management v0.8.0 Step 3: `team_id` lets a caller either leave
    the presented token's active workspace untouched (default -- every
    existing caller, i.e. plain /auth/refresh, is unaffected and the
    selected team survives the refresh) or explicitly switch it (POST
    /auth/switch-team passes its own validated `team_id`, including
    `None` for "back to personal"). Either way the candidate still goes
    through `build_user_claims` -> `team_service.resolve_team_claim`'s
    fresh re-validation below, not trusted as-is -- see that function's
    docstring.
    """
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == _hash_refresh_token(presented_token)).first()
    if not db_token:
        return None

    if db_token.rotated_at is not None:
        # Reuse of an already-exchanged token -- someone (attacker or, if
        # this fires for the legitimate user, a stale copy of a token they
        # already rotated elsewhere) is presenting a token that should no
        # longer exist. Kill the whole family rather than just this token,
        # since a live descendant token (family_id's newest row) may
        # already be in an attacker's hands.
        _revoke_family(db, db_token.family_id)
        session_service.revoke(db, db_token.family_id, session_service.REASON_REUSE_DETECTED)
        _log_session_revoked(db, db_token.user_id, db_token.family_id, session_service.REASON_REUSE_DETECTED)
        db.commit()
        return None

    if db_token.revoked:
        return None

    if db_token.expires_at < datetime.utcnow():
        return None

    session = session_service.get_by_family_id(db, db_token.family_id)
    if not session_service.is_usable(session):
        return None

    # HIPAA Phase 1 PR3: the fix for the "expires_at slides forward on
    # every rotation, so a continuously-refreshed session never actually
    # expires" gap identified in the Phase 1 security review -- verified
    # live before this PR (new_expires_at below was always `utcnow() +
    # REFRESH_TOKEN_TTL_DAYS`, so `db_token.expires_at` above never had a
    # chance to catch a session that kept getting refreshed). Checked
    # against `session.created_at`/`last_activity_at`, which this PR is
    # the first thing to ever enforce policy against -- see
    # session_service.check_timeout_policy's own docstring for exactly
    # what each of the two limits means and why absolute is checked
    # first. On violation, explicitly revoke (not just reject) so the
    # session-list API reports it accurately and a repeat presentation
    # of the same token doesn't need to re-derive the same conclusion --
    # and so there's a real mutation to hang the audit event off, the
    # same reasoning every other revocation path in this module follows.
    timeout_reason = session_service.check_timeout_policy(session)
    if timeout_reason is not None:
        _revoke_family(db, db_token.family_id)
        session_service.revoke(db, db_token.family_id, timeout_reason)
        _log_session_revoked(db, db_token.user_id, db_token.family_id, timeout_reason)
        db.commit()
        return None

    user = db.query(User).filter(User.id == db_token.user_id).first()
    if not user or user.status != "active":
        return None

    try:
        old_claims = decode_token(presented_token)
    except Exception:
        old_claims = {}
    auth_method = old_claims.get("auth_method") or "password"
    idp_org_id = old_claims.get("idp_org_id")
    requested_team_id = old_claims.get("team_id") if team_id is _UNSET else team_id

    fresh_claims = build_user_claims(
        db, user, auth_method=auth_method, idp_org_id=idp_org_id,
        requested_team_id=requested_team_id,
    )
    new_access = create_access_token(fresh_claims)
    new_refresh = create_refresh_token(fresh_claims)

    db_token.revoked = True
    db_token.rotated_at = datetime.utcnow()

    # Backfill: a token minted before PR0.2's migration has no family_id
    # of its own. Assign one now so this and every token descended from it
    # going forward participate in reuse detection, without needing to
    # touch already-issued tokens that predate this column.
    family_id = db_token.family_id or str(uuid.uuid4())
    db_token.family_id = family_id

    new_expires_at = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_TTL_DAYS)

    db.add(
        RefreshToken(
            user_id=user.id,
            token=new_refresh,
            token_hash=_hash_refresh_token(new_refresh),
            revoked=False,
            family_id=family_id,
            expires_at=new_expires_at,
        )
    )

    # Phase 4 PR-A: keep the session's activity/expiry in sync with the
    # token just issued. `session` is None in exactly two cases: a
    # pre-PR-A token being rotated for the first time since this feature
    # shipped (family_id may also have just been freshly assigned, two
    # lines above), or one whose family_id was backfilled on some earlier
    # rotation before this feature existed -- either way, create the
    # session row now rather than leaving it permanently missing, the
    # same "backfill on first rotation" treatment family_id itself
    # already gets a few lines up.
    if session is not None:
        session_service.touch(db, family_id, new_expires_at)
    else:
        session_service.create(
            db,
            session_id=family_id,
            user_id=user.id,
            organization_id=fresh_claims.get("org_id"),
            org_role=fresh_claims.get("org_role"),
            auth_method=auth_method,
            mfa_verified=fresh_claims.get("mfa_verified", True),
            expires_at=new_expires_at,
        )

    db.commit()

    return new_access, new_refresh
