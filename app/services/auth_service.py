import uuid
from datetime import datetime, timedelta
from app.db.models import OrganizationMFAPolicy, User, RefreshToken
from app.core.security import verify_password
from app.core.jwt import create_access_token, create_mfa_challenge_token, create_refresh_token, decode_token
from app.services import audit_service, org_service, permission_parity
from app.services.audit_service import AuditEventType

REFRESH_TOKEN_TTL_DAYS = 7


def _log_login_failure(db, email: str, user: User | None, reason: str) -> None:
    audit_service.log_event(
        db, AuditEventType.LOGIN_FAILURE,
        actor_user_id=user.id if user else None, target_user_id=user.id if user else None,
        resource_type="user", resource_id=user.id if user else None,
        metadata={"email": email, "reason": reason},
    )


def authenticate_user(db, email, password):
    """PR9: emits exactly one login_success/login_failure audit event per
    call, on every return path -- password-based login only
    (/auth/login); OAuth/SSO logins have their own distinct flows and are
    not in this change's scope."""
    user = db.query(User).filter(User.email == email).first()

    if not user or user.status != "active":
        _log_login_failure(db, email, user, "unknown_user_or_inactive")
        return None

    if not user.hashed_password:
        _log_login_failure(db, email, user, "no_password_set")
        return None  # OAuth-only account — no password set

    if not verify_password(password, user.hashed_password):
        _log_login_failure(db, email, user, "invalid_password")
        return None

    audit_service.log_event(
        db, AuditEventType.LOGIN_SUCCESS, actor_user_id=user.id, target_user_id=user.id,
        resource_type="user", resource_id=user.id, metadata={"email": email},
    )
    return user


def build_user_claims(
    db, user, auth_method: str = "password", idp_org_id: int | None = None
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
    all additive -- sub/email/roles/permissions are computed exactly as
    before and never removed, so anything reading only those (existing
    require_permission, existing /auth/validate consumers) is unaffected.
    org_id/org_role reflect the user's resolved primary org membership
    (None/[] if they don't have one yet -- a valid state, not an error, for
    any account that predates the Default Org backfill). The parity check
    below is observational only: it logs drift between the legacy global
    permission set and the new org-scoped one, but `permissions` below
    remains the global computation -- nothing about what's actually
    enforced changes in this PR.

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
    """
    permissions = sorted({p.name for r in user.roles for p in r.permissions})

    org_membership = org_service.resolve_primary_membership(db, user.id)
    org_id = org_membership.organization_id if org_membership else None
    org_role = sorted(r.name for r in org_membership.roles) if org_membership else []

    if org_membership is not None:
        permission_parity.check_and_log(user, permissions, org_membership)

    return {
        "sub": str(user.id),
        "email": user.email,
        "roles": [r.name for r in user.roles],
        "permissions": permissions,
        "org_id": org_id,
        "org_role": org_role,
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
_PERSISTED_AUTH_METHODS = {"password": "password", "oauth": "oauth", "sso": "oidc"}


def _persisted_auth_method(auth_method: str) -> str:
    return _PERSISTED_AUTH_METHODS.get(auth_method, "unknown")


def generate_tokens(db, user, auth_method: str = "password", idp_org_id: int | None = None):
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
    db_token = RefreshToken(
        user_id=user.id,
        token=refresh,
        revoked=False,
        family_id=str(uuid.uuid4()),
        expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
    )

    db.add(db_token)
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
    db, user, auth_method: str = "password", idp_org_id: int | None = None
) -> dict:
    """PR11.5.3: the single shared MFA decision point every login flow
    (password/oauth/sso/license -- all seven generate_tokens call sites,
    see docs/pr11-mfa-login-challenge-discovery.md SS1-SS2) calls instead
    of generate_tokens directly. Exists so the `if user.mfa_enabled`
    branch lives in exactly one place, never duplicated per route.

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
        access, refresh = generate_tokens(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
        return {"mfa_required": False, "access_token": access, "refresh_token": refresh}

    challenge_token = create_mfa_challenge_token(user.id, auth_method=auth_method, idp_org_id=idp_org_id)

    audit_service.log_event(
        db, AuditEventType.MFA_CHALLENGE_REQUIRED,
        actor_user_id=user.id, target_user_id=user.id,
        organization_id=organization_id,
        resource_type="user", resource_id=user.id,
        metadata={"authentication_method": auth_method},
    )

    return {"mfa_required": True, "challenge_token": challenge_token, "methods": ["totp"]}


def revoke_token(db, token):
    db_token = db.query(RefreshToken).filter(RefreshToken.token == token).first()
    if db_token:
        db_token.revoked = True
        db.commit()


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


def rotate_refresh_token(db, presented_token: str):
    """Validates `presented_token` exactly as the old `validate_refresh_token`
    did, then additionally rotates it: the presented row is marked revoked
    + rotated_at, a new row is created in the same family, and the
    returned access token's claims are rebuilt fresh from the database via
    `build_user_claims` -- not replayed from the old token's own payload.

    Returns `(new_access_token, new_refresh_token)` on success, or `None`
    if the token is unknown, already revoked, expired, belongs to a
    no-longer-active user, or -- the new case PR0.2 adds -- is a replay of
    a token that was already rotated once (in which case, as a side
    effect, the whole family is revoked; see `_revoke_family`).
    """
    db_token = db.query(RefreshToken).filter(RefreshToken.token == presented_token).first()
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
        return None

    if db_token.revoked:
        return None

    if db_token.expires_at < datetime.utcnow():
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

    fresh_claims = build_user_claims(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
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

    db.add(
        RefreshToken(
            user_id=user.id,
            token=new_refresh,
            revoked=False,
            family_id=family_id,
            expires_at=datetime.utcnow() + timedelta(days=REFRESH_TOKEN_TTL_DAYS),
        )
    )
    db.commit()

    return new_access, new_refresh