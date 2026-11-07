"""#443 / #96: POST /service/mint-user-token.

Covers the least-privilege boundary on the caller (service_token.mint is not
implied by any other permission), the lightweight-mint design (no session or
refresh-token row, no last_login_at write), and #96's limits on the target:
existing active users only, the caller's verification statement, privileged
targets, org-scoped minting, the short TTL, the per-caller rate limit and the
audit trail.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import time
import uuid
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.jwt import decode_token
from app.db.models import AuditEvent, Organization, OrganizationMembership, RefreshToken, User, UserSession
from app.services.role_service import get_or_create_role

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

URL = "/service/mint-user-token"
VERIFIED = {"email_verified": True, "verification_method": "allauth_verified_primary"}


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"mint-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _relogin(client, account):
    resp = client.post("/auth/login", json={"email": account["email"], "password": account["password"]})
    return {**account, "access_token": resp.json()["access_token"]}


def _grant_role(email: str, role_name: str, permission_names: list[str]) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = get_or_create_role(db, role_name, permission_names)
        if role not in user.roles:
            user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _mint_caller(client, extra_permissions=()):
    """A real user holding service_token.mint via a dedicated role --
    mirrors ensure_bio_agent_service_role's real shape, built directly in
    the test DB since the test app boots without BIO_AGENT_SVC_EMAIL set."""
    caller = _register_and_login(client)
    _grant_role(caller["email"], "bio_agent_service", ["service_token.mint"])
    if extra_permissions:
        _grant_role(caller["email"], f"mint-extra-{uuid.uuid4().hex[:6]}", list(extra_permissions))
    return _relogin(client, caller)


def _existing_user(client):
    return _register_and_login(client, email=f"chat-user-{uuid.uuid4().hex[:8]}@example.test")


def _mint(client, caller, email, **fields):
    body = {"email": email, **VERIFIED, **fields}
    return client.post(URL, json=body, headers=_auth_header(caller["access_token"]))


def _user_row(email: str):
    db = _DirectSession()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


def _make_org(status="active") -> int:
    db = _DirectSession()
    try:
        slug = f"mint-org-{uuid.uuid4().hex[:8]}"
        org = Organization(slug=slug, name=slug, status=status, created_at=datetime.utcnow())
        db.add(org)
        db.commit()
        return org.id
    finally:
        db.close()


def _add_membership(email, org_id, role_name, permission_names, status="active") -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = get_or_create_role(db, role_name, permission_names)
        db.add(OrganizationMembership(
            organization_id=org_id, user_id=user.id, status=status,
            joined_at=datetime.utcnow(), roles=[role],
        ))
        db.commit()
    finally:
        db.close()


def _set_user_status(email, status) -> None:
    db = _DirectSession()
    try:
        db.query(User).filter(User.email == email).first().status = status
        db.commit()
    finally:
        db.close()


def _events(event_type, actor_email):
    db = _DirectSession()
    try:
        actor = db.query(User).filter(User.email == actor_email).first()
        return (
            db.query(AuditEvent)
            .filter(AuditEvent.event_type == event_type, AuditEvent.actor_user_id == actor.id)
            .order_by(AuditEvent.id)
            .all()
        )
    finally:
        db.close()


SCIENTIST = ("scientist", ["workflow.execute", "dataset.read", "model.use", "runs.read"])
ORG_ADMIN = ("org_admin", ["manage_org", "manage_teams", "runs.read"])


# ── Caller least-privilege boundary ──────────────────────────────────────────


def test_mint_rejected_for_a_caller_with_no_permissions_at_all(client):
    """A caller with no permissions gets 403."""
    caller = _register_and_login(client)
    assert _mint(client, caller, "someone@example.test").status_code == 403


def test_mint_rejected_for_scientist_role_holder(client):
    """An ordinary scientist (workflow.execute) cannot mint tokens for other users."""
    caller = _register_and_login(client)
    _grant_role(caller["email"], "scientist", ["workflow.execute"])
    caller = _relogin(client, caller)
    assert _mint(client, caller, "someone@example.test").status_code == 403


# ── Happy path ────────────────────────────────────────────────────────────────


def test_mint_succeeds_for_an_existing_active_user(client):
    """A service_token.mint holder gets a bearer token for an existing active user."""
    caller = _mint_caller(client)
    target = _existing_user(client)

    resp = _mint(client, caller, target["email"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["access_token"]


def test_minted_token_carries_the_target_users_own_identity_not_the_callers(client):
    """The minted token's sub and email are the target's, and auth_method is service_mint."""
    caller = _mint_caller(client)
    target = _existing_user(client)

    claims = decode_token(_mint(client, caller, target["email"]).json()["access_token"])
    assert claims["email"] == target["email"]
    assert claims["sub"] == str(_user_row(target["email"]).id)
    assert claims["sub"] != str(_user_row(caller["email"]).id)
    assert claims["auth_method"] == "service_mint"


def test_mint_reuses_an_existing_account_rather_than_duplicating_it(client):
    """Minting for an existing email reuses that account."""
    caller = _mint_caller(client)
    existing = _existing_user(client)

    resp = _mint(client, caller, existing["email"])
    assert decode_token(resp.json()["access_token"])["sub"] == str(_user_row(existing["email"]).id)
    db = _DirectSession()
    try:
        assert db.query(User).filter(User.email == existing["email"]).count() == 1
    finally:
        db.close()


# ── #96: target must be an existing, active user ────────────────────────────


def test_unknown_email_is_refused_and_no_user_is_created(client):
    """An unknown email gets 403 and no account is created for it."""
    caller = _mint_caller(client)
    email = f"brand-new-{uuid.uuid4().hex[:8]}@example.test"

    resp = _mint(client, caller, email)
    assert resp.status_code == 403
    assert "access_token" not in resp.json()
    assert _user_row(email) is None


def test_inactive_user_is_refused(client):
    """A suspended user gets 403."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    _set_user_status(target["email"], "suspended")

    assert _mint(client, caller, target["email"]).status_code == 403


def test_every_target_refusal_returns_the_same_response(client):
    """Unknown and inactive targets get identical responses, so the caller cannot tell them apart."""
    caller = _mint_caller(client)
    inactive = _existing_user(client)
    _set_user_status(inactive["email"], "suspended")

    unknown_resp = _mint(client, caller, f"nobody-{uuid.uuid4().hex[:8]}@example.test")
    inactive_resp = _mint(client, caller, inactive["email"])
    assert unknown_resp.status_code == inactive_resp.status_code == 403
    assert unknown_resp.json() == inactive_resp.json()


def test_email_is_trimmed_and_case_folded_before_lookup(client):
    """Surrounding whitespace and capitals still resolve to the existing account."""
    caller = _mint_caller(client)
    target = _existing_user(client)

    resp = _mint(client, caller, f"  {target['email'].upper()}  ")
    assert resp.status_code == 200
    assert decode_token(resp.json()["access_token"])["sub"] == str(_user_row(target["email"]).id)


def test_malformed_email_is_rejected(client):
    """A value that is not an email address gets 422."""
    caller = _mint_caller(client)
    assert _mint(client, caller, "not-an-email").status_code == 422


# ── #96: the caller states how it verified the address ──────────────────────


def test_missing_email_verified_is_rejected(client):
    """A request without email_verified gets 422."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    resp = client.post(
        URL, json={"email": target["email"], "verification_method": "allauth_verified_primary"},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 422


def test_false_email_verified_is_rejected(client):
    """email_verified=false gets 422."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    assert _mint(client, caller, target["email"], email_verified=False).status_code == 422


def test_missing_or_unknown_verification_method_is_rejected(client):
    """A missing or unrecognised verification_method gets 422."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    resp = client.post(
        URL, json={"email": target["email"], "email_verified": True},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 422
    assert _mint(client, caller, target["email"], verification_method="trust_me").status_code == 422


# ── #96: privileged targets ──────────────────────────────────────────────────


def test_global_admin_target_is_refused(client):
    """A user holding a global admin permission gets no minted token."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    _grant_role(target["email"], "admin", ["manage_roles"])

    assert _mint(client, caller, target["email"]).status_code == 403


def test_org_admin_target_is_refused(client):
    """A user whose primary org role is org_admin gets no minted token."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    _add_membership(target["email"], _make_org(), *ORG_ADMIN)

    assert _mint(client, caller, target["email"]).status_code == 403


def test_service_account_target_is_refused(client):
    """Another service_token.mint holder (a service account) cannot be minted for."""
    caller = _mint_caller(client)
    other_service = _mint_caller(client)

    assert _mint(client, caller, other_service["email"]).status_code == 403


def test_privileged_target_allowed_with_mint_privileged_permission(client):
    """A caller that also holds service_token.mint_privileged can mint for an admin."""
    caller = _mint_caller(client, extra_permissions=["service_token.mint_privileged"])
    target = _existing_user(client)
    _grant_role(target["email"], "admin", ["manage_roles"])

    resp = _mint(client, caller, target["email"])
    assert resp.status_code == 200
    assert "manage_roles" in decode_token(resp.json()["access_token"])["permissions"]


def test_privilege_is_judged_for_the_org_being_minted_for(client):
    """Plain member of org A and admin of org B: org A mints, org B is refused."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    org_a, org_b = _make_org(), _make_org()
    _add_membership(target["email"], org_a, *SCIENTIST)
    _add_membership(target["email"], org_b, *ORG_ADMIN)

    assert _mint(client, caller, target["email"], org_id=org_a).status_code == 200
    assert _mint(client, caller, target["email"], org_id=org_b).status_code == 403


# ── #96: org-aware minting ───────────────────────────────────────────────────


def test_mint_without_org_id_uses_the_primary_org(client):
    """With no org_id, the token is for the primary (earliest active) membership."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    primary, other = _make_org(), _make_org()
    _add_membership(target["email"], primary, *SCIENTIST)
    _add_membership(target["email"], other, "viewer", ["dataset.read", "workflow.read"])

    claims = decode_token(_mint(client, caller, target["email"]).json()["access_token"])
    assert claims["org_id"] == primary


def test_mint_with_org_id_uses_that_membership(client):
    """org_id of a non-primary org the user belongs to scopes the token to that org."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    primary, other = _make_org(), _make_org()
    _add_membership(target["email"], primary, "viewer", ["dataset.read", "workflow.read"])
    _add_membership(target["email"], other, *SCIENTIST)

    resp = _mint(client, caller, target["email"], org_id=other)
    assert resp.status_code == 200
    claims = decode_token(resp.json()["access_token"])
    assert claims["org_id"] == other
    assert claims["org_role"] == ["scientist"]
    assert "workflow.execute" in claims["permissions"]


def test_mint_with_org_id_of_a_non_member_org_is_refused(client):
    """org_id of an org the user is not in gets 403 and no token, with no fallback."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    _add_membership(target["email"], _make_org(), *SCIENTIST)
    stranger_org = _make_org()

    resp = _mint(client, caller, target["email"], org_id=stranger_org)
    assert resp.status_code == 403
    assert "access_token" not in resp.json()


def test_mint_with_org_id_of_an_inactive_membership_is_refused(client):
    """A membership that is not active (e.g. invited) does not count."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    org = _make_org()
    _add_membership(target["email"], org, *SCIENTIST, status="invited")

    assert _mint(client, caller, target["email"], org_id=org).status_code == 403


def test_mint_for_a_suspended_org_is_refused(client):
    """An active membership in a suspended org gets 403."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    org = _make_org(status="suspended")
    _add_membership(target["email"], org, *SCIENTIST)

    assert _mint(client, caller, target["email"], org_id=org).status_code == 403


# ── #96: short TTL ───────────────────────────────────────────────────────────


def test_minted_token_lives_300_seconds(client):
    """expires_in is 300 and the token's exp matches it."""
    caller = _mint_caller(client)
    target = _existing_user(client)

    before = int(time.time())
    body = _mint(client, caller, target["email"]).json()
    assert body["expires_in"] == 300
    exp = decode_token(body["access_token"])["exp"]
    assert before + 290 <= exp <= int(time.time()) + 300


# ── #96: per-caller rate limit ──────────────────────────────────────────────


def test_caller_over_the_rate_limit_gets_429(client, monkeypatch):
    """With a limit of 3, the 4th request in the window gets 429 and is audited once."""
    monkeypatch.setattr(settings, "SERVICE_MINT_RATE_LIMIT", 3)
    caller = _mint_caller(client)
    target = _existing_user(client)

    statuses = [_mint(client, caller, target["email"]).status_code for _ in range(5)]
    assert statuses == [200, 200, 200, 429, 429]
    limited = [e for e in _events("service_token_mint_denied", caller["email"])
               if e.event_metadata["reason"] == "rate_limited"]
    assert len(limited) == 1


def test_rate_limit_is_per_caller(client, monkeypatch):
    """One caller hitting its limit does not limit another caller."""
    monkeypatch.setattr(settings, "SERVICE_MINT_RATE_LIMIT", 1)
    first, second = _mint_caller(client), _mint_caller(client)
    target = _existing_user(client)

    assert _mint(client, first, target["email"]).status_code == 200
    assert _mint(client, first, target["email"]).status_code == 429
    assert _mint(client, second, target["email"]).status_code == 200


# ── Lightweight-mint design decision: no session churn ──────────────────────


def test_mint_creates_no_refresh_token_or_session_row(client):
    """Minting creates no refresh token and no session row for the target user."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    target_user = _user_row(target["email"])

    db = _DirectSession()
    try:
        sessions_before = db.query(UserSession).filter(UserSession.user_id == target_user.id).count()
        refresh_before = db.query(RefreshToken).filter(RefreshToken.user_id == target_user.id).count()
    finally:
        db.close()

    assert _mint(client, caller, target["email"]).status_code == 200

    db = _DirectSession()
    try:
        assert db.query(RefreshToken).filter(RefreshToken.user_id == target_user.id).count() == refresh_before
        assert db.query(UserSession).filter(UserSession.user_id == target_user.id).count() == sessions_before
    finally:
        db.close()


def test_mint_does_not_write_last_login_at(client):
    """Minting does not change the target user's last_login_at."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    before = _user_row(target["email"]).last_login_at

    assert _mint(client, caller, target["email"]).status_code == 200
    assert _user_row(target["email"]).last_login_at == before


# ── Audit trail ───────────────────────────────────────────────────────────────


def test_successful_mint_is_audited_with_org_method_and_jti(client):
    """One service_token_minted event: caller, target, org, verification method and the
    token's jti, and never the token itself."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    org = _make_org()
    _add_membership(target["email"], org, *SCIENTIST)

    token = _mint(client, caller, target["email"], org_id=org).json()["access_token"]
    events = _events("service_token_minted", caller["email"])

    assert len(events) == 1
    event = events[0]
    assert event.target_user_id == _user_row(target["email"]).id
    assert event.organization_id == org
    meta = event.event_metadata
    assert meta["requested_org_id"] == org
    assert meta["organization_id"] == org
    assert meta["verification_method"] == "allauth_verified_primary"
    assert meta["jti"] == decode_token(token)["jti"]
    assert token not in str(meta)


def test_refused_mint_is_audited_with_reason(client):
    """A refused mint writes one service_token_mint_denied event with the reason."""
    caller = _mint_caller(client)
    target = _existing_user(client)
    stranger_org = _make_org()

    _mint(client, caller, target["email"], org_id=stranger_org)
    events = _events("service_token_mint_denied", caller["email"])

    assert len(events) == 1
    assert events[0].target_user_id == _user_row(target["email"]).id
    assert events[0].event_metadata["reason"] == "not_a_member"
    assert events[0].event_metadata["requested_org_id"] == stranger_org
    assert _events("service_token_minted", caller["email"]) == []


def test_unknown_email_refusal_is_audited(client):
    """Refusing an unknown email is audited with reason unknown_user and no target id."""
    caller = _mint_caller(client)
    email = f"nobody-{uuid.uuid4().hex[:8]}@example.test"

    _mint(client, caller, email)
    events = _events("service_token_mint_denied", caller["email"])
    assert [e.event_metadata["reason"] for e in events] == ["unknown_user"]
    assert events[0].target_user_id is None
    assert events[0].event_metadata["target_email"] == email
