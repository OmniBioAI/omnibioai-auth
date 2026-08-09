"""Phase 4 PR-A (Session Foundation): the `sessions` table and its
integration into login/refresh/logout.

Uses the same direct-DB-session pattern as tests/test_refresh_rotation.py
and tests/test_token_revocation.py -- a second connection to the same
physical sqlite file conftest.py's `client` fixture uses, for setup
(org/membership creation, direct expiry manipulation) no HTTP route
exposes a way to do.
"""
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Organization, OrganizationMembership, User, UserSession

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"session-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"email": email, "password": password, **login.json()}


def _refresh(client, refresh_token):
    return client.post("/auth/refresh", json={"refresh_token": refresh_token})


def _list_sessions(client, access_token):
    return client.get("/sessions", headers=_auth(access_token))


def _create_org_membership(email: str, org_slug: str) -> int:
    """Direct-DB setup: no API route lets a fresh test user create and
    join an org in one step. Returns the new organization's id."""
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        org = Organization(slug=org_slug, name=org_slug, status="active")
        db.add(org)
        db.flush()
        db.add(OrganizationMembership(organization_id=org.id, user_id=user.id, status="active"))
        db.commit()
        return org.id
    finally:
        db.close()


def _get_session_row(session_id: str) -> UserSession | None:
    db = _DirectSession()
    try:
        return db.query(UserSession).filter(UserSession.session_id == session_id).first()
    finally:
        db.close()


def _set_session_expired(session_id: str) -> None:
    db = _DirectSession()
    try:
        row = db.query(UserSession).filter(UserSession.session_id == session_id).first()
        row.expires_at = datetime.utcnow() - timedelta(days=1)
        db.commit()
    finally:
        db.close()


# ── 1: login creates a session ──────────────────────────────────────────────


def test_login_creates_exactly_one_session(client):
    user = _register_and_login(client)
    resp = _list_sessions(client, user["access_token"])
    assert resp.status_code == 200
    sessions = resp.json()
    assert len(sessions) == 1
    assert sessions[0]["status"] == "active"
    assert sessions[0]["auth_method"] == "password"
    assert sessions[0]["mfa_verified"] is True


def test_session_id_is_a_real_row_in_the_sessions_table(client):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    row = _get_session_row(session_id)
    assert row is not None
    assert row.status == "active"


# ── 2 / 13: user isolation ──────────────────────────────────────────────────


def test_session_belongs_to_correct_user(client):
    user_a = _register_and_login(client)
    user_b = _register_and_login(client)

    session_a_id = _list_sessions(client, user_a["access_token"]).json()[0]["session_id"]

    # user_b cannot see user_a's session by id.
    resp = client.get(f"/sessions/{session_a_id}", headers=_auth(user_b["access_token"]))
    assert resp.status_code == 404

    # user_b cannot revoke user_a's session either.
    resp = client.post(f"/sessions/{session_a_id}/revoke", headers=_auth(user_b["access_token"]))
    assert resp.status_code == 404

    # ... and user_a's own session survives the attempt, untouched.
    row = _get_session_row(session_a_id)
    assert row.status == "active"


# ── 3 / 12: organization attribution and isolation ──────────────────────────


def test_session_belongs_to_correct_organization(client):
    user = _register_and_login(client)
    org_id = _create_org_membership(user["email"], f"org-{uuid.uuid4().hex[:8]}")

    # This user's *next* login is the first one to see the new membership
    # (build_user_claims resolves it fresh at token-issuance time).
    relog = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    tokens = relog.json()

    sessions = _list_sessions(client, tokens["access_token"]).json()
    # Two sessions now exist for this user (the original login + this one)
    # -- find the one that corresponds to this fresh login.
    newest = max(sessions, key=lambda s: s["created_at"])
    assert newest["organization_id"] == org_id


def test_organization_isolation_between_two_users(client):
    user_a = _register_and_login(client)
    user_b = _register_and_login(client)
    org_a = _create_org_membership(user_a["email"], f"org-a-{uuid.uuid4().hex[:8]}")
    org_b = _create_org_membership(user_b["email"], f"org-b-{uuid.uuid4().hex[:8]}")
    assert org_a != org_b

    relog_a = client.post("/auth/login", json={"email": user_a["email"], "password": user_a["password"]})
    relog_b = client.post("/auth/login", json={"email": user_b["email"], "password": user_b["password"]})

    sessions_a = _list_sessions(client, relog_a.json()["access_token"]).json()
    sessions_b = _list_sessions(client, relog_b.json()["access_token"]).json()

    assert all(s["organization_id"] in (None, org_a) for s in sessions_a)
    assert all(s["organization_id"] in (None, org_b) for s in sessions_b)
    assert {s["organization_id"] for s in sessions_a} != {s["organization_id"] for s in sessions_b}


# ── 4 / 5: refresh preserves session identity, no session proliferation ────


def test_refresh_preserves_session_identity(client):
    user = _register_and_login(client)
    before = _list_sessions(client, user["access_token"]).json()[0]
    session_id = before["session_id"]

    refreshed = _refresh(client, user["refresh_token"])
    assert refreshed.status_code == 200

    after_list = _list_sessions(client, refreshed.json()["access_token"]).json()
    assert len(after_list) == 1
    after = after_list[0]
    assert after["session_id"] == session_id
    assert after["last_activity_at"] >= before["last_activity_at"]
    assert after["expires_at"] >= before["expires_at"]


def test_refresh_rotation_chain_does_not_create_unnecessary_sessions(client):
    user = _register_and_login(client)

    r1 = _refresh(client, user["refresh_token"])
    r2 = _refresh(client, r1.json()["refresh_token"])
    r3 = _refresh(client, r2.json()["refresh_token"])
    assert r3.status_code == 200

    sessions = _list_sessions(client, r3.json()["access_token"]).json()
    assert len(sessions) == 1


def test_different_logins_produce_different_sessions(client):
    """Two independent logins (not a refresh chain) for the same user are
    two distinct sessions -- concurrent-session support is unrestricted by
    default, matching today's unrestricted concurrent-login behavior."""
    user = _register_and_login(client)
    second_login = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert second_login.status_code == 200

    sessions = _list_sessions(client, second_login.json()["access_token"]).json()
    assert len(sessions) == 2
    assert sessions[0]["session_id"] != sessions[1]["session_id"]


# ── 6: logout revokes the correct session ───────────────────────────────────


def test_logout_revokes_the_correct_session(client):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]

    resp = client.post("/auth/logout", json={"refresh_token": user["refresh_token"]})
    assert resp.status_code == 200

    row = _get_session_row(session_id)
    assert row.status == "revoked"
    assert row.revoked_reason == "user_logout"
    assert row.revoked_at is not None


def test_logout_does_not_revoke_a_different_users_session(client):
    user_a = _register_and_login(client)
    user_b = _register_and_login(client)
    session_b_id = _list_sessions(client, user_b["access_token"]).json()[0]["session_id"]

    client.post("/auth/logout", json={"refresh_token": user_a["refresh_token"]})

    row_b = _get_session_row(session_b_id)
    assert row_b.status == "active"


# ── 7: revoked session cannot be reused ─────────────────────────────────────


def test_revoked_session_cannot_be_reused_via_refresh(client):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]

    revoke = client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))
    assert revoke.status_code == 200
    assert revoke.json()["status"] == "revoked"
    assert revoke.json()["revoked_reason"] == "user_revoked"

    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


def test_revoke_session_endpoint_is_idempotent(client):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]

    first = client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))
    assert first.status_code == 200
    first_revoked_at = first.json()["revoked_at"]

    # A second revoke call must not 500, and must not "re-revoke" (the
    # original revoked_at is historically meaningful and must not move).
    second = client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))
    assert second.status_code == 200
    assert second.json()["revoked_at"] == first_revoked_at


def test_reuse_detection_also_revokes_the_session(client):
    """A refresh-token replay (existing reuse-detection behavior,
    unchanged) must now also show up as a revoked session, not just
    revoked RefreshToken rows."""
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]

    first = _refresh(client, user["refresh_token"])
    assert first.status_code == 200

    # Replay the original (already-rotated) token -- triggers reuse
    # detection, existing behavior, unchanged.
    replay = _refresh(client, user["refresh_token"])
    assert replay.status_code == 401

    row = _get_session_row(session_id)
    assert row.status == "revoked"
    assert row.revoked_reason == "reuse_detected"


# ── 8 / 9: expiration ───────────────────────────────────────────────────────


def test_expired_session_is_inactive(client):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _set_session_expired(session_id)

    resp = client.get(f"/sessions/{session_id}", headers=_auth(user["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["status"] == "expired"


def test_expired_session_blocks_refresh_even_though_the_refresh_token_row_itself_is_still_valid(client):
    """Isolates the new session-level guard in rotate_refresh_token: the
    presented RefreshToken row is itself still unexpired/unrevoked (a
    real deployment would never see this exact combination organically --
    RefreshToken.expires_at and the session's expires_at are always kept
    in sync by generate_tokens/touch), so if this passes, the rejection
    can only be coming from session_service.is_usable's guard, not from
    any of rotate_refresh_token's pre-existing RefreshToken-level checks.
    """
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _set_session_expired(session_id)

    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


def test_active_session_remains_usable(client):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]

    resp = client.get(f"/sessions/{session_id}", headers=_auth(user["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["status"] == "active"

    refreshed = _refresh(client, user["refresh_token"])
    assert refreshed.status_code == 200


# ── 10: concurrent refresh is safe ──────────────────────────────────────────


def test_concurrent_refresh_of_the_same_token_does_not_corrupt_the_session(client):
    """Two simultaneous refresh calls presenting the *same* refresh token.

    NOTE on what this test found: `rotate_refresh_token` has a pre-existing
    check-then-act race (no row locking between reading `db_token.rotated_at`
    and writing it) that predates this PR and is out of scope to fix here
    (redesigning refresh rotation is explicitly excluded) -- under real
    thread concurrency both presentations can observe "not yet rotated" and
    both succeed. That is a real, worth-flagging finding (see the PR-A
    report's Remaining Risks), but it is a RefreshToken-level race, not a
    session-level one.

    What this test actually guarantees, and is Session Foundation's own
    responsibility to get right regardless of how that pre-existing race
    resolves: the race must never leave a *duplicate* or orphaned session
    row behind for this family -- exactly one row must exist afterward, no
    matter how many of the two racing requests the pre-existing token-level
    logic let through, because `session_service.touch` always updates the
    one existing row for this family rather than ever inserting a second
    one.
    """
    user = _register_and_login(client)

    def _do_refresh():
        try:
            return _refresh(client, user["refresh_token"])
        except Exception as exc:  # e.g. sqlite3.OperationalError under contention
            return exc

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: _do_refresh(), range(2)))

    ok_responses = [r for r in results if not isinstance(r, Exception)]
    assert all(r.status_code in (200, 401) for r in ok_responses)

    # Confirm no duplicate/orphaned row for this family, independent of
    # which side (or both) actually won -- query the DB directly rather
    # than through a token that may or may not still be valid.
    db = _DirectSession()
    try:
        matching = (
            db.query(UserSession)
            .filter(UserSession.user_id == db.query(User).filter(User.email == user["email"]).first().id)
            .all()
        )
    finally:
        db.close()
    assert len(matching) == 1


# ── 14-16: existing login/refresh/logout tests remain green ────────────────
# (exercised by the full suite -- tests/test_auth.py, test_refresh_rotation.py,
# test_session_cookie.py -- not duplicated here.)


# ── 18: no sensitive material leaks into anything session-related ──────────


def test_session_response_never_exposes_token_shaped_fields(client):
    user = _register_and_login(client)
    resp = _list_sessions(client, user["access_token"])
    forbidden = {"token", "access_token", "refresh_token", "password", "hashed_password", "jti"}
    for session in resp.json():
        assert forbidden.isdisjoint(session.keys())


# ── session_service unit coverage (no-HTTP-round-trip edge cases) ─────────


def test_session_service_get_by_family_id_handles_falsy_input():
    from app.services import session_service

    db = _DirectSession()
    try:
        assert session_service.get_by_family_id(db, None) is None
        assert session_service.get_by_family_id(db, "") is None
    finally:
        db.close()


def test_session_service_is_usable_true_for_missing_session():
    from app.services import session_service

    # No session row exists for this family at all (e.g. a pre-PR-A
    # refresh token, not yet backfilled) -- must not be treated as unusable.
    assert session_service.is_usable(None) is True


def test_session_service_is_usable_false_for_revoked_session(client):
    from app.services import session_service

    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))

    row = _get_session_row(session_id)
    assert session_service.is_usable(row) is False


def test_session_service_touch_is_a_noop_on_a_revoked_session(client):
    from app.services import session_service

    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))
    revoked_at_before = _get_session_row(session_id).revoked_at

    db = _DirectSession()
    try:
        session_service.touch(db, session_id, datetime.utcnow() + timedelta(days=99))
        db.commit()
    finally:
        db.close()

    row = _get_session_row(session_id)
    assert row.status == "revoked"
    assert row.revoked_at == revoked_at_before
    # touch() must not have slid expires_at forward on a revoked session.
    assert row.expires_at < datetime.utcnow() + timedelta(days=90)


def test_new_session_code_contains_no_logging_of_secrets():
    """Static guard, not a runtime check: this module and the session
    routes/service deliberately add zero logging statements (see
    app/services/session_service.py's module docstring) -- assert that
    stays true, and that if a print/log statement is ever added later, it
    at least never mentions a token/password/secret-shaped name."""
    import pathlib

    forbidden_terms = ("token", "password", "secret", "refresh_token", "access_token")
    logging_calls = ("print(", "logger.", "logging.")

    for relative in (
        "app/services/session_service.py",
        "app/api/routes_sessions.py",
    ):
        path = pathlib.Path(__file__).resolve().parent.parent / relative
        for line in path.read_text().splitlines():
            if any(call in line for call in logging_calls):
                lowered = line.lower()
                assert not any(term in lowered for term in forbidden_terms), (
                    f"{relative} appears to log sensitive material: {line!r}"
                )
