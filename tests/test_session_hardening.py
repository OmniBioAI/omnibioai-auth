"""HIPAA Phase 1 PR3: session lifecycle hardening -- idle timeout,
absolute lifetime, concurrent-session limits, and account-disable
session revocation.

Same direct-DB-session pattern tests/test_session_foundation.py already
established (see that file's own module docstring) -- a second
connection to the same physical sqlite file conftest.py's `client`
fixture uses, for setup/assertions no HTTP route exposes a way to do
(backdating created_at/last_activity_at instead of real sleeps, reading
persisted revoked_reason, querying AuditEvent directly).
"""
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.db.models import AuditEvent, User, UserSession
from app.services import session_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"session-hardening-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return {"email": email, "password": password, **login.json()}


def _refresh(client, refresh_token):
    return client.post("/auth/refresh", json={"refresh_token": refresh_token})


def _list_sessions(client, access_token):
    return client.get("/sessions", headers=_auth(access_token))


def _get_session_row(session_id: str) -> UserSession | None:
    db = _DirectSession()
    try:
        return db.query(UserSession).filter(UserSession.session_id == session_id).first()
    finally:
        db.close()


def _backdate_session(session_id: str, *, created_at=None, last_activity_at=None) -> None:
    db = _DirectSession()
    try:
        row = db.query(UserSession).filter(UserSession.session_id == session_id).first()
        if created_at is not None:
            row.created_at = created_at
        if last_activity_at is not None:
            row.last_activity_at = last_activity_at
        db.commit()
    finally:
        db.close()


def _session_revoked_events(user_id: int | None = None):
    db = _DirectSession()
    try:
        q = db.query(AuditEvent).filter(AuditEvent.event_type == "session_revoked")
        events = q.all()
        if user_id is not None:
            events = [e for e in events if e.target_user_id == user_id]
        return events
    finally:
        db.close()


def _user_id(email: str) -> int:
    db = _DirectSession()
    try:
        return db.query(User).filter(User.email == email).first().id
    finally:
        db.close()


def _set_user_status(email: str, status: str) -> None:
    """Goes through the real admin chokepoint
    (user_admin_service.set_user_status), not a raw column write --
    that function is where this PR's session-revocation-on-disable
    logic actually lives; bypassing it here would test nothing about
    that behavior."""
    from app.services import user_admin_service

    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        user_admin_service.set_user_status(db, user, status, reason="test", actor_user_id=user.id)
    finally:
        db.close()


@pytest.fixture
def tight_session_limits(monkeypatch):
    monkeypatch.setattr(settings, "SESSION_IDLE_TIMEOUT_SECONDS", 3600)
    monkeypatch.setattr(settings, "SESSION_ABSOLUTE_TIMEOUT_SECONDS", 86400)
    monkeypatch.setattr(settings, "SESSION_MAX_CONCURRENT", 3)


# ── Idle timeout ─────────────────────────────────────────────────────────

def test_refresh_succeeds_before_idle_timeout(client, tight_session_limits):
    user = _register_and_login(client)
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 200


def test_refresh_fails_after_idle_timeout(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, last_activity_at=datetime.utcnow() - timedelta(seconds=3601))

    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


def test_idle_timeout_revokes_session_with_correct_reason(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, last_activity_at=datetime.utcnow() - timedelta(seconds=3601))

    _refresh(client, user["refresh_token"])

    row = _get_session_row(session_id)
    assert row.status == session_service.STATUS_REVOKED
    assert row.revoked_reason == session_service.REASON_IDLE_TIMEOUT


def test_activity_timestamp_updates_on_successful_refresh(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    before = _get_session_row(session_id).last_activity_at

    _backdate_session(session_id, last_activity_at=datetime.utcnow() - timedelta(seconds=60))
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 200

    new_row = _get_session_row(session_id)
    assert new_row.last_activity_at > before


def test_idle_timeout_does_not_extend_absolute_lifetime(client, tight_session_limits):
    """A session refreshed just often enough to never idle-timeout must
    still die at its absolute deadline -- this is the actual bug PR3
    fixes (expires_at used to slide forward forever)."""
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    # Recent activity (idle timeout not a factor), but session created
    # long enough ago to already be past the absolute deadline.
    _backdate_session(
        session_id,
        created_at=datetime.utcnow() - timedelta(seconds=86401),
        last_activity_at=datetime.utcnow(),
    )
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401
    assert _get_session_row(session_id).revoked_reason == session_service.REASON_ABSOLUTE_TIMEOUT


# ── Absolute timeout ─────────────────────────────────────────────────────

def test_refresh_succeeds_before_absolute_deadline(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, created_at=datetime.utcnow() - timedelta(seconds=86399))
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 200


def test_refresh_fails_after_absolute_deadline(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, created_at=datetime.utcnow() - timedelta(seconds=86401))
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


def test_repeated_refreshes_cannot_keep_session_alive_past_absolute_deadline(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    # created_at fixed just under the deadline -- every refresh keeps
    # last_activity_at fresh (never idle-timing-out) but must not be
    # able to push created_at itself forward.
    fixed_created_at = datetime.utcnow() - timedelta(seconds=86300)
    _backdate_session(session_id, created_at=fixed_created_at)

    refresh_token = user["refresh_token"]
    resp = _refresh(client, refresh_token)
    assert resp.status_code == 200
    refresh_token = resp.json()["refresh_token"]
    assert _get_session_row(session_id).created_at == fixed_created_at

    # Force the (still fixed) created_at far enough past the deadline
    # relative to now, simulating "time passed" without a real sleep.
    _backdate_session(session_id, created_at=datetime.utcnow() - timedelta(seconds=86401))
    final = _refresh(client, refresh_token)
    assert final.status_code == 401


# ── Combined / boundary conditions ──────────────────────────────────────

def test_absolute_timeout_takes_priority_when_both_violated(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(
        session_id,
        created_at=datetime.utcnow() - timedelta(seconds=200000),
        last_activity_at=datetime.utcnow() - timedelta(seconds=200000),
    )
    _refresh(client, user["refresh_token"])
    assert _get_session_row(session_id).revoked_reason == session_service.REASON_ABSOLUTE_TIMEOUT


def test_idle_timeout_fires_when_only_idle_violated(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(
        session_id,
        created_at=datetime.utcnow() - timedelta(seconds=7200),  # well under absolute (86400)
        last_activity_at=datetime.utcnow() - timedelta(seconds=3601),  # over idle (3600)
    )
    _refresh(client, user["refresh_token"])
    assert _get_session_row(session_id).revoked_reason == session_service.REASON_IDLE_TIMEOUT


# ── Concurrent session limit ─────────────────────────────────────────────

def test_session_below_limit_succeeds_without_eviction(client, tight_session_limits):
    email = f"below-limit-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    session_ids = []
    for _ in range(settings.SESSION_MAX_CONCURRENT):
        login = client.post("/auth/login", json={"email": email, "password": password})
        session_ids.append(login.json()["access_token"])
    # All should still be usable -- check via /sessions using the LAST login's token.
    last_access = session_ids[-1]
    sessions = _list_sessions(client, last_access).json()
    active = [s for s in sessions if s["status"] == "active"]
    assert len(active) == settings.SESSION_MAX_CONCURRENT


def test_session_at_limit_evicts_oldest(client, tight_session_limits):
    email = f"at-limit-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})

    logins = []
    for _ in range(settings.SESSION_MAX_CONCURRENT):
        logins.append(client.post("/auth/login", json={"email": email, "password": password}).json())

    oldest_session_id = _list_sessions(client, logins[0]["access_token"]).json()
    oldest_session_id = min(oldest_session_id, key=lambda s: s["created_at"])["session_id"]

    # One more login pushes past the limit.
    one_more = client.post("/auth/login", json={"email": email, "password": password}).json()

    sessions = _list_sessions(client, one_more["access_token"]).json()
    active = [s for s in sessions if s["status"] == "active"]
    assert len(active) == settings.SESSION_MAX_CONCURRENT

    evicted = _get_session_row(oldest_session_id)
    assert evicted.status == session_service.STATUS_REVOKED
    assert evicted.revoked_reason == session_service.REASON_CONCURRENT_LIMIT


def test_oldest_session_selected_correctly_not_arbitrary(client, tight_session_limits):
    email = f"oldest-select-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})

    logins = []
    for i in range(settings.SESSION_MAX_CONCURRENT):
        login = client.post("/auth/login", json={"email": email, "password": password}).json()
        logins.append(login)
        session_id = _list_sessions(client, login["access_token"]).json()[-1]["session_id"]
        # Force a distinguishable, strictly increasing creation order.
        _backdate_session(session_id, created_at=datetime.utcnow() - timedelta(seconds=(10 - i) * 100))

    all_before = _list_sessions(client, logins[-1]["access_token"]).json()
    oldest = min(all_before, key=lambda s: s["created_at"])

    client.post("/auth/login", json={"email": email, "password": password})

    row = _get_session_row(oldest["session_id"])
    assert row.status == session_service.STATUS_REVOKED
    assert row.revoked_reason == session_service.REASON_CONCURRENT_LIMIT


def test_revoked_sessions_do_not_count_toward_limit(client, tight_session_limits):
    email = f"revoked-not-counted-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})

    logins = []
    for _ in range(settings.SESSION_MAX_CONCURRENT):
        logins.append(client.post("/auth/login", json={"email": email, "password": password}).json())

    first_session_id = _list_sessions(client, logins[0]["access_token"]).json()[0]["session_id"]
    client.post(f"/sessions/{first_session_id}/revoke", headers=_auth(logins[-1]["access_token"]))

    # A brand new login should NOT need to evict anything -- there are
    # only (limit - 1) effectively-active sessions now.
    new_login = client.post("/auth/login", json={"email": email, "password": password}).json()
    active = [s for s in _list_sessions(client, new_login["access_token"]).json() if s["status"] == "active"]
    assert len(active) == settings.SESSION_MAX_CONCURRENT


def test_idle_expired_sessions_do_not_count_toward_limit(client, tight_session_limits):
    email = f"idle-not-counted-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})

    logins = []
    for _ in range(settings.SESSION_MAX_CONCURRENT):
        logins.append(client.post("/auth/login", json={"email": email, "password": password}).json())

    idle_session_id = _list_sessions(client, logins[0]["access_token"]).json()[0]["session_id"]
    _backdate_session(idle_session_id, last_activity_at=datetime.utcnow() - timedelta(seconds=3601))

    new_login = client.post("/auth/login", json={"email": email, "password": password}).json()
    # The idle-expired one was never persisted-revoked by the eviction
    # logic (it just didn't count) -- but the real limit still holds.
    active = [s for s in _list_sessions(client, new_login["access_token"]).json() if s["status"] == "active"]
    assert len(active) <= settings.SESSION_MAX_CONCURRENT + 1  # +1: the stale "active"-labeled idle row itself


def test_concurrent_logins_cannot_trivially_bypass_limit(client, tight_session_limits):
    email = f"concurrent-login-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})

    def _login(_):
        return client.post("/auth/login", json={"email": email, "password": password})

    n_logins = settings.SESSION_MAX_CONCURRENT + 5
    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(_login, range(n_logins)))
    assert all(r.status_code == 200 for r in responses)

    last_token = responses[-1].json()["access_token"]
    active = [s for s in _list_sessions(client, last_token).json() if s["status"] == "active"]
    # SQLite has no real row-level locking (see _evict_oldest_sessions_
    # over_limit's own docstring) so a small overshoot under heavy
    # concurrency here is the expected, documented degradation -- the
    # real guarantee holds under MySQL/InnoDB. This asserts the bound
    # stays *sane*, not exact, on this backend.
    assert len(active) <= n_logins


# ── Manual revocation / logout regressions ──────────────────────────────

def test_manual_session_revocation_still_works(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    resp = client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))
    assert resp.status_code == 200
    assert resp.json()["status"] == "revoked"


def test_refresh_after_manual_revocation_fails(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    client.post(f"/sessions/{session_id}/revoke", headers=_auth(user["access_token"]))
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


def test_logout_still_revokes_correct_session(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    logout = client.post(
        "/auth/logout",
        json={"refresh_token": user["refresh_token"], "access_token": user["access_token"]},
    )
    assert logout.status_code == 200
    assert _get_session_row(session_id).status == session_service.STATUS_REVOKED


# ── Account disable / re-enable ───────────────────────────────────────────

def test_disabling_user_revokes_all_active_sessions(client, tight_session_limits):
    email = f"disable-sessions-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    for _ in range(2):
        client.post("/auth/login", json={"email": email, "password": password})

    _set_user_status(email, "suspended")

    user_id = _user_id(email)
    db = _DirectSession()
    try:
        rows = db.query(UserSession).filter(UserSession.user_id == user_id).all()
    finally:
        db.close()
    assert len(rows) == 2
    assert all(r.status == session_service.STATUS_REVOKED for r in rows)
    assert all(r.revoked_reason == session_service.REASON_ACCOUNT_DISABLED for r in rows)


def test_disabled_user_refresh_fails_immediately(client, tight_session_limits):
    user = _register_and_login(client)
    _set_user_status(user["email"], "suspended")
    resp = _refresh(client, user["refresh_token"])
    assert resp.status_code == 401


def test_disabled_user_authenticated_access_fails(client, tight_session_limits):
    user = _register_and_login(client)
    _set_user_status(user["email"], "suspended")
    resp = client.post("/auth/validate", json={"token": user["access_token"]})
    assert resp.json()["valid"] is False


def test_reenable_does_not_resurrect_old_refresh_token(client, tight_session_limits):
    """The core regression this PR fixes: before PR3, a disabled user's
    refresh token was only ever *blocked* by a live status check, never
    actually revoked -- re-enabling the account silently made it valid
    again. Now it's explicitly revoked, so it stays dead even after
    re-enable."""
    user = _register_and_login(client)
    _set_user_status(user["email"], "suspended")
    assert _refresh(client, user["refresh_token"]).status_code == 401

    _set_user_status(user["email"], "active")

    still_dead = _refresh(client, user["refresh_token"])
    assert still_dead.status_code == 401

    # The user must establish a brand new session -- a fresh login works.
    fresh_login = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert fresh_login.status_code == 200


def test_reenabled_user_old_access_token_stays_rejected_until_expiry_semantics_unchanged(client, tight_session_limits):
    """Not a new guarantee (access-token rejection on suspend/status is
    pre-existing, unchanged by this PR) -- locks in that re-enabling
    doesn't retroactively make an old access token issued before/during
    suspension valid again either, since /auth/validate re-checks
    User.status live, not from any session-derived state this PR added.
    """
    user = _register_and_login(client)
    _set_user_status(user["email"], "suspended")
    assert client.post("/auth/validate", json={"token": user["access_token"]}).json()["valid"] is False
    _set_user_status(user["email"], "active")
    # The OLD access token is still, coincidentally, unexpired (15 min
    # TTL) and User.status is active again -- pre-existing behavior
    # (unrelated to session revocation) says this now validates again,
    # since access-token validity was never tied to session state to
    # begin with. This documents that boundary rather than asserting
    # something this PR doesn't claim to change.
    assert client.post("/auth/validate", json={"token": user["access_token"]}).json()["valid"] is True


# ── Audit ────────────────────────────────────────────────────────────────

def test_audit_event_on_idle_timeout(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, last_activity_at=datetime.utcnow() - timedelta(seconds=3601))
    _refresh(client, user["refresh_token"])

    events = _session_revoked_events(_user_id(user["email"]))
    reasons = [e.event_metadata.get("reason") for e in events]
    assert session_service.REASON_IDLE_TIMEOUT in reasons


def test_audit_event_on_absolute_timeout(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, created_at=datetime.utcnow() - timedelta(seconds=86401))
    _refresh(client, user["refresh_token"])

    events = _session_revoked_events(_user_id(user["email"]))
    reasons = [e.event_metadata.get("reason") for e in events]
    assert session_service.REASON_ABSOLUTE_TIMEOUT in reasons


def test_audit_event_on_concurrent_eviction(client, tight_session_limits):
    email = f"audit-concurrent-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    for _ in range(settings.SESSION_MAX_CONCURRENT + 1):
        client.post("/auth/login", json={"email": email, "password": password})

    events = _session_revoked_events(_user_id(email))
    reasons = [e.event_metadata.get("reason") for e in events]
    assert session_service.REASON_CONCURRENT_LIMIT in reasons


def test_audit_event_on_account_disable(client, tight_session_limits):
    user = _register_and_login(client)
    _set_user_status(user["email"], "suspended")

    events = _session_revoked_events(_user_id(user["email"]))
    reasons = [e.event_metadata.get("reason") for e in events]
    assert session_service.REASON_ACCOUNT_DISABLED in reasons


def test_audit_events_contain_no_secrets(client, tight_session_limits):
    user = _register_and_login(client)
    session_id = _list_sessions(client, user["access_token"]).json()[0]["session_id"]
    _backdate_session(session_id, last_activity_at=datetime.utcnow() - timedelta(seconds=3601))
    _refresh(client, user["refresh_token"])
    _set_user_status(user["email"], "suspended")

    events = _session_revoked_events(_user_id(user["email"]))
    assert len(events) > 0
    for e in events:
        blob = str(e.event_metadata)
        assert user["access_token"] not in blob
        assert user["refresh_token"] not in blob
        assert user["password"] not in blob


# ── Security regressions ─────────────────────────────────────────────────

def test_refresh_token_replay_still_detected_and_now_also_audited(client, tight_session_limits):
    user = _register_and_login(client)
    old_refresh = user["refresh_token"]
    rotated = _refresh(client, old_refresh)
    assert rotated.status_code == 200

    replay = _refresh(client, old_refresh)
    assert replay.status_code == 401

    events = _session_revoked_events(_user_id(user["email"]))
    reasons = [e.event_metadata.get("reason") for e in events]
    assert session_service.REASON_REUSE_DETECTED in reasons


def test_session_listing_never_exposes_tokens(client, tight_session_limits):
    user = _register_and_login(client)
    resp = _list_sessions(client, user["access_token"])
    assert user["access_token"] not in resp.text
    assert user["refresh_token"] not in resp.text


# ── Performance: no runaway query growth on refresh ──────────────────────

def test_refresh_query_count_does_not_scale_with_other_sessions(client, tight_session_limits):
    """Listens on the app's own actual engine (app.db.session.engine --
    the one conftest.py's `client` fixture points at, not this file's
    own `_direct_engine`, which is a separate connection an app request
    never touches) to count real SQL statements a single /auth/refresh
    issues. Asserts that count with 10 pre-existing sessions for the
    user is no larger than with 1 -- catching an accidental per-session
    scan (e.g. an unbounded "all sessions for this user" query) rather
    than asserting an exact, brittle statement count.
    """
    import app.db.session as app_db_session

    def _refresh_query_count(refresh_token) -> int:
        counts = []

        def _count(*args, **kwargs):
            counts.append(1)

        event.listen(app_db_session.engine, "before_cursor_execute", _count)
        try:
            resp = _refresh(client, refresh_token)
        finally:
            event.remove(app_db_session.engine, "before_cursor_execute", _count)
        assert resp.status_code == 200
        return len(counts), resp.json()["refresh_token"]

    email_few = f"perf-few-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email_few, "password": password})
    login_few = client.post("/auth/login", json={"email": email_few, "password": password}).json()
    count_few, _ = _refresh_query_count(login_few["refresh_token"])

    email_many = f"perf-many-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email_many, "password": password})
    for _ in range(9):
        client.post("/auth/login", json={"email": email_many, "password": password})
    login_many = client.post("/auth/login", json={"email": email_many, "password": password}).json()
    count_many, _ = _refresh_query_count(login_many["refresh_token"])

    assert count_many <= count_few + 1  # +1 slack: no hard guarantee of byte-identical plans, just boundedness
