"""HIPAA Phase 5: MFA recovery-code consumption atomicity.

Exercises app/services/mfa_service.py::try_consume_recovery_code through
both the real HTTP surface (POST /users/me/mfa/challenge) and direct,
multi-session service-layer calls, following this repo's established
convention (see tests/test_mfa_totp_replay_protection.py's own module
docstring): real routes/services against the shared sqlite test DB, rows/
audit events read back via a second, direct session. Self-contained
(local helpers), same per-file duplication convention every other test
file here already uses.

The underlying single-use guarantee is a plain SQL UPDATE ... WHERE
used_at IS NULL, checked by rows-affected -- not Redis, not a Python-
level lock. Correctness comes from the database engine's own row-level
locking during the UPDATE (MySQL/InnoDB in production; SQLite's
whole-database write lock in tests), which is exactly what makes this
correct across any number of horizontally-scaled app instances sharing
one production database. See
docs/security-mfa-recovery-code-atomicity.md for the full design.
"""
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, MFARecoveryCode, User
from app.services import auth_service, mfa_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

# Own, thread-safe engine for the concurrency tests below (each caller
# opens its own session) -- check_same_thread=False, same override
# conftest.py's own test_engine (and
# tests/test_mfa_totp_replay_protection.py's own _concurrent_engine)
# already apply for the identical reason: a SQLAlchemy Session is not
# itself safe to share across threads.
_concurrent_engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
_ConcurrentSession = sessionmaker(bind=_concurrent_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"recovery-race-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _enable_mfa(client, headers) -> str:
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret


def _fresh_challenge_token(client, user) -> str:
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    return resp.json()["challenge_token"]


def _events(**filters) -> list[dict]:
    db = _DirectSession()
    try:
        query = db.query(AuditEvent)
        for key, value in filters.items():
            query = query.filter(getattr(AuditEvent, key) == value)
        rows = query.order_by(AuditEvent.id).all()
        return [
            {
                "id": r.id, "event_type": r.event_type, "actor_user_id": r.actor_user_id,
                "target_user_id": r.target_user_id,
                "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _recovery_code_row(code_id: int) -> MFARecoveryCode:
    db = _DirectSession()
    try:
        return db.query(MFARecoveryCode).filter(MFARecoveryCode.id == code_id).first()
    finally:
        db.close()


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_mfa.py's/tests/test_mfa_totp_replay_protection.py's
    fixture of the same name."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


@pytest.fixture
def mfa_user(client, configured_crypto):
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    user["secret"] = _enable_mfa(client, headers)
    user["user_id"] = _user_id(client, user["access_token"])
    return user


def _fresh_recovery_code(client, mfa_user) -> str:
    headers = _auth_header(mfa_user["access_token"])
    return client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"][0]


# ── 1/10. Normal, non-race behavior unchanged ────────────────────────────


def test_one_valid_unused_recovery_code_succeeds(client, mfa_user):
    code = _fresh_recovery_code(client, mfa_user)
    token = _fresh_challenge_token(client, mfa_user)

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})

    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_existing_recovery_code_behavior_unchanged_for_normal_requests(client, mfa_user):
    """Full end-to-end shape (mfa_last_verified_at, audit event, token
    claims) exactly as before this fix -- only the internal
    consume-mechanism changed, not any externally-observable behavior
    for the single-request case."""
    code = _fresh_recovery_code(client, mfa_user)
    token = _fresh_challenge_token(client, mfa_user)

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert resp.status_code == 200
    data = resp.json()
    assert "refresh_token" in data
    assert data["token_type"] == "bearer"

    db = _DirectSession()
    try:
        row = db.query(User).filter(User.id == mfa_user["user_id"]).first()
        assert row.mfa_last_verified_at is not None
    finally:
        db.close()

    events = _events(event_type="mfa_recovery_code_used", actor_user_id=mfa_user["user_id"])
    assert len(events) == 1
    assert events[0]["metadata"]["authentication_method"] == "password"


# ── 2. Sequential reuse fails ────────────────────────────────────────────


def test_reusing_recovery_code_sequentially_fails(client, mfa_user):
    code = _fresh_recovery_code(client, mfa_user)

    first = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code,
    })
    assert first.status_code == 200

    second = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code,
    })
    assert second.status_code == 400
    assert "access_token" not in second.json()


# ── 3/4/5. Concurrent claim -- exactly one winner, loser cannot mint a session ──


def test_concurrent_requests_different_challenge_tokens_same_code_exactly_one_success(client, mfa_user):
    """The gap this PR closes: two DIFFERENT challenge_tokens (two
    separate logins, two different jtis -- RevokedToken.token_jti's own
    UNIQUE constraint cannot backstop this, unlike the same-token case)
    concurrently presenting the SAME recovery code. Before this fix,
    both could independently observe the code as unused and both mint a
    session -- deterministically reproduced against pre-fix code during
    discovery (see docs/security-mfa-recovery-code-atomicity.md)."""
    code = _fresh_recovery_code(client, mfa_user)
    tokens = [_fresh_challenge_token(client, mfa_user) for _ in range(8)]

    def _attempt(tok):
        return client.post("/users/me/mfa/challenge", json={"challenge_token": tok, "code": code})

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(_attempt, tokens))

    statuses = [r.status_code for r in responses]
    successes = [r for r in responses if r.status_code == 200]
    assert len(successes) == 1
    assert "access_token" in successes[0].json()
    assert "refresh_token" in successes[0].json()
    # Every loser fails safely -- no session, no 500, and no ambiguity
    # about which of the pre-existing response shapes it gets.
    losers = [r for r in responses if r.status_code != 200]
    assert len(losers) == 7
    for r in losers:
        assert r.status_code == 400  # each had its own token, so it's "no match", not a jti collision
        assert "access_token" not in r.json()
        assert "refresh_token" not in r.json()
    assert 500 not in statuses


def test_concurrent_requests_same_challenge_token_same_code_exactly_one_success(client, mfa_user):
    """Same invariant, the other concurrency shape (one shared
    challenge_token, racing on both the recovery-code claim and the jti
    consumption at once) -- covered end-to-end here too, not just via
    tests/test_mfa_totp_replay_protection.py's own version of this same
    scenario."""
    code = _fresh_recovery_code(client, mfa_user)
    token = _fresh_challenge_token(client, mfa_user)

    def _attempt(_):
        return client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(_attempt, range(8)))

    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert 500 not in statuses
    assert all(s in (200, 400, 401) for s in statuses)


# ── 6/7. Deterministic, lock-free, cross-session proof ──────────────────


def test_atomicity_holds_across_separate_db_sessions_deterministic(client, mfa_user):
    """Authoritative, non-flaky proof of the invariant -- does not rely
    on real OS-thread timing/luck. Two independent SQLAlchemy sessions
    (simulating two application-instance DB connections) each perform
    their own verify_recovery_code read, explicitly interleaved *before*
    either attempts the claim -- reproducing the exact TOCTOU precondition
    the pre-fix code was vulnerable to -- then both attempt
    try_consume_recovery_code. Exactly one may return True."""
    code = _fresh_recovery_code(client, mfa_user)

    db_a = _ConcurrentSession()
    db_b = _ConcurrentSession()
    try:
        # Both "requests" read the row as unused before either writes --
        # the precondition the old read-then-write code was vulnerable
        # under, driven here explicitly rather than hoping real thread
        # scheduling reproduces it.
        match_a = mfa_service.verify_recovery_code(db_a, mfa_user["user_id"], code)
        match_b = mfa_service.verify_recovery_code(db_b, mfa_user["user_id"], code)
        assert match_a is not None and match_b is not None
        code_id = match_a.id
        assert code_id == match_b.id

        claimed_a = mfa_service.try_consume_recovery_code(db_a, code_id)
        claimed_b = mfa_service.try_consume_recovery_code(db_b, code_id)

        assert claimed_a != claimed_b  # exactly one True, one False
        assert claimed_a or claimed_b
    finally:
        db_a.close()
        db_b.close()

    row = _recovery_code_row(code_id)
    assert row.used_at is not None


def test_atomicity_does_not_depend_on_process_local_locking(client, mfa_user):
    """try_consume_recovery_code takes no lock object, module-level or
    otherwise -- each of these 25 concurrent calls opens its own,
    entirely independent DB session with no shared Python state between
    them (no threading.Lock, no shared dict) -- yet exactly one succeeds.
    The database's own UPDATE ... WHERE used_at IS NULL predicate is the
    only thing enforcing the invariant."""
    code = _fresh_recovery_code(client, mfa_user)
    match = mfa_service.verify_recovery_code(_ConcurrentSession(), mfa_user["user_id"], code)
    code_id = match.id

    def _claim(_):
        db = _ConcurrentSession()
        try:
            return mfa_service.try_consume_recovery_code(db, code_id)
        finally:
            db.close()

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_claim, range(25)))

    assert sum(1 for r in results if r) == 1


# ── 8. Challenge JTI single-use remains intact ───────────────────────────


def test_challenge_jti_single_use_remains_intact_for_recovery_code_success(client, mfa_user):
    code = _fresh_recovery_code(client, mfa_user)
    token = _fresh_challenge_token(client, mfa_user)

    first = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert first.status_code == 200

    # Same token, a *different*, still-unused code -- the token itself
    # must be rejected as already-consumed regardless of what code is
    # presented against it.
    second_code = _fresh_recovery_code(client, mfa_user)
    second = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": second_code})
    assert second.status_code == 401


# ── 9. Different codes remain independent ────────────────────────────────


def test_different_recovery_codes_consumed_independently(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    code_a, code_b = codes[0], codes[1]

    resp_a = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code_a,
    })
    assert resp_a.status_code == 200

    resp_b = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code_b,
    })
    assert resp_b.status_code == 200

    # Consuming `code_a` must not have touched `code_b`'s own row, or
    # vice versa.
    remaining = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = remaining.json()["challenge_token"]
    still_unused = codes[2]
    resp_c = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": still_unused})
    assert resp_c.status_code == 200


# ── Audit: exactly one success event under a race ────────────────────────


def test_audit_emits_exactly_one_success_event_under_concurrent_race(client, mfa_user):
    code = _fresh_recovery_code(client, mfa_user)
    tokens = [_fresh_challenge_token(client, mfa_user) for _ in range(6)]

    def _attempt(tok):
        return client.post("/users/me/mfa/challenge", json={"challenge_token": tok, "code": code})

    with ThreadPoolExecutor(max_workers=6) as pool:
        list(pool.map(_attempt, tokens))

    events = _events(event_type="mfa_recovery_code_used", actor_user_id=mfa_user["user_id"])
    assert len(events) == 1


def test_no_secret_or_code_leakage_in_audit_under_race(client, mfa_user):
    code = _fresh_recovery_code(client, mfa_user)
    tokens = [_fresh_challenge_token(client, mfa_user) for _ in range(4)]

    def _attempt(tok):
        return client.post("/users/me/mfa/challenge", json={"challenge_token": tok, "code": code})

    with ThreadPoolExecutor(max_workers=4) as pool:
        list(pool.map(_attempt, tokens))

    events = _events(actor_user_id=mfa_user["user_id"])
    for e in events:
        blob = str(e)
        assert code not in blob
        assert mfa_user["secret"] not in blob
        for t in tokens:
            assert t not in blob
