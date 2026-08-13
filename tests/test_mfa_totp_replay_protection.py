"""HIPAA Phase 3b: TOTP replay / consumed-time-step protection.

Exercises app/services/mfa_service.py's _totp_matched_step/
_try_claim_totp_step/MFAUsedTOTPStep mechanism through the real HTTP
surface (POST /users/me/mfa/challenge), following this repo's established
convention (see tests/test_mfa_login_challenge.py's own module
docstring): real routes/services against the shared sqlite test DB, rows/
audit events read back via a second, direct session. Self-contained
(local helpers), same per-file duplication convention every other test
file here already uses.

The underlying single-use guarantee is a plain SQL UNIQUE constraint
(app/db/models.py::MFAUsedTOTPStep, `UNIQUE(device_id, time_step)`), not
Redis -- so this repo's fakeredis test facility (used by
tests/test_mfa_challenge_throttling.py/tests/test_login_rate_limiting.py)
isn't the relevant distributed-storage mechanism here. The shared SQLite
test engine (same convention tests/test_login_rate_limiting.py's own
concurrency test already relies on for app/core/rate_limit.py's Lua
script) plays that role instead -- correctness here comes from the
database engine's own constraint enforcement, which is exactly what
makes this mechanism correct across any number of horizontally-scaled
app instances sharing one production database, not from anything
Python-level.
"""
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, MFAUsedTOTPStep, User
from app.services import mfa_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

# Own, thread-safe engine for the concurrency test below (worker threads
# each open their own session) -- check_same_thread=False, same override
# conftest.py's own test_engine already applies for the identical reason.
_concurrent_engine = create_engine("sqlite:///./test.db", connect_args={"check_same_thread": False})
_ConcurrentSession = sessionmaker(bind=_concurrent_engine)

_PERIOD = mfa_service._PERIOD


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"totp-replay-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _enable_mfa(client, headers) -> tuple[str, int]:
    """Returns (secret, device_id)."""
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret, enroll["device_id"]


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
                "before_state": r.before_state, "after_state": r.after_state,
                "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _used_steps_for_device(device_id: int) -> list[int]:
    db = _DirectSession()
    try:
        rows = db.query(MFAUsedTOTPStep).filter(MFAUsedTOTPStep.device_id == device_id).all()
        return [r.time_step for r in rows]
    finally:
        db.close()


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_mfa.py's/tests/test_mfa_login_challenge.py's
    fixture of the same name."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


@pytest.fixture
def mfa_user(client, configured_crypto):
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    user["secret"], user["device_id"] = _enable_mfa(client, headers)
    user["user_id"] = _user_id(client, user["access_token"])
    return user


# ── 1. First use succeeds ────────────────────────────────────────────────


def test_same_valid_totp_accepted_once(client, mfa_user):
    now = int(time.time())
    code = mfa_service._totp_code_at(mfa_user["secret"], now)
    token = _fresh_challenge_token(client, mfa_user)

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})

    assert resp.status_code == 200
    assert "access_token" in resp.json()
    # Exactly one step recorded as used for this device.
    assert len(_used_steps_for_device(mfa_user["device_id"])) == 1


# ── 2. Immediate replay rejected ─────────────────────────────────────────


def test_immediate_replay_with_fresh_challenge_token_rejected(client, mfa_user):
    """The gap this PR closes: a captured/known-valid code must not be
    redeemable a second time via a *different* challenge_token (a fresh
    login), even though the code itself is still cryptographically valid
    for the remainder of its ~90s window."""
    now = int(time.time())
    code = mfa_service._totp_code_at(mfa_user["secret"], now)

    first_token = _fresh_challenge_token(client, mfa_user)
    first = client.post("/users/me/mfa/challenge", json={"challenge_token": first_token, "code": code})
    assert first.status_code == 200

    second_token = _fresh_challenge_token(client, mfa_user)
    second = client.post("/users/me/mfa/challenge", json={"challenge_token": second_token, "code": code})

    assert second.status_code == 400  # same generic "invalid code" shape as a wrong guess
    assert "access_token" not in second.json()


def test_replay_falls_through_to_recovery_code_check_and_then_fails_generically(client, mfa_user):
    """A replayed TOTP code must not short-circuit differently than a
    wrong one -- it still gets a chance against recovery codes (same code
    shape check as any other failed TOTP match) before the generic 400,
    preserving the existing "TOTP vs recovery code" disambiguation-by-
    format behavior untouched."""
    now = int(time.time())
    code = mfa_service._totp_code_at(mfa_user["secret"], now)
    client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code,
    })

    resp = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code,
    })
    assert resp.status_code == 400
    assert resp.json()["detail"] == "Invalid verification code"


# ── 3. Concurrency ────────────────────────────────────────────────────────


def test_concurrent_duplicate_submissions_result_in_exactly_one_success(client, mfa_user):
    now = int(time.time())
    code = mfa_service._totp_code_at(mfa_user["secret"], now)
    tokens = [_fresh_challenge_token(client, mfa_user) for _ in range(8)]

    def _attempt(tok):
        return client.post("/users/me/mfa/challenge", json={"challenge_token": tok, "code": code})

    with ThreadPoolExecutor(max_workers=8) as pool:
        responses = list(pool.map(_attempt, tokens))

    successes = [r for r in responses if r.status_code == 200]
    assert len(successes) == 1
    # No more than one claimed row for this device/step, regardless of
    # how many requests raced -- the UNIQUE constraint, not Python-level
    # locking, is what guarantees this.
    assert len(_used_steps_for_device(mfa_user["device_id"])) == 1


def test_try_claim_totp_step_atomicity_directly(client, mfa_user):
    """Same shape as tests/test_login_rate_limiting.py's own
    test_concurrent_failures_are_atomic_no_overshoot -- exercises the
    primitive directly, since HTTP round trips would just add unrelated
    latency noise on top of what's actually being tested. Each worker
    opens its own session against _concurrent_engine (check_same_thread=
    False) -- a SQLAlchemy Session is not itself safe to share across
    threads."""
    def _claim(_):
        d = _ConcurrentSession()
        try:
            return mfa_service._try_claim_totp_step(d, mfa_user["device_id"], 999999)
        finally:
            d.close()

    with ThreadPoolExecutor(max_workers=10) as pool:
        results = list(pool.map(_claim, range(20)))

    assert sum(1 for r in results if r) == 1


# ── 4/5. Window / adjacent-step behavior ─────────────────────────────────


def test_replay_rejected_anywhere_within_the_acceptance_window(client, mfa_user):
    """A code generated for the *previous* step (still valid under the
    +-1 clock-skew window) is accepted once on first use, then rejected
    on replay -- the window widening the set of currently-valid codes
    must not widen how many times any one of them can be redeemed."""
    now = int(time.time())
    prev_step_code = mfa_service._totp_code_at(mfa_user["secret"], now - _PERIOD)

    first = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": prev_step_code,
    })
    assert first.status_code == 200

    second = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": prev_step_code,
    })
    assert second.status_code == 400


def test_legitimate_adjacent_step_code_still_valid_after_prior_step_used(client, mfa_user):
    """Existing clock-skew tolerance is unaffected: consuming step N does
    not block a *different*, legitimate code for step N+1 (e.g. the
    authenticator app's own natural 30s rollover between two real login
    attempts)."""
    now = int(time.time())
    code_a = mfa_service._totp_code_at(mfa_user["secret"], now)
    first = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code_a,
    })
    assert first.status_code == 200

    code_b = mfa_service._totp_code_at(mfa_user["secret"], now + _PERIOD)
    if code_b == code_a:
        pytest.skip("degenerate case: adjacent step produced an identical code")
    second = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code_b,
    })
    assert second.status_code == 200


def test_first_use_still_honors_plus_minus_one_step_clock_skew(client, mfa_user):
    """_totp_matched_step must accept the exact same +-1 step window
    verify_totp_code always has -- verified independently of any replay
    concern, on a device's very first use."""
    now = int(time.time())
    future_step_code = mfa_service._totp_code_at(mfa_user["secret"], now + _PERIOD)
    resp = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": future_step_code,
    })
    assert resp.status_code == 200


# ── 6. Old/expired step state doesn't interfere ─────────────────────────


def test_old_consumed_step_does_not_block_unrelated_later_step(client, mfa_user):
    """A step consumed long ago (well outside any real verification
    window) has no bearing on a later, different, real-time-valid step --
    'expiration' is implicit in TOTP's own ever-advancing counter, not a
    cleanup job this mechanism needs to run. See MFAUsedTOTPStep's own
    docstring. Verification always checks against real wall-clock time
    (mfa_service._totp_matched_step's own for_time=None default), so this
    directly seeds an old row rather than trying to fake a future
    verification time -- there's no way to make the server itself believe
    time has advanced.
    """
    db = _DirectSession()
    try:
        db.add(MFAUsedTOTPStep(device_id=mfa_user["device_id"], time_step=12345))
        db.commit()
    finally:
        db.close()

    now = int(time.time())
    current_code = mfa_service._totp_code_at(mfa_user["secret"], now)
    resp = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": current_code,
    })
    assert resp.status_code == 200
    assert len(_used_steps_for_device(mfa_user["device_id"])) == 2


# ── 7. Same challenge cannot be completed twice ──────────────────────────


def test_same_challenge_token_cannot_be_completed_twice(client, mfa_user):
    now = int(time.time())
    code = mfa_service._totp_code_at(mfa_user["secret"], now)
    token = _fresh_challenge_token(client, mfa_user)

    first = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert first.status_code == 200

    second = client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": code})
    assert second.status_code == 401  # jti already consumed -- MFAChallengeError, not a fresh replay check


# ── _consume_challenge_jti concurrency hardening ─────────────────────────


def test_consume_challenge_jti_raises_clean_error_on_jti_collision(client):
    """Direct unit coverage of the hardening this PR adds: a genuine
    RevokedToken.token_jti UNIQUE-constraint collision (simulating the
    losing side of a concurrent race) must raise MFAChallengeError, not
    let a raw IntegrityError escape uncaught."""
    from app.db.models import RevokedToken

    jti = f"test-collision-{uuid.uuid4().hex}"
    db = _DirectSession()
    try:
        db.add(RevokedToken(token_jti=jti))
        db.commit()
    finally:
        db.close()

    db2 = _DirectSession()
    try:
        with pytest.raises(mfa_service.MFAChallengeError):
            mfa_service._consume_challenge_jti(db2, jti)
        # The session must come out usable, not left in a broken
        # transaction state, for whatever the caller does next.
        db2.query(User).count()
    finally:
        db2.close()


def test_concurrent_recovery_code_race_yields_exactly_one_success_not_500(client, mfa_user):
    """The recovery-code path's own read-then-write (verify_recovery_code
    + consume_recovery_code) has no atomic single-winner mechanism of its
    own -- see docs/security-mfa-totp-replay-protection.md's
    "Recovery-code concurrency finding". This proves the *outcome* users
    and operators actually care about still holds regardless of exactly
    how the race interleaves: exactly one session is ever minted, and
    every other request gets a clean, pre-existing error shape (401 if it
    lost the jti race in _consume_challenge_jti, hardened above; 400 if
    consume_recovery_code's used_at had already landed by the time its
    own verify_recovery_code read ran) -- never an unhandled 500, even
    though the recovery code's own `used_at` may be written more than
    once as a side effect."""
    headers = _auth_header(mfa_user["access_token"])
    recovery_code = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"][0]
    token = _fresh_challenge_token(client, mfa_user)

    def _attempt(_):
        return client.post("/users/me/mfa/challenge", json={"challenge_token": token, "code": recovery_code})

    with ThreadPoolExecutor(max_workers=6) as pool:
        responses = list(pool.map(_attempt, range(6)))

    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert 500 not in statuses
    # Every non-winner lands on one of two clean, pre-existing response
    # shapes depending on how the race actually interleaved: 401 (lost
    # the jti race in _consume_challenge_jti, hardened above) or 400
    # (consume_recovery_code's used_at had already landed by the time
    # this thread's own verify_recovery_code read ran, so it found no
    # unused match at all) -- never a 500, and never a second 200.
    assert all(s in (200, 401, 400) for s in statuses)


# ── 8. Cross-user isolation ────────────────────────────────────────────────


def test_cross_user_replay_fails(client, configured_crypto):
    user_a = _register_and_login(client)
    headers_a = _auth_header(user_a["access_token"])
    user_a["secret"], user_a["device_id"] = _enable_mfa(client, headers_a)

    user_b = _register_and_login(client)
    headers_b = _auth_header(user_b["access_token"])
    user_b["secret"], user_b["device_id"] = _enable_mfa(client, headers_b)

    now = int(time.time())
    code_a = mfa_service._totp_code_at(user_a["secret"], now)
    resp = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, user_a), "code": code_a,
    })
    assert resp.status_code == 200

    # B's own device is untouched by A's consumed step -- different
    # device_id, so even a numeric coincidence in time_step can't cross
    # devices (UNIQUE is per (device_id, time_step), not global).
    code_b = mfa_service._totp_code_at(user_b["secret"], now)
    resp_b = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, user_b), "code": code_b,
    })
    assert resp_b.status_code == 200


# ── 9. Recovery-code behavior unchanged ───────────────────────────────────


def test_recovery_code_single_use_still_enforced_unchanged(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    recovery_code = codes[0]

    first = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": recovery_code,
    })
    assert first.status_code == 200

    second = client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": recovery_code,
    })
    assert second.status_code == 400  # already used -- MFARecoveryCode.used_at, unchanged mechanism


def test_recovery_code_success_does_not_touch_totp_step_table(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": codes[0],
    })
    assert _used_steps_for_device(mfa_user["device_id"]) == []


# ── 10. No secret/code/token leakage ─────────────────────────────────────


def test_replay_rejection_leaks_no_secret_code_or_token_in_audit(client, mfa_user):
    now = int(time.time())
    code = mfa_service._totp_code_at(mfa_user["secret"], now)
    client.post("/users/me/mfa/challenge", json={
        "challenge_token": _fresh_challenge_token(client, mfa_user), "code": code,
    })
    replay_token = _fresh_challenge_token(client, mfa_user)
    client.post("/users/me/mfa/challenge", json={"challenge_token": replay_token, "code": code})

    events = _events(actor_user_id=mfa_user["user_id"])
    for e in events:
        blob = str(e)
        assert mfa_user["secret"] not in blob
        assert code not in blob
        assert replay_token not in blob
        assert "encrypted_secret" not in blob


# ── 12. Enrollment unaffected ─────────────────────────────────────────────


def test_enrollment_confirmation_unaffected_by_replay_mechanism(client, configured_crypto):
    """verify_totp_enrollment still uses the unmodified, boolean-only
    verify_totp_code -- this table is never touched during enrollment."""
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))

    resp = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert resp.status_code == 200
    assert _used_steps_for_device(enroll["device_id"]) == []
