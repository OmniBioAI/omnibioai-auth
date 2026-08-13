"""HIPAA Phase 4 follow-up: POST /auth/{provider}/link/confirm timing
side-channel closure.

app/api/routes_oauth.py::confirm_oauth_link was flagged, but explicitly
not fixed, by HIPAA Phase 4
(docs/security-login-timing-side-channel.md's "Residual limitations" #1):
its own `verify_password` call site had the identical class of gap
authenticate_user had -- the "account not found" and "no password set"
failure branches returned before any hashing work, while the "wrong
password" branch paid a full bcrypt verification. See
docs/security-link-confirm-timing-equalization.md for the full
discovery/threat-model/design writeup, including why this is lower
severity than the original login oracle.

Same deterministic-testing convention as
tests/test_login_timing_side_channel.py: spy on
app.api.routes_oauth.verify_password and assert call count/argument
identity, never wall-clock duration.
"""
import uuid

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_link_token, create_oauth_state_token
from app.core.oauth_providers import PROVIDERS
from app.core.security import DUMMY_PASSWORD_HASH
from app.db.models import AuditEvent, User
from app.services import oauth_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _unique_email():
    return f"link-timing-{uuid.uuid4().hex[:10]}@omnibioai.test"


@pytest.fixture
def configured_google(monkeypatch):
    monkeypatch.setitem(PROVIDERS["google"], "client_id", "test-google-client-id")
    monkeypatch.setitem(PROVIDERS["google"], "client_secret", "test-google-client-secret")


def _mock_exchange(monkeypatch, provider_user_id, email):
    async def fake_exchange(provider, code, code_verifier=None):
        return provider_user_id, email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)


def _mint_link_token(client, configured_google, monkeypatch, email, provider_user_id):
    """Drives the real /auth/google/callback link_required path to obtain a
    genuine, server-issued link_token for `email`, rather than
    hand-constructing the payload -- exercises this route the way an
    actual attacker with a stolen token would have obtained one."""
    _mock_exchange(monkeypatch, provider_user_id, email)
    state = create_oauth_state_token("google")
    resp = client.post("/auth/google/callback", json={"code": "fake-code", "state": state})
    assert resp.json()["status"] == "link_required"
    return resp.json()["link_token"]


@pytest.fixture
def verify_password_spy(monkeypatch):
    """Same shape as test_login_timing_side_channel.py's own fixture, but
    against routes_oauth's imported name (verify_password is imported
    directly into that module's namespace, not called via a module
    prefix)."""
    from app.core.security import verify_password as _real_verify_password
    import app.api.routes_oauth as routes_oauth_module

    calls = []

    def _spy(password, hashed):
        calls.append(hashed)
        return _real_verify_password(password, hashed)

    monkeypatch.setattr(routes_oauth_module, "verify_password", _spy)
    return calls


def _events(**filters) -> list[dict]:
    db = _DirectSession()
    try:
        query = db.query(AuditEvent)
        for key, value in filters.items():
            query = query.filter(getattr(AuditEvent, key) == value)
        rows = query.order_by(AuditEvent.id).all()
        return [{"event_type": r.event_type, "metadata": r.event_metadata} for r in rows]
    finally:
        db.close()


# ── Invalid/expired token: no user resolution reached, left unequalized ────


def test_invalid_link_token_invokes_no_hash_verification(client, verify_password_spy):
    """Deliberately NOT equalized (see docs/security-link-confirm-timing-
    equalization.md's "Scope" section): decode_token fails before any
    user lookup happens at all -- there is no user-existence signal here
    to blur, only a "is this a validly-signed token" signal that's
    already status-code-visible (400) independent of timing, exactly as
    HIPAA Phase 4 documented for this route."""
    resp = client.post("/auth/link/confirm", json={"link_token": "garbage", "password": "whatever"})
    assert resp.status_code == 400
    assert verify_password_spy == []


def test_wrong_token_type_invokes_no_hash_verification(client, verify_password_spy):
    from app.core.jwt import create_oauth_state_token as _mint_state
    wrong_type_token = _mint_state("google")  # a real, validly-signed token, but type="oauth_state"
    resp = client.post("/auth/link/confirm", json={"link_token": wrong_type_token, "password": "whatever"})
    assert resp.status_code == 400
    assert verify_password_spy == []


# ── Account not found: now equalized ────────────────────────────────────────


def test_link_token_for_deleted_account_invokes_one_dummy_hash_verification(client, verify_password_spy):
    """Simulates the race this branch actually guards against (see
    docs/security-link-confirm-timing-equalization.md): the account the
    token was minted for no longer exists by confirm-time."""
    email = _unique_email()
    db = _DirectSession()
    try:
        user = User(email=email, hashed_password="irrelevant", status="active")
        db.add(user)
        db.commit()
        user_id = user.id
    finally:
        db.close()

    link_token = create_link_token(user_id, "google", "google-uid-ghost", email)

    db = _DirectSession()
    try:
        db.query(User).filter(User.id == user_id).delete()
        db.commit()
    finally:
        db.close()

    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "whatever-guess"})
    assert resp.status_code == 404
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


def test_link_token_user_id_mismatch_invokes_one_dummy_hash_verification(client, verify_password_spy):
    """payload['user_id'] no longer matches the row found by
    payload['email'] (e.g. the email was reassigned to a different
    account) -- same 404 branch, same equalization."""
    email = _unique_email()
    db = _DirectSession()
    try:
        user = User(email=email, hashed_password="irrelevant", status="active")
        db.add(user)
        db.commit()
        real_id = user.id
    finally:
        db.close()

    link_token = create_link_token(real_id + 999999, "google", "google-uid-mismatch", email)

    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "whatever-guess"})
    assert resp.status_code == 404
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


# ── No password set: now equalized ──────────────────────────────────────────


def test_link_token_for_passwordless_account_invokes_one_dummy_hash_verification(client, verify_password_spy):
    email = _unique_email()
    db = _DirectSession()
    try:
        user = User(email=email, hashed_password=None, status="active")
        db.add(user)
        db.commit()
        user_id = user.id
    finally:
        db.close()

    link_token = create_link_token(user_id, "google", "google-uid-nopass", email)

    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "whatever-guess"})
    assert resp.status_code == 409
    assert verify_password_spy == [DUMMY_PASSWORD_HASH]


# ── Wrong password: unchanged, still one real-hash verification ────────────


def test_link_confirm_wrong_password_invokes_one_real_hash_verification(
    client, configured_google, monkeypatch, registered_user, verify_password_spy,
):
    link_token = _mint_link_token(client, configured_google, monkeypatch, registered_user["email"], "google-uid-wrong-pw")
    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"})
    assert resp.status_code == 401
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


# ── Success: unchanged, still one real-hash verification, still links ──────


def test_link_confirm_success_invokes_one_real_hash_verification_and_links_account(
    client, configured_google, monkeypatch, registered_user, verify_password_spy,
):
    link_token = _mint_link_token(client, configured_google, monkeypatch, registered_user["email"], "google-uid-ok")
    resp = client.post(
        "/auth/link/confirm", json={"link_token": link_token, "password": registered_user["password"]}
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH

    # subsequent logins via the same provider identity go straight through --
    # confirms link_oauth_to_existing_user actually ran, unchanged
    state2 = create_oauth_state_token("google")
    second = client.post("/auth/google/callback", json={"code": "fake-code-2", "state": state2})
    assert second.json()["status"] == "ok"


def test_link_confirm_mfa_required_invokes_one_real_hash_verification_and_challenges(
    client, configured_google, monkeypatch, registered_user, verify_password_spy,
):
    """MFA behavior must be completely untouched by this fix -- same
    real-hash branch as any other correct password, only the response
    shape (challenge, not tokens) differs, exactly as before."""
    from cryptography.fernet import Fernet
    import app.core.crypto as crypto

    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))

    login = client.post(
        "/auth/login", json={"email": registered_user["email"], "password": registered_user["password"]}
    )
    access_token = login.json()["access_token"]
    headers = {"Authorization": f"Bearer {access_token}"}

    import urllib.parse
    from app.services import mfa_service
    import time

    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(enroll["otpauth_uri"]).query)["secret"][0]
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200

    link_token = _mint_link_token(client, configured_google, monkeypatch, registered_user["email"], "google-uid-mfa")
    verify_password_spy.clear()
    resp = client.post(
        "/auth/link/confirm", json={"link_token": link_token, "password": registered_user["password"]}
    )
    assert resp.status_code == 200
    assert resp.json()["mfa_required"] is True
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


# ── No secret leakage in audit / response ───────────────────────────────────


def test_no_password_or_dummy_hash_leaked_in_audit_or_response(client, verify_password_spy):
    email = _unique_email()
    db = _DirectSession()
    try:
        user = User(email=email, hashed_password=None, status="active")
        db.add(user)
        db.commit()
        user_id = user.id
    finally:
        db.close()

    link_token = create_link_token(user_id, "google", "google-uid-leak", email)
    secret_guess = "S3cretGuessPassword!"
    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": secret_guess})
    assert resp.status_code == 409
    assert secret_guess not in resp.text
    assert DUMMY_PASSWORD_HASH not in resp.text

    # this route emits no audit event today (unchanged by this fix) --
    # confirm that stays true, and that nothing about this request leaked
    # into whatever audit events exist regardless.
    events = _events()
    blob = str(events)
    assert secret_guess not in blob
    assert DUMMY_PASSWORD_HASH not in blob


# ── OAuth/SAML org-linking (idp_org_id) path unaffected ─────────────────────


def test_sso_link_confirm_wrong_password_still_invokes_one_real_hash_verification_no_membership_provisioned(
    client, registered_user, verify_password_spy,
):
    """A link token carrying idp_org_id (enterprise SSO flow) that fails
    password verification must behave identically to the 3-provider
    flow's own wrong-password branch: one real-hash verification, no
    membership provisioned (jit_provision_membership is only reached
    after a successful verification, unchanged by this fix)."""
    link_token = create_link_token(
        _user_id_for(registered_user["email"]),
        "google", "google-uid-sso-wrong", registered_user["email"], idp_org_id=1,
    )
    resp = client.post("/auth/link/confirm", json={"link_token": link_token, "password": "wrong-password"})
    assert resp.status_code == 401
    assert len(verify_password_spy) == 1
    assert verify_password_spy[0] != DUMMY_PASSWORD_HASH


def _user_id_for(email):
    db = _DirectSession()
    try:
        return db.query(User).filter(User.email == email).first().id
    finally:
        db.close()
