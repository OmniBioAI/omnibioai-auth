"""End-to-end email OTP coverage through real Auth routes and persistence."""
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet

from app.core.config import settings
from app.db.models import MFAEmailOTP, User
from app.db.session import SessionLocal
from app.services import email_delivery_service, mfa_service


PASSWORD = "Email-MFA-test-password-2026!"


@pytest.fixture
def configured_crypto(monkeypatch):
    import app.core.crypto as crypto

    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    return crypto


def _enrolled_user(client):
    email = f"email-mfa-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    login = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    headers = {"Authorization": f"Bearer {login['access_token']}"}
    enrollment = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(enrollment["otpauth_uri"]).query)["secret"][0]
    code = mfa_service._totp_code_at(secret, int(time.time()))
    assert client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enrollment["device_id"], "code": code},
        headers=headers,
    ).status_code == 200
    db = SessionLocal()
    try:
        user_id = db.query(User).filter(User.email == email).one().id
    finally:
        db.close()
    return email, user_id, secret


def _configure(monkeypatch, email, user_id, sent):
    monkeypatch.setattr(settings, "EMAIL_MFA_ENABLED", True)
    monkeypatch.setattr(settings, "EMAIL_MFA_ADMIN_USER_ID", user_id)
    monkeypatch.setattr(settings, "EMAIL_MFA_ADMIN_ADDRESS", email)
    monkeypatch.setattr(settings, "EMAIL_MFA_OTP_PEPPER", "test-email-otp-pepper-32-bytes-minimum")
    monkeypatch.setattr(settings, "EMAIL_SERVICE_SEND_URL", "https://email.test.invalid/send")
    monkeypatch.setattr(settings, "EMAIL_SERVICE_TOKEN", "test-provider-token")
    monkeypatch.setattr(settings, "EMAIL_MFA_MAX_SENDS_PER_HOUR", 5)
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ENABLED", False)

    def capture(recipient, code, expires_minutes=5):
        sent.append((recipient, code, expires_minutes))

    monkeypatch.setattr(email_delivery_service, "send_mfa_code", capture)


def test_password_login_emails_six_digit_hash_only_code_and_completes_once(client, configured_crypto, monkeypatch, caplog):
    email, user_id, secret = _enrolled_user(client)
    sent = []
    _configure(monkeypatch, email, user_id, sent)

    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200
    challenge = login.json()
    assert challenge["methods"] == ["email"]
    assert len(sent) == 1 and sent[0][0] == email and sent[0][1].isdigit() and len(sent[0][1]) == 6
    plaintext = sent[0][1]

    db = SessionLocal()
    try:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).one()
        assert row.code_hash != plaintext
        assert plaintext not in row.code_hash
        assert 295 <= (row.expires_at - row.created_at).total_seconds() <= 300
        assert row.attempts == 0 and row.consumed_at is None
    finally:
        db.close()

    verified = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": plaintext, "method": "email",
    })
    assert verified.status_code == 200
    assert verified.json()["methods"] == ["totp", "recovery_code"]
    assert "access_token" not in verified.json()
    totp = mfa_service._totp_code_at(secret, int(time.time()))
    completed = client.post("/users/me/mfa/challenge", json={
        "challenge_token": verified.json()["challenge_token"], "code": totp, "method": "totp",
    })
    assert completed.status_code == 200
    assert "access_token" in completed.json()
    replay = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": plaintext, "method": "email",
    })
    assert replay.status_code == 401
    assert plaintext not in caplog.text


def test_email_code_expires_and_is_limited_to_five_attempts(client, configured_crypto, monkeypatch):
    email, user_id, _ = _enrolled_user(client)
    sent = []
    _configure(monkeypatch, email, user_id, sent)
    challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    for _ in range(5):
        response = client.post("/users/me/mfa/challenge", json={
            "challenge_token": challenge["challenge_token"], "code": "999999", "method": "email",
        })
        assert response.status_code == 400
    db = SessionLocal()
    try:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).one()
        assert row.attempts == 5 and row.invalidated_at is not None
    finally:
        db.close()
    correct_after_limit = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": sent[0][1], "method": "email",
    })
    assert correct_after_limit.status_code == 400

    # A fresh password authentication creates a fresh code; force it expired.
    fresh = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    db = SessionLocal()
    try:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).order_by(MFAEmailOTP.id.desc()).first()
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()
    expired = client.post("/users/me/mfa/challenge", json={
        "challenge_token": fresh["challenge_token"], "code": sent[-1][1], "method": "email",
    })
    assert expired.status_code == 400


def test_resend_enforces_cooldown_and_invalidates_previous_code(client, configured_crypto, monkeypatch):
    email, user_id, _ = _enrolled_user(client)
    sent = []
    _configure(monkeypatch, email, user_id, sent)
    challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    immediate = client.post("/users/me/mfa/email/resend", json={"challenge_token": challenge["challenge_token"]})
    assert immediate.status_code == 429
    assert int(immediate.headers["Retry-After"]) > 0

    db = SessionLocal()
    try:
        first = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).one()
        first.created_at = datetime.utcnow() - timedelta(seconds=61)
        db.commit()
    finally:
        db.close()
    resend = client.post("/users/me/mfa/email/resend", json={"challenge_token": challenge["challenge_token"]})
    assert resend.status_code == 200
    assert resend.json() == {"sent": True, "cooldown_seconds": 60}
    assert len(sent) == 2
    old = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": sent[0][1], "method": "email",
    })
    assert old.status_code == 400
    new = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": sent[1][1], "method": "email",
    })
    assert new.status_code == 200


def test_email_code_delivery_is_rate_limited_per_account(client, configured_crypto, monkeypatch):
    email, user_id, _ = _enrolled_user(client)
    sent = []
    _configure(monkeypatch, email, user_id, sent)

    for _ in range(5):
        response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 200
        assert response.json()["methods"] == ["email"]

    limited = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert limited.status_code == 429
    assert limited.json()["error"] == "email_otp_rate_limited"
    assert int(limited.headers["Retry-After"]) > 0
    assert len(sent) == 5


def test_google_authenticator_remains_required_after_email_for_enrolled_user(client, configured_crypto, monkeypatch):
    email, user_id, secret = _enrolled_user(client)
    sent = []
    _configure(monkeypatch, email, user_id, sent)
    challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    code = mfa_service._totp_code_at(secret, int(time.time()))
    bypass = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": code, "method": "totp",
    })
    assert bypass.status_code == 400
    email_step = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": sent[0][1], "method": "email",
    })
    assert email_step.status_code == 200
    assert email_step.json()["methods"] == ["totp", "recovery_code"]
    response = client.post("/users/me/mfa/challenge", json={
        "challenge_token": email_step.json()["challenge_token"], "code": code, "method": "totp",
    })
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_designated_admin_receives_email_mfa_without_an_authenticator_enrollment(client, monkeypatch):
    email = f"email-mfa-unenrolled-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": PASSWORD})
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        user_id = user.id
        user.mfa_enabled = False
        user.mfa_status = "disabled"
        db.commit()
    finally:
        db.close()
    sent = []
    _configure(monkeypatch, email, user_id, sent)

    challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert challenge.status_code == 200
    assert challenge.json()["methods"] == ["email"]
    assert len(sent) == 1
    completed = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge.json()["challenge_token"],
        "code": sent[0][1],
        "method": "email",
    })
    assert completed.status_code == 200


def test_delivery_failure_fails_closed_without_persisting_code(client, configured_crypto, monkeypatch):
    email, user_id, _ = _enrolled_user(client)
    sent = []
    _configure(monkeypatch, email, user_id, sent)

    def fail(*_args, **_kwargs):
        raise email_delivery_service.EmailDeliveryError("provider unavailable")

    monkeypatch.setattr(email_delivery_service, "send_mfa_code", fail)
    response = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 503
    assert "code" not in response.text.lower()
    db = SessionLocal()
    try:
        assert db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).count() == 0
    finally:
        db.close()
