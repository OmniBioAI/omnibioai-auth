"""Regression coverage for the isolated email-first MFA stage."""
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
def email_mfa_setup(monkeypatch):
    import app.core.crypto as crypto
    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    monkeypatch.setattr(settings, "EMAIL_MFA_ENABLED", True)
    monkeypatch.setattr(settings, "EMAIL_MFA_OTP_PEPPER", "test-email-otp-pepper-32-bytes-minimum")
    monkeypatch.setattr(settings, "EMAIL_SERVICE_SEND_URL", "https://email.test.invalid/send")
    monkeypatch.setattr(settings, "EMAIL_SERVICE_TOKEN", "synthetic-test-token")
    monkeypatch.setattr(settings, "MFA_RATE_LIMIT_ENABLED", False)
    sent = []
    monkeypatch.setattr(email_delivery_service, "send_mfa_code",
                        lambda recipient, code, expires_minutes=5: sent.append((recipient, code)))
    return sent


def _enroll(client):
    email = f"recovery-email-mfa-{uuid.uuid4().hex[:10]}@omnibioai.test"
    # Enroll a synthetic authenticator before enabling the email-first
    # release policy for the login under test.
    enabled = settings.EMAIL_MFA_ENABLED
    settings.EMAIL_MFA_ENABLED = False
    assert client.post("/auth/register", json={"email": email, "password": PASSWORD}).status_code == 200
    primary = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    headers = {"Authorization": f"Bearer {primary['access_token']}"}
    enrollment = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(enrollment["otpauth_uri"]).query)["secret"][0]
    code = mfa_service._totp_code_at(secret, int(time.time()))
    assert client.post("/users/me/mfa/totp/verify", json={
        "device_id": enrollment["device_id"], "code": code,
    }, headers=headers).status_code == 200
    with SessionLocal() as db:
        user_id = db.query(User).filter(User.email == email).one().id
    settings.EMAIL_MFA_ENABLED = enabled
    return email, user_id, secret


def test_email_stage_is_hashed_single_use_and_cannot_bypass_totp(client, email_mfa_setup):
    sent = email_mfa_setup
    email, user_id, totp_secret = _enroll(client)
    login = client.post("/auth/login", json={"email": email, "password": PASSWORD})
    assert login.status_code == 200
    challenge = login.json()
    assert challenge["methods"] == ["email"]
    assert len(sent) == 1 and sent[0][0] == email and len(sent[0][1]) == 6
    with SessionLocal() as db:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).one()
        assert row.code_hash != sent[0][1]
        assert row.expires_at - row.created_at == timedelta(seconds=settings.EMAIL_MFA_TTL_SECONDS)

    totp_bypass = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"],
        "code": mfa_service._totp_code_at(totp_secret, int(time.time())), "method": "totp",
    })
    assert totp_bypass.status_code == 400
    email_step = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": sent[0][1], "method": "email",
    })
    assert email_step.status_code == 200
    assert email_step.json()["methods"] == ["totp", "recovery_code"]
    assert "access_token" not in email_step.json()
    second_factor = mfa_service._totp_code_at(totp_secret, int(time.time()))
    finished = client.post("/users/me/mfa/challenge", json={
        "challenge_token": email_step.json()["challenge_token"],
        "code": second_factor, "method": "totp",
    })
    assert finished.status_code == 200 and "access_token" in finished.json()
    replay = client.post("/users/me/mfa/challenge", json={
        "challenge_token": challenge["challenge_token"], "code": sent[0][1], "method": "email",
    })
    assert replay.status_code == 401


def test_email_code_expiry_and_attempt_limit(client, email_mfa_setup):
    sent = email_mfa_setup
    email, user_id, _ = _enroll(client)
    challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    for _ in range(settings.EMAIL_MFA_MAX_ATTEMPTS):
        response = client.post("/users/me/mfa/challenge", json={
            "challenge_token": challenge["challenge_token"], "code": "999999", "method": "email",
        })
        assert response.status_code == 400
    with SessionLocal() as db:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).one()
        assert row.attempts == settings.EMAIL_MFA_MAX_ATTEMPTS and row.invalidated_at is not None
    expired_challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    with SessionLocal() as db:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).order_by(MFAEmailOTP.id.desc()).first()
        row.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    expired = client.post("/users/me/mfa/challenge", json={
        "challenge_token": expired_challenge["challenge_token"], "code": sent[-1][1], "method": "email",
    })
    assert expired.status_code == 400


def test_email_resend_cooldown_and_hourly_cap(client, email_mfa_setup, monkeypatch):
    sent = email_mfa_setup
    monkeypatch.setattr(settings, "EMAIL_MFA_MAX_SENDS_PER_HOUR", 2)
    email, user_id, _ = _enroll(client)
    challenge = client.post("/auth/login", json={"email": email, "password": PASSWORD}).json()
    limited = client.post("/users/me/mfa/email/resend", json={"challenge_token": challenge["challenge_token"]})
    assert limited.status_code == 429 and int(limited.headers["Retry-After"]) > 0
    with SessionLocal() as db:
        row = db.query(MFAEmailOTP).filter(MFAEmailOTP.user_id == user_id).one()
        row.created_at = datetime.utcnow() - timedelta(seconds=61)
        db.commit()
    resent = client.post("/users/me/mfa/email/resend", json={"challenge_token": challenge["challenge_token"]})
    assert resent.status_code == 200 and len(sent) == 2
    exhausted = client.post("/users/me/mfa/email/resend", json={"challenge_token": challenge["challenge_token"]})
    assert exhausted.status_code == 429
