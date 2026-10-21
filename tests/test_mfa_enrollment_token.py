"""Tests for the one-time pre-authentication TOTP enrollment capability."""
import time
import urllib.parse
import uuid
from datetime import datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_mfa_enrollment_token, decode_token
from app.db.models import MFAEnrollmentSession
from app.services import mfa_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_user(client):
    email = f"mfa-enrollment-token-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return email, password, login.json()["access_token"]


def _require_mfa_policy(client, access_token, email):
    headers = _auth_header(access_token)
    org = client.post(
        "/orgs",
        json={"name": "MFA Enrollment Token Test", "slug": f"mfa-enroll-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    )
    assert org.status_code == 201
    policy = client.post(f"/orgs/{org.json()['id']}/mfa-policy", json={"required": True}, headers=headers)
    assert policy.status_code == 201
    response = client.post("/auth/login", json={"email": email, "password": "TestPassword123!"})
    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "mfa_enrollment_required"
    return response.json()["detail"]["enrollment_token"]


@pytest.fixture
def configured_crypto(monkeypatch):
    import app.core.crypto as crypto

    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))


def _secret_from_uri(uri):
    return urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)["secret"][0]


def test_enrollment_token_only_enrolls_once_then_normal_login_challenges(client, configured_crypto):
    email, password, access_token = _register_user(client)
    enrollment_token = _require_mfa_policy(client, access_token, email)
    claims = decode_token(enrollment_token)
    assert claims["type"] == "mfa_enrollment"
    assert claims["purpose"] == "totp_enrollment"
    assert "sub" not in claims
    assert 590 <= claims["exp"] - int(time.time()) <= 600

    headers = _auth_header(enrollment_token)
    enrolled = client.post("/users/me/mfa/totp/enroll", headers=headers)
    assert enrolled.status_code == 201
    secret = _secret_from_uri(enrolled.json()["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verified = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enrolled.json()["device_id"], "code": code},
        headers=headers,
    )
    assert verified.status_code == 200

    # The same scoped capability cannot create or verify another enrollment.
    assert client.post("/users/me/mfa/totp/enroll", headers=headers).status_code == 401
    assert client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enrolled.json()["device_id"], "code": code},
        headers=headers,
    ).status_code == 401

    # Enrollment issues no session; the next password login follows the
    # ordinary enrolled-user MFA challenge path.
    challenge = client.post("/auth/login", json={"email": email, "password": password})
    assert challenge.status_code == 200
    assert challenge.json()["mfa_required"] is True
    assert "access_token" not in challenge.json()


def test_enrollment_token_is_rejected_by_other_identity_and_mfa_apis(client):
    email, _, access_token = _register_user(client)
    enrollment_token = _require_mfa_policy(client, access_token, email)
    headers = _auth_header(enrollment_token)

    assert client.get("/orgs", headers=headers).status_code == 401
    assert client.get("/users/me/mfa/devices", headers=headers).status_code == 401
    assert client.post("/auth/validate", json={"token": enrollment_token}).json() == {"valid": False}


def test_expired_enrollment_token_is_rejected(client):
    email, _, access_token = _register_user(client)
    user_id = decode_token(access_token)["sub"]
    token_jti = str(uuid.uuid4())
    expired_at = datetime.utcnow() - timedelta(seconds=1)
    db = _DirectSession()
    try:
        db.add(MFAEnrollmentSession(
            user_id=int(user_id), token_jti=token_jti,
            created_at=expired_at - timedelta(minutes=10), expires_at=expired_at,
        ))
        db.commit()
    finally:
        db.close()

    expired_token = create_mfa_enrollment_token(int(user_id), token_jti, expired_at)
    response = client.post("/users/me/mfa/totp/enroll", headers=_auth_header(expired_token))
    assert response.status_code == 401
