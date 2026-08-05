"""PR11.5.2 (Enterprise TOTP MFA Enrollment). Follows
tests/test_pr11_identity_audit.py's / tests/test_apikeys.py's own
established convention: real HTTP calls through real routes/services
against the shared sqlite test DB, rows/audit events read back via a
second, direct session -- never mocks of mfa_service/audit_service
themselves. Each test file is self-contained (its own local
`configured_crypto`/`_register_and_login`/`_events` helpers), matching
this repo's existing per-file duplication convention rather than a
shared conftest fixture.
"""
import time
import urllib.parse
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, MFADevice, User
from app.services import mfa_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"mfa-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _device_row(device_id: int) -> MFADevice | None:
    db = _DirectSession()
    try:
        return db.query(MFADevice).filter(MFADevice.id == device_id).first()
    finally:
        db.close()


def _user_row(user_id: int) -> User:
    db = _DirectSession()
    try:
        return db.query(User).filter(User.id == user_id).first()
    finally:
        db.close()


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
                "target_user_id": r.target_user_id, "resource_type": r.resource_type,
                "resource_id": r.resource_id, "before_state": r.before_state,
                "after_state": r.after_state, "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _assert_no_secret_leakage(event: dict, *, secret: str | None = None, code: str | None = None) -> None:
    blob = str(event["before_state"]) + str(event["after_state"]) + str(event["metadata"])
    for forbidden in ("encrypted_secret", "otpauth://"):
        assert forbidden not in blob, f"{forbidden!r} leaked into audit event: {event}"
    if secret:
        assert secret not in blob, f"plaintext TOTP secret leaked into audit event: {event}"
    if code:
        assert code not in blob, f"OTP code leaked into audit event: {event}"


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_config.py's/tests/test_org_sso.py's
    fixture of the same name: conftest.py never sets
    CONFIG_ENCRYPTION_KEY, and app.core.crypto's Fernet instance is
    computed once at import time, so patch the already-imported
    module's singleton directly rather than the env var."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


@pytest.fixture
def user(client, configured_crypto):
    return _register_and_login(client)


# ── RFC 6238 primitives (pure functions, no HTTP/DB) ────────────────────────


def test_verify_totp_code_accepts_current_previous_and_next_step():
    secret = mfa_service.generate_totp_secret()
    now = (int(time.time()) // 30) * 30 + 15  # mid-step, so +-1 arithmetic below is unambiguous
    current_code = mfa_service._totp_code_at(secret, now)
    prev_code = mfa_service._totp_code_at(secret, now - 30)
    next_code = mfa_service._totp_code_at(secret, now + 30)

    assert mfa_service.verify_totp_code(secret, current_code, for_time=now)
    assert mfa_service.verify_totp_code(secret, prev_code, for_time=now)
    assert mfa_service.verify_totp_code(secret, next_code, for_time=now)


def test_verify_totp_code_rejects_code_outside_window():
    secret = mfa_service.generate_totp_secret()
    now = (int(time.time()) // 30) * 30 + 15
    far_code = mfa_service._totp_code_at(secret, now - 90)

    assert not mfa_service.verify_totp_code(secret, far_code, for_time=now)


def test_verify_totp_code_rejects_malformed_input():
    secret = mfa_service.generate_totp_secret()

    assert not mfa_service.verify_totp_code(secret, "abcdef")
    assert not mfa_service.verify_totp_code(secret, "12345")
    assert not mfa_service.verify_totp_code(secret, "")
    assert not mfa_service.verify_totp_code(secret, None)


def test_generate_provisioning_uri_shape():
    secret = mfa_service.generate_totp_secret()
    uri = mfa_service.generate_provisioning_uri(secret, "person@example.com")

    assert uri.startswith("otpauth://totp/OmniBioAI%3Aperson%40example.com?")
    assert f"secret={secret}" in uri
    assert "issuer=OmniBioAI" in uri
    assert "algorithm=SHA1" in uri
    assert "digits=6" in uri
    assert "period=30" in uri


# ── Enrollment (POST /users/me/mfa/totp/enroll) ─────────────────────────────


def test_start_totp_enrollment_creates_pending_device_and_does_not_return_secret(client, user):
    resp = client.post("/users/me/mfa/totp/enroll", headers=_auth_header(user["access_token"]))

    assert resp.status_code == 201
    data = resp.json()
    assert set(data.keys()) == {"device_id", "otpauth_uri"}
    assert data["otpauth_uri"].startswith("otpauth://totp/")

    device = _device_row(data["device_id"])
    assert device is not None
    assert device.device_type == "totp"
    assert device.verified_at is None
    assert device.disabled_at is None
    assert device.encrypted_secret  # stored, but must not equal the plaintext
    secret = _extract_secret(data["otpauth_uri"])
    assert secret not in device.encrypted_secret


def test_start_totp_enrollment_fails_loudly_when_encryption_key_unset(client):
    # Deliberately no `configured_crypto` fixture here -- exercises the
    # real "CONFIG_ENCRYPTION_KEY not set" state conftest.py leaves in
    # place by default, same as test_config.py's own equivalent test.
    u = _register_and_login(client)

    resp = client.post("/users/me/mfa/totp/enroll", headers=_auth_header(u["access_token"]))

    assert resp.status_code == 500


def test_start_totp_enrollment_replaces_existing_pending_device(client, user):
    headers = _auth_header(user["access_token"])
    first = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    second = client.post("/users/me/mfa/totp/enroll", headers=headers).json()

    assert first["device_id"] != second["device_id"]
    assert _device_row(first["device_id"]).disabled_at is not None
    assert _device_row(second["device_id"]).disabled_at is None


# ── Verification (POST /users/me/mfa/totp/verify) ───────────────────────────


def test_verify_totp_enrollment_with_valid_code_activates_device_and_updates_user(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))

    resp = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enroll["device_id"], "code": code},
        headers=headers,
    )

    assert resp.status_code == 200
    data = resp.json()
    assert data["id"] == enroll["device_id"]
    assert data["verified_at"] is not None
    assert "encrypted_secret" not in data

    row = _user_row(_user_id(client, user["access_token"]))
    assert row.mfa_enabled is True
    assert row.mfa_status == "enabled"
    assert row.mfa_primary_method == "totp"
    assert row.mfa_enabled_at is not None
    assert row.mfa_last_verified_at is not None


def test_verify_totp_enrollment_with_invalid_code_rejected(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    correct = mfa_service._totp_code_at(secret, int(time.time()))
    wrong = ("1" if correct[0] != "1" else "2") + correct[1:]  # deterministically wrong, still 6 digits

    resp = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enroll["device_id"], "code": wrong},
        headers=headers,
    )

    assert resp.status_code == 400
    assert _device_row(enroll["device_id"]).verified_at is None
    assert _user_row(_user_id(client, user["access_token"])).mfa_enabled is False


def test_verify_totp_enrollment_nonexistent_device_returns_404(client, user):
    resp = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": 999999999, "code": "123456"},
        headers=_auth_header(user["access_token"]),
    )

    assert resp.status_code == 404


def test_verify_totp_enrollment_rejects_another_users_device(client, user):
    other = _register_and_login(client)
    enroll = client.post("/users/me/mfa/totp/enroll", headers=_auth_header(user["access_token"])).json()

    resp = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enroll["device_id"], "code": "123456"},
        headers=_auth_header(other["access_token"]),
    )

    assert resp.status_code == 404
    # Untouched by the other user's failed attempt.
    assert _device_row(enroll["device_id"]).verified_at is None


def test_verify_totp_enrollment_rejects_already_verified_device(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    client.post("/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers)

    resp = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enroll["device_id"], "code": code},
        headers=headers,
    )

    assert resp.status_code == 400


# ── Device management ────────────────────────────────────────────────────────


def test_list_mfa_devices_hides_secret_fields(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()

    resp = client.get("/users/me/mfa/devices", headers=headers)

    assert resp.status_code == 200
    devices = resp.json()
    assert len(devices) == 1
    assert devices[0]["id"] == enroll["device_id"]
    assert devices[0]["device_type"] == "totp"
    assert devices[0]["verified_at"] is None
    assert set(devices[0].keys()) == {"id", "device_type", "label", "created_at", "verified_at", "last_used_at"}


def test_list_mfa_devices_only_shows_callers_own_devices(client, user):
    other = _register_and_login(client)
    client.post("/users/me/mfa/totp/enroll", headers=_auth_header(other["access_token"]))

    resp = client.get("/users/me/mfa/devices", headers=_auth_header(user["access_token"]))

    assert resp.status_code == 200
    assert resp.json() == []


def test_remove_mfa_device_disables_mfa_when_last_verified_device_removed(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    client.post("/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers)

    resp = client.delete(f"/users/me/mfa/devices/{enroll['device_id']}", headers=headers)

    assert resp.status_code == 204
    assert _device_row(enroll["device_id"]).disabled_at is not None

    row = _user_row(_user_id(client, user["access_token"]))
    assert row.mfa_enabled is False
    assert row.mfa_status == "disabled"
    assert client.get("/users/me/mfa/devices", headers=headers).json() == []


def test_remove_mfa_device_rejects_another_users_device(client, user):
    other = _register_and_login(client)
    enroll = client.post("/users/me/mfa/totp/enroll", headers=_auth_header(user["access_token"])).json()

    resp = client.delete(
        f"/users/me/mfa/devices/{enroll['device_id']}",
        headers=_auth_header(other["access_token"]),
    )

    assert resp.status_code == 404
    assert _device_row(enroll["device_id"]).disabled_at is None


def test_remove_mfa_device_nonexistent_returns_404(client, user):
    resp = client.delete("/users/me/mfa/devices/999999999", headers=_auth_header(user["access_token"]))

    assert resp.status_code == 404


# ── Audit trail ──────────────────────────────────────────────────────────────


def test_enrollment_start_emits_audit_event_without_secret(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    user_id = _user_id(client, user["access_token"])

    events = _events(event_type="mfa_device_enrollment_started", actor_user_id=user_id)

    assert len(events) == 1
    assert events[0]["resource_id"] == str(enroll["device_id"])
    assert events[0]["metadata"]["device_type"] == "totp"
    _assert_no_secret_leakage(events[0], secret=secret)


def test_verify_emits_device_added_and_mfa_enabled_events_without_secret_or_code(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    client.post("/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers)
    user_id = _user_id(client, user["access_token"])

    added = _events(event_type="mfa_device_added", actor_user_id=user_id)
    assert len(added) == 1
    _assert_no_secret_leakage(added[0], secret=secret, code=code)

    enabled = _events(event_type="mfa_enabled", actor_user_id=user_id)
    assert len(enabled) == 1
    assert enabled[0]["after_state"]["mfa_enabled"] is True
    _assert_no_secret_leakage(enabled[0], secret=secret, code=code)


def test_verifying_second_device_does_not_re_emit_mfa_enabled(client, user):
    headers = _auth_header(user["access_token"])

    def _enroll_and_verify():
        enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
        secret = _extract_secret(enroll["otpauth_uri"])
        code = mfa_service._totp_code_at(secret, int(time.time()))
        resp = client.post(
            "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
        )
        assert resp.status_code == 200

    _enroll_and_verify()
    # The first device is now *verified*, not pending -- start_totp_enrollment
    # only disables pending devices, so this is a genuine second device, not
    # a replacement (see docs/pr11-totp-enrollment-discovery.md SS4).
    _enroll_and_verify()

    user_id = _user_id(client, user["access_token"])
    assert len(_events(event_type="mfa_device_added", actor_user_id=user_id)) == 2
    assert len(_events(event_type="mfa_enabled", actor_user_id=user_id)) == 1  # not re-logged


def test_remove_last_verified_device_emits_removed_and_disabled_events(client, user):
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    client.post("/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers)
    client.delete(f"/users/me/mfa/devices/{enroll['device_id']}", headers=headers)
    user_id = _user_id(client, user["access_token"])

    removed = _events(event_type="mfa_device_removed", actor_user_id=user_id)
    assert len(removed) == 1
    _assert_no_secret_leakage(removed[0], secret=secret)

    disabled = _events(event_type="mfa_disabled", actor_user_id=user_id)
    assert len(disabled) == 1
    assert disabled[0]["after_state"]["mfa_enabled"] is False


def test_remove_pending_unverified_device_does_not_emit_mfa_disabled(client, user):
    """Never-verified devices never flipped mfa_enabled on in the first
    place -- removing one must not fire a "disabled" event for a state
    change that never happened (the same no-op-avoidance convention
    org_sso_service.set_enforced already uses)."""
    headers = _auth_header(user["access_token"])
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    client.delete(f"/users/me/mfa/devices/{enroll['device_id']}", headers=headers)
    user_id = _user_id(client, user["access_token"])

    assert _events(event_type="mfa_disabled", actor_user_id=user_id) == []
    assert len(_events(event_type="mfa_device_removed", actor_user_id=user_id)) == 1
