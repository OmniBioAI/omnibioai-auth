"""PR11.5.4 (Enterprise MFA Recovery Codes + Admin Reset). Follows this
repo's established convention: real HTTP calls through real routes/
services against the shared sqlite test DB, rows/audit events read
back via a second, direct session. Each test file is self-contained
(local helpers), matching this repo's per-file duplication convention.
"""
import re
import time
import urllib.parse
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, MFADevice, MFARecoveryCode, Role, User
from app.services import mfa_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

_CODE_SHAPE = re.compile(r"^[A-Z]{4}-[A-Z]{4}-[A-Z]{4}$")


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"mfa-recovery-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _user_row(user_id: int) -> User:
    db = _DirectSession()
    try:
        return db.query(User).filter(User.id == user_id).first()
    finally:
        db.close()


def _recovery_code_rows(user_id: int) -> list[MFARecoveryCode]:
    db = _DirectSession()
    try:
        return db.query(MFARecoveryCode).filter(MFARecoveryCode.user_id == user_id).all()
    finally:
        db.close()


def _device_rows(user_id: int) -> list[MFADevice]:
    db = _DirectSession()
    try:
        return db.query(MFADevice).filter(MFADevice.user_id == user_id).all()
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
                "target_user_id": r.target_user_id, "organization_id": r.organization_id,
                "resource_type": r.resource_type, "resource_id": r.resource_id,
                "before_state": r.before_state, "after_state": r.after_state,
                "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _assert_no_secret_leakage(event: dict, *, secret: str | None = None, codes: list[str] | None = None) -> None:
    blob = str(event["before_state"]) + str(event["after_state"]) + str(event["metadata"])
    for forbidden in ("encrypted_secret", "code_hash", "otpauth://"):
        assert forbidden not in blob, f"{forbidden!r} leaked into audit event: {event}"
    if secret:
        assert secret not in blob, f"plaintext TOTP secret leaked into audit event: {event}"
    for code in codes or []:
        assert code not in blob, f"plaintext recovery code leaked into audit event: {event}"


@pytest.fixture
def configured_crypto(monkeypatch):
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _enable_mfa(client, headers) -> str:
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret


@pytest.fixture
def mfa_user(client, configured_crypto):
    user = _register_and_login(client)
    headers = _auth_header(user["access_token"])
    user["secret"] = _enable_mfa(client, headers)
    return user


def _grant_platform_admin(email: str) -> None:
    """Same technique as tests/test_pr11_identity_audit.py's fixture of
    the same name: the bootstrap "admin@omnibioai" account does NOT
    itself hold manage_all_orgs (its fixed permission set is
    config/licenses/roles/sso-override/platform.manage_content/cron/
    infra only) -- a route gated by MANAGE_ALL_ORGS needs a user
    explicitly granted the platform_admin role, then re-logged-in so
    the fresh token's permissions claim reflects it."""
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


@pytest.fixture
def platform_admin(client):
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    admin_id = _user_id(client, relogged["access_token"])
    return {**admin, "access_token": relogged["access_token"], "id": admin_id, "headers": _auth_header(relogged["access_token"])}


# ── Generation ────────────────────────────────────────────────────────────────


def test_generate_recovery_codes_returns_10_codes_in_expected_format(client, mfa_user):
    resp = client.post("/users/me/mfa/recovery-codes", headers=_auth_header(mfa_user["access_token"]))

    assert resp.status_code == 201
    codes = resp.json()["codes"]
    assert len(codes) == 10
    assert len(set(codes)) == 10  # all distinct
    for code in codes:
        assert _CODE_SHAPE.match(code), f"unexpected code shape: {code!r}"


def test_generate_recovery_codes_stores_hash_not_plaintext(client, mfa_user):
    user_id = _user_id(client, mfa_user["access_token"])
    resp = client.post("/users/me/mfa/recovery-codes", headers=_auth_header(mfa_user["access_token"]))
    codes = resp.json()["codes"]

    rows = _recovery_code_rows(user_id)
    assert len(rows) == 10
    stored_hashes = {r.code_hash for r in rows}

    for code in codes:
        assert code not in stored_hashes  # plaintext never equals its own hash
        for row_hash in stored_hashes:
            assert code not in row_hash  # and never a substring of any stored value either
        assert len(row_hash) == 64  # sha256 hex
        int(row_hash, 16)  # valid hex, raises otherwise


def test_generate_recovery_codes_twice_invalidates_first_batch(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    first = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    client.post("/users/me/mfa/recovery-codes", headers=headers)  # second call, no active batch yet to worry about

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]
    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": first[0]})

    assert resp.status_code == 400  # first batch's code A no longer valid


# ── Consumption ──────────────────────────────────────────────────────────────


def test_recovery_code_challenge_valid_code_returns_tokens(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    challenge_token = login.json()["challenge_token"]

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": codes[0]})

    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "refresh_token" in data


def test_recovery_code_reused_fails(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]

    login1 = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    first = client.post(
        "/users/me/mfa/challenge", json={"challenge_token": login1.json()["challenge_token"], "code": codes[0]}
    )
    assert first.status_code == 200

    login2 = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    second = client.post(
        "/users/me/mfa/challenge", json={"challenge_token": login2.json()["challenge_token"], "code": codes[0]}
    )
    assert second.status_code == 400


def test_recovery_code_lowercase_and_whitespace_normalized(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    variant = f"  {codes[0].lower()}  "

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    resp = client.post(
        "/users/me/mfa/challenge", json={"challenge_token": login.json()["challenge_token"], "code": variant}
    )

    assert resp.status_code == 200


def test_recovery_code_cross_user_isolation(client, mfa_user):
    other = _register_and_login(client)
    other_headers = _auth_header(other["access_token"])
    _enable_mfa(client, other_headers)

    codes = client.post("/users/me/mfa/recovery-codes", headers=_auth_header(mfa_user["access_token"])).json()["codes"]

    other_login = client.post("/auth/login", json={"email": other["email"], "password": other["password"]})
    challenge_token = other_login.json()["challenge_token"]

    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": challenge_token, "code": codes[0]})

    assert resp.status_code == 400  # token is fine, code isn't this user's own


# ── Challenge: TOTP and recovery both still work ────────────────────────────


def test_totp_still_works_after_recovery_codes_generated(client, mfa_user):
    client.post("/users/me/mfa/recovery-codes", headers=_auth_header(mfa_user["access_token"]))

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    resp = client.post("/users/me/mfa/challenge", json={"challenge_token": login.json()["challenge_token"], "code": code})

    assert resp.status_code == 200


def test_recovery_code_status_reflects_remaining_after_use(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    assert client.get("/users/me/mfa/recovery-codes", headers=headers).json() == {"remaining": 10}

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    client.post("/users/me/mfa/challenge", json={"challenge_token": login.json()["challenge_token"], "code": codes[0]})

    assert client.get("/users/me/mfa/recovery-codes", headers=headers).json() == {"remaining": 9}


def test_recovery_codes_status_never_returns_codes(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    client.post("/users/me/mfa/recovery-codes", headers=headers)

    resp = client.get("/users/me/mfa/recovery-codes", headers=headers)

    assert resp.status_code == 200
    assert set(resp.json().keys()) == {"remaining"}


# ── Regeneration ─────────────────────────────────────────────────────────────


def test_regenerate_invalidates_old_codes_and_issues_new(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    old_codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]

    resp = client.post("/users/me/mfa/recovery-codes/regenerate", headers=headers)
    assert resp.status_code == 200
    new_codes = resp.json()["codes"]
    assert len(new_codes) == 10
    assert set(new_codes).isdisjoint(old_codes)

    login1 = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    old_attempt = client.post(
        "/users/me/mfa/challenge", json={"challenge_token": login1.json()["challenge_token"], "code": old_codes[0]}
    )
    assert old_attempt.status_code == 400  # old code A now invalid

    login2 = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    new_attempt = client.post(
        "/users/me/mfa/challenge", json={"challenge_token": login2.json()["challenge_token"], "code": new_codes[0]}
    )
    assert new_attempt.status_code == 200  # new code valid


# ── Admin reset ──────────────────────────────────────────────────────────────


def test_admin_reset_requires_platform_admin(client, mfa_user):
    user_id = _user_id(client, mfa_user["access_token"])
    resp = client.post(f"/platform/users/{user_id}/mfa/reset", headers=_auth_header(mfa_user["access_token"]))
    assert resp.status_code == 403


def test_admin_reset_nonexistent_user_returns_404(client, platform_admin):
    resp = client.post("/platform/users/999999999/mfa/reset", headers=platform_admin["headers"])
    assert resp.status_code == 404


def test_admin_reset_disables_mfa_devices_and_recovery_codes(client, mfa_user, platform_admin):
    headers = _auth_header(mfa_user["access_token"])
    client.post("/users/me/mfa/recovery-codes", headers=headers)
    user_id = _user_id(client, mfa_user["access_token"])

    resp = client.post(f"/platform/users/{user_id}/mfa/reset", headers=platform_admin["headers"])

    assert resp.status_code == 200
    data = resp.json()
    assert data == {"user_id": user_id, "mfa_enabled": False, "mfa_status": "disabled"}

    row = _user_row(user_id)
    assert row.mfa_enabled is False
    assert row.mfa_status == "disabled"
    assert row.mfa_primary_method is None
    assert row.mfa_enabled_at is None
    assert row.mfa_last_verified_at is None
    # Explicitly preserved -- never touched by reset.
    assert row.status == "active"

    devices = _device_rows(user_id)
    assert devices and all(d.disabled_at is not None for d in devices)

    codes = _recovery_code_rows(user_id)
    assert codes and all(c.used_at is not None for c in codes)


def test_admin_reset_invalidates_stale_challenge_totp_and_recovery(client, mfa_user, platform_admin):
    """After reset: TOTP invalid, recovery codes invalid, MFA disabled --
    exercised end-to-end via a challenge_token issued *before* the
    reset (the realistic "user mid-login when an admin resets them"
    scenario)."""
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    user_id = _user_id(client, mfa_user["access_token"])

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    stale_challenge = login.json()["challenge_token"]

    client.post(f"/platform/users/{user_id}/mfa/reset", headers=platform_admin["headers"])

    totp_code = mfa_service._totp_code_at(mfa_user["secret"], int(time.time()))
    totp_resp = client.post("/users/me/mfa/challenge", json={"challenge_token": stale_challenge, "code": totp_code})
    assert totp_resp.status_code == 401  # mfa_enabled now False -- rejected before even checking the code

    recovery_resp = client.post("/users/me/mfa/challenge", json={"challenge_token": stale_challenge, "code": codes[0]})
    assert recovery_resp.status_code == 401

    # A fresh login for this user no longer challenges at all -- MFA is off.
    fresh_login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    assert fresh_login.json().get("mfa_required") is not True
    assert "access_token" in fresh_login.json()


# ── Audit ────────────────────────────────────────────────────────────────────


def test_recovery_codes_generated_audit_event_without_secret_leakage(client, mfa_user):
    user_id = _user_id(client, mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=_auth_header(mfa_user["access_token"])).json()["codes"]

    events = _events(event_type="mfa_recovery_codes_generated", actor_user_id=user_id)

    assert len(events) == 1
    assert events[0]["metadata"]["codes_issued"] == 10
    _assert_no_secret_leakage(events[0], codes=codes)


def test_recovery_codes_regenerated_audit_event(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    user_id = _user_id(client, mfa_user["access_token"])
    old_codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    new_codes = client.post("/users/me/mfa/recovery-codes/regenerate", headers=headers).json()["codes"]

    generated = _events(event_type="mfa_recovery_codes_generated", actor_user_id=user_id)
    regenerated = _events(event_type="mfa_recovery_codes_regenerated", actor_user_id=user_id)

    assert len(generated) == 1  # only the first call
    assert len(regenerated) == 1
    assert regenerated[0]["metadata"]["codes_issued"] == 10
    assert regenerated[0]["metadata"]["codes_invalidated"] == 10
    _assert_no_secret_leakage(regenerated[0], codes=old_codes + new_codes)


def test_recovery_code_used_audit_event_without_secret_leakage(client, mfa_user):
    headers = _auth_header(mfa_user["access_token"])
    codes = client.post("/users/me/mfa/recovery-codes", headers=headers).json()["codes"]
    user_id = _user_id(client, mfa_user["access_token"])

    login = client.post("/auth/login", json={"email": mfa_user["email"], "password": mfa_user["password"]})
    client.post("/users/me/mfa/challenge", json={"challenge_token": login.json()["challenge_token"], "code": codes[0]})

    events = _events(event_type="mfa_recovery_code_used", actor_user_id=user_id)

    assert len(events) == 1
    assert events[0]["target_user_id"] == user_id
    assert events[0]["metadata"]["authentication_method"] == "password"
    _assert_no_secret_leakage(events[0], secret=mfa_user["secret"], codes=codes)


def test_admin_reset_audit_event_actor_target_attribution(client, mfa_user, platform_admin):
    user_id = _user_id(client, mfa_user["access_token"])
    admin_id = platform_admin["id"]

    client.post(f"/platform/users/{user_id}/mfa/reset", headers=platform_admin["headers"])

    events = _events(event_type="mfa_reset_by_admin", target_user_id=user_id)

    assert len(events) == 1
    assert events[0]["actor_user_id"] == admin_id
    assert events[0]["target_user_id"] == user_id
    assert events[0]["actor_user_id"] != events[0]["target_user_id"]
    assert events[0]["after_state"] == {"mfa_enabled": False, "mfa_status": "disabled"}
    _assert_no_secret_leakage(events[0], secret=mfa_user["secret"])
