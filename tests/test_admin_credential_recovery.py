"""Isolated HTTP and service tests for signed local Admin recovery."""
import base64
import concurrent.futures
import json
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.fernet import Fernet

from app.core import recovery_approval
from app.core.recovery_approval import RecoveryApproval, load_signed_recovery_approval
from app.core.security import password_verifier_scheme, pwd_context
from app.db.models import AuditEvent, Role, User, UserSession
from app.db.session import SessionLocal
from app.services import audit_service
from app.services.audit_service import AuditEventType
from app.services.credential_recovery_service import CredentialRecoveryError, recover_admin_mfa, recover_admin_password


SYNTHETIC_OLD_PASSWORD = "Synthetic-Old-Password-Never-Used-Outside-Test"
SYNTHETIC_NEW_PASSWORD = "Cobalt-river-fern-lantern-2026-unique"
OPERATOR_LOGIN = "isolated-test-operator"


def _register(client, label):
    email = f"recovery-{label}-{uuid.uuid4().hex[:8]}@omnibioai.test"
    response = client.post("/auth/register", json={"email": email, "password": SYNTHETIC_OLD_PASSWORD})
    assert response.status_code == 200
    return email


def _grant_role(email, role_name):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        role = db.query(Role).filter(Role.name == role_name, Role.organization_id.is_(None)).first()
        if role is None:
            role = Role(name=role_name, organization_id=None, permissions=[])
            db.add(role)
            db.flush()
        if role not in user.roles:
            user.roles.append(role)
        db.commit()
        return user.id
    finally:
        db.close()


def _identity_pair(client, label="case"):
    target_email = _register(client, f"target-{label}")
    approver_email = _register(client, f"owner-{label}")
    target_id = _grant_role(target_email, "admin")
    approver_id = _grant_role(approver_email, "platform_admin")
    _grant_role(approver_email, "admin")
    return target_id, target_email, approver_id


def _approval_file(tmp_path, monkeypatch, *, target_id, target_email, approver_id,
                   operator_login=OPERATOR_LOGIN, allow_mfa_reset=False,
                   overrides=None, invalid_signature=False):
    private_key = Ed25519PrivateKey.generate()
    public_path = tmp_path / "trusted-owner-public-key.pem"
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    public_path.chmod(0o444)
    monkeypatch.setattr(recovery_approval, "APPROVAL_PUBLIC_KEY_PATH", str(public_path))
    issued = datetime.now(timezone.utc)
    payload = {
        "version": 1,
        "approval_id": str(uuid.uuid4()),
        "action": "admin_credential_recovery",
        "target_user_id": target_id,
        "target_email": target_email,
        "expected_credential_state": "disabled_or_unsupported",
        "operator_login": operator_login,
        "approver_user_id": approver_id,
        "ticket_id": f"TEST-{uuid.uuid4().hex[:10]}",
        "identity_verification_ref": f"TEST-VERIFY-{uuid.uuid4().hex[:10]}",
        "allow_mfa_reset": allow_mfa_reset,
        "issued_at": issued.isoformat(),
        "expires_at": (issued + timedelta(minutes=10)).isoformat(),
    }
    if overrides:
        payload.update(overrides)
    signed = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    signature = private_key.sign(signed)
    if invalid_signature:
        signature = b"x" * len(signature)
    approval_path = tmp_path / "approval.json"
    approval_path.write_text(json.dumps({**payload, "signature": base64.b64encode(signature).decode()}))
    approval_path.chmod(0o600)
    return approval_path


def _load_approval(path):
    return load_signed_recovery_approval(path)


def _disable_password(email):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        user.hashed_password = "!synthetic-disabled-verifier"
        db.commit()
    finally:
        db.close()


def _recover(target_id, approval, password=SYNTHETIC_NEW_PASSWORD, confirmation=None):
    db = SessionLocal()
    try:
        confirmation = confirmation or f"RECOVER {approval.target_user_id} {approval.target_email} {approval.ticket_id}"
        return recover_admin_password(
            db,
            target_user_id=target_id,
            operator_login=OPERATOR_LOGIN,
            confirmation=confirmation,
            password=password,
            approval=approval,
        )
    finally:
        db.close()


def test_disabled_verifier_login_is_generic_json_401(client, caplog):
    email = _register(client, "disabled-http")
    _disable_password(email)
    response = client.post("/auth/login", json={"email": email, "password": SYNTHETIC_OLD_PASSWORD})
    unknown = client.post("/auth/login", json={"email": "not-present@omnibioai.test", "password": SYNTHETIC_OLD_PASSWORD})
    assert response.status_code == 401
    assert response.headers["content-type"].startswith("application/json")
    assert response.json() == unknown.json() == {"detail": "Invalid credentials"}
    assert "access_token" not in response.json()
    assert "UnknownHashError" not in response.text
    assert SYNTHETIC_OLD_PASSWORD not in caplog.text
    oversized = client.post("/auth/login", json={"email": email, "password": "X" * 5000})
    assert oversized.status_code in {401, 429}
    assert oversized.headers["content-type"].startswith("application/json")


@pytest.mark.parametrize("scheme", ["bcrypt", "bcrypt_sha256"])
def test_existing_supported_password_schemes_still_login(client, scheme):
    email = _register(client, f"scheme-{scheme}")
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).one()
        user.hashed_password = pwd_context.hash(SYNTHETIC_OLD_PASSWORD, scheme=scheme)
        db.commit()
    finally:
        db.close()
    response = client.post("/auth/login", json={"email": email, "password": SYNTHETIC_OLD_PASSWORD})
    assert response.status_code == 200
    assert "access_token" in response.json()


def test_signed_recovery_preserves_identity_revokes_session_and_allows_new_login(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "success")
    login = client.post("/auth/login", json={"email": target_email, "password": SYNTHETIC_OLD_PASSWORD}).json()
    _disable_password(target_email)
    approval_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email, approver_id=approver_id,
    )
    approval = _load_approval(approval_path)

    before = SessionLocal()
    try:
        target = before.query(User).filter(User.id == target_id).one()
        original_roles = sorted((role.id, role.name, role.organization_id) for role in target.roles)
    finally:
        before.close()

    result = _recover(target_id, approval)
    assert result["user_id"] == target_id
    assert result["sessions_revoked"] >= 1
    assert result["mfa_reset"] is False

    after = SessionLocal()
    try:
        target = after.query(User).filter(User.id == target_id).one()
        assert target.email == target_email
        assert target.status == "active"
        assert password_verifier_scheme(target.hashed_password) == "bcrypt_sha256"
        assert sorted((role.id, role.name, role.organization_id) for role in target.roles) == original_roles
        session = after.query(UserSession).filter(UserSession.user_id == target_id).one()
        assert session.status == "revoked"
        assert session.revoked_reason == "credential_recovery"
        event = after.query(AuditEvent).filter(
            AuditEvent.event_type == AuditEventType.CREDENTIAL_RECOVERY_COMPLETED,
            AuditEvent.resource_id == approval.approval_id,
        ).one()
        assert event.target_user_id == target_id
        assert event.event_metadata["ticket_id"] == approval.ticket_id
        assert "password" not in json.dumps(event.event_metadata).lower()
        assert SYNTHETIC_NEW_PASSWORD not in json.dumps({
            "before": event.before_state,
            "after": event.after_state,
            "metadata": event.event_metadata,
        })
    finally:
        after.close()

    refresh_response = client.post("/auth/refresh", json={"refresh_token": login["refresh_token"]})
    assert refresh_response.status_code == 401
    new_login = client.post("/auth/login", json={"email": target_email, "password": SYNTHETIC_NEW_PASSWORD})
    wrong_login = client.post("/auth/login", json={"email": target_email, "password": SYNTHETIC_OLD_PASSWORD})
    assert new_login.status_code == 200
    assert wrong_login.status_code == 401


def test_invalid_signature_wrong_target_and_enabled_credential_are_rejected(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "denial")
    _disable_password(target_email)
    invalid_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id, invalid_signature=True,
    )
    with pytest.raises(recovery_approval.RecoveryApprovalError):
        _load_approval(invalid_path)

    expired_at = datetime.now(timezone.utc)
    expired_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
        overrides={
            "issued_at": (expired_at - timedelta(minutes=40)).isoformat(),
            "expires_at": (expired_at - timedelta(minutes=10)).isoformat(),
        },
    )
    with pytest.raises(recovery_approval.RecoveryApprovalError):
        _load_approval(expired_path)

    valid_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    approval = _load_approval(valid_path)
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id + 1000, approval)

    # Restore a supported verifier and prove recovery refuses to overwrite it.
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == target_id).one()
        user.hashed_password = pwd_context.hash(SYNTHETIC_OLD_PASSWORD)
        db.commit()
    finally:
        db.close()
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id, approval)


def test_wrong_identity_and_confirmation_do_not_mutate(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "identity")
    _disable_password(target_email)
    path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    approval = _load_approval(path)
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id, approval, confirmation="RECOVER 1 other@omnibioai TEST")
    wrong_email_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id, overrides={"target_email": "different@omnibioai.test"},
    )
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id, _load_approval(wrong_email_path))
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == target_id).one()
        assert password_verifier_scheme(user.hashed_password) is None
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.CREDENTIAL_RECOVERY_COMPLETED,
            resource_id=approval.approval_id,
        ).count() == 0
    finally:
        db.close()


def test_audit_failure_rolls_back_password_and_session_revocations(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "audit-fail")
    client.post("/auth/login", json={"email": target_email, "password": SYNTHETIC_OLD_PASSWORD})
    _disable_password(target_email)
    path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    approval = _load_approval(path)
    real_log_event = audit_service.log_event

    def fail_recovery_event(db, event_type, *args, **kwargs):
        if event_type == AuditEventType.CREDENTIAL_RECOVERY_COMPLETED:
            raise RuntimeError("synthetic audit store failure")
        return real_log_event(db, event_type, *args, **kwargs)

    monkeypatch.setattr(audit_service, "log_event", fail_recovery_event)
    with pytest.raises(RuntimeError):
        _recover(target_id, approval)
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.id == target_id).one()
        session = db.query(UserSession).filter(UserSession.user_id == target_id).one()
        assert password_verifier_scheme(user.hashed_password) is None
        assert session.status == "active"
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.CREDENTIAL_RECOVERY_COMPLETED,
            resource_id=approval.approval_id,
        ).count() == 0
    finally:
        db.close()


def test_mfa_remains_enforced_after_recovery_without_reset_approval(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "mfa")
    login_before = client.post("/auth/login", json={"email": target_email, "password": SYNTHETIC_OLD_PASSWORD}).json()
    import app.core.crypto as crypto
    from app.services import mfa_service
    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    enroll = client.post(
        "/users/me/mfa/totp/enroll",
        headers={"Authorization": f"Bearer {login_before['access_token']}"},
    )
    assert enroll.status_code == 201
    import urllib.parse
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(enroll.json()["otpauth_uri"]).query)["secret"][0]
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verified = client.post(
        "/users/me/mfa/totp/verify",
        json={"device_id": enroll.json()["device_id"], "code": code},
        headers={"Authorization": f"Bearer {login_before['access_token']}"},
    )
    assert verified.status_code == 200
    _disable_password(target_email)

    approval_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id, allow_mfa_reset=False,
    )
    approval = _load_approval(approval_path)
    result = _recover(target_id, approval)
    assert result["mfa_reset"] is False
    challenge = client.post("/auth/login", json={"email": target_email, "password": SYNTHETIC_NEW_PASSWORD})
    assert challenge.status_code == 200
    assert challenge.json()["mfa_required"] is True
    assert "access_token" not in challenge.json()
    totp = mfa_service._totp_code_at(secret, int(time.time()))
    completed = client.post(
        "/users/me/mfa/challenge",
        json={"challenge_token": challenge.json()["challenge_token"], "code": totp},
    )
    assert completed.status_code == 200
    assert "access_token" in completed.json()
    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == target_id).one()
        assert target.mfa_enabled is True
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.MFA_RESET_BY_ADMIN,
            target_user_id=target_id,
        ).count() == 0
    finally:
        db.close()


def test_mfa_reset_requires_explicit_platform_owner_approval(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "mfa-reset")
    _disable_password(target_email)
    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == target_id).one()
        target.mfa_enabled = True
        target.mfa_status = "enabled"
        target.mfa_primary_method = "totp"
        db.commit()
    finally:
        db.close()

    reset_path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id, allow_mfa_reset=True,
    )
    reset_approval = _load_approval(reset_path)
    result = _recover(target_id, reset_approval)
    assert result["mfa_reset"] is True
    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == target_id).one()
        assert target.mfa_enabled is False
        assert target.mfa_status == "disabled"
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.MFA_RESET_BY_ADMIN,
            target_user_id=target_id,
        ).count() == 1
    finally:
        db.close()


def test_unknown_authenticator_replacement_uses_separate_signed_mfa_only_approval(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "mfa-only")
    original_login = client.post(
        "/auth/login", json={"email": target_email, "password": SYNTHETIC_OLD_PASSWORD},
    )
    assert original_login.status_code == 200
    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == target_id).one()
        original_password_hash = target.hashed_password
        original_roles = sorted((role.id, role.name) for role in target.roles)
        target.mfa_enabled = True
        target.mfa_status = "enabled"
        target.mfa_primary_method = "totp"
        db.commit()
    finally:
        db.close()

    now = datetime.now(timezone.utc)
    approval = RecoveryApproval(
        approval_id=str(uuid.uuid4()),
        action="admin_mfa_recovery",
        target_user_id=target_id,
        target_email=target_email,
        expected_credential_state="unknown_authenticator_enrollment",
        operator_login=OPERATOR_LOGIN,
        approver_user_id=approver_id,
        ticket_id=f"TEST-{uuid.uuid4().hex[:10]}",
        identity_verification_ref=f"TEST-VERIFY-{uuid.uuid4().hex[:10]}",
        allow_mfa_reset=True,
        issued_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    confirmation = f"RECOVER-MFA {target_id} {target_email} {approval.ticket_id}"
    db = SessionLocal()
    try:
        result = recover_admin_mfa(
            db,
            target_user_id=target_id,
            operator_login=OPERATOR_LOGIN,
            confirmation=confirmation,
            approval=approval,
        )
    finally:
        db.close()
    assert result["mfa_reset"] is True

    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == target_id).one()
        assert target.hashed_password == original_password_hash
        assert sorted((role.id, role.name) for role in target.roles) == original_roles
        assert target.mfa_enabled is False and target.mfa_status == "disabled"
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.MFA_RECOVERY_COMPLETED,
            target_user_id=target_id,
        ).count() == 1
    finally:
        db.close()

    # The distinct action cannot be replayed through password recovery or MFA recovery.
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id, approval)
    db = SessionLocal()
    try:
        with pytest.raises(CredentialRecoveryError):
            recover_admin_mfa(
                db,
                target_user_id=target_id,
                operator_login=OPERATOR_LOGIN,
                confirmation=confirmation,
                approval=approval,
            )
    finally:
        db.close()


def test_approval_can_only_be_used_once(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "replay")
    _disable_password(target_email)
    path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    approval = _load_approval(path)
    _recover(target_id, approval)
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id, approval)


def test_password_policy_rejects_weak_candidate_without_mutation(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "weak-password")
    _disable_password(target_email)
    path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    approval = _load_approval(path)
    with pytest.raises(CredentialRecoveryError, match="security requirements"):
        _recover(target_id, approval, password="password")
    db = SessionLocal()
    try:
        target = db.query(User).filter(User.id == target_id).one()
        assert password_verifier_scheme(target.hashed_password) is None
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.CREDENTIAL_RECOVERY_COMPLETED,
            resource_id=approval.approval_id,
        ).count() == 0
    finally:
        db.close()


def test_recovery_requires_active_platform_owner_approval(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "unauthorized")
    _disable_password(target_email)
    db = SessionLocal()
    try:
        owner = db.query(User).filter(User.id == approver_id).one()
        owner.roles = [role for role in owner.roles if role.name != "platform_admin"]
        db.commit()
    finally:
        db.close()
    path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    with pytest.raises(CredentialRecoveryError):
        _recover(target_id, _load_approval(path))
    db = SessionLocal()
    try:
        assert password_verifier_scheme(db.query(User).filter(User.id == target_id).one().hashed_password) is None
    finally:
        db.close()


def test_concurrent_recovery_with_same_approval_commits_at_most_once(client, tmp_path, monkeypatch):
    target_id, target_email, approver_id = _identity_pair(client, "concurrent")
    _disable_password(target_email)
    path = _approval_file(
        tmp_path, monkeypatch, target_id=target_id, target_email=target_email,
        approver_id=approver_id,
    )
    approvals = [_load_approval(path)]
    second_path = tmp_path / "second-approval.json"
    private_key = Ed25519PrivateKey.generate()
    public_path = tmp_path / "trusted-owner-public-key.pem"
    public_path.write_bytes(private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    public_path.chmod(0o444)
    payload = {
        "version": 1,
        "approval_id": str(uuid.uuid4()),
        "action": "admin_credential_recovery",
        "target_user_id": target_id,
        "target_email": target_email,
        "expected_credential_state": "disabled_or_unsupported",
        "operator_login": OPERATOR_LOGIN,
        "approver_user_id": approver_id,
        "ticket_id": f"TEST-{uuid.uuid4().hex[:10]}",
        "identity_verification_ref": f"TEST-VERIFY-{uuid.uuid4().hex[:10]}",
        "allow_mfa_reset": False,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
    }
    signed = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    second_path.write_text(json.dumps({
        **payload,
        "signature": base64.b64encode(private_key.sign(signed)).decode(),
    }))
    second_path.chmod(0o600)
    approvals.append(_load_approval(second_path))

    def attempt(approval):
        try:
            return _recover(target_id, approval)
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, approvals))
    successes = [result for result in results if result is not None]
    assert len(successes) == 1
    db = SessionLocal()
    try:
        assert db.query(AuditEvent).filter_by(
            event_type=AuditEventType.CREDENTIAL_RECOVERY_COMPLETED,
        ).filter(AuditEvent.target_user_id == target_id).count() == 1
        user = db.query(User).filter(User.id == target_id).one()
        assert password_verifier_scheme(user.hashed_password) == "bcrypt_sha256"
    finally:
        db.close()


def test_command_has_no_password_argument_or_public_recovery_route(capsys):
    from app.cli import recover_admin
    from app.main import app

    with pytest.raises(SystemExit) as exc:
        recover_admin.main(["--help"])
    assert exc.value.code == 0
    help_text = capsys.readouterr().out
    assert "--password" not in help_text
    assert all("credential-recovery" not in route.path for route in app.routes)
