"""Tests for the local operator password-enrollment service."""
from datetime import datetime, timedelta
import getpass
import uuid
import warnings
from unittest.mock import MagicMock, patch

import pytest

from app.core.security import hash_password, verify_password
from app.db.models import (
    AuditEvent,
    LicenseKey,
    MFADevice,
    OAuthAccount,
    OrganizationMembership,
    Permission,
    RefreshToken,
    Role,
    User,
    UserSession,
)
from app.db.session import SessionLocal
from app.services.password_enrollment_service import (
    PasswordEnrollmentError,
    PasswordEnrollmentResult,
    UserAuthProfile,
    enroll_existing_user_password,
    inspect_user_auth_profile,
)
from scripts import set_user_password as password_cli


def _user(db, *, email=None, password="Old-Test-Passphrase-934!", roles=()):
    user = User(
        email=email or f"enroll-{uuid.uuid4().hex}@omnibioai.test",
        hashed_password=hash_password(password) if password else None,
        status="active",
    )
    user.roles.extend(roles)
    db.add(user)
    db.flush()
    return user


def _session_and_refresh(db, user, family_id, *, revoked=False):
    now = datetime.utcnow()
    db.add(RefreshToken(
        user_id=user.id,
        token="test-only-placeholder-not-a-bearer-token",
        token_hash=uuid.uuid4().hex * 2,
        family_id=family_id,
        revoked=revoked,
        expires_at=now + timedelta(days=1),
    ))
    db.add(UserSession(
        session_id=family_id,
        user_id=user.id,
        status="active",
        expires_at=now + timedelta(days=1),
    ))


def _confirmed_profile(db, email):
    profile = inspect_user_auth_profile(db, email)
    db.rollback()  # mirror CLI ending its inspection transaction before prompting
    return profile


def test_existing_active_user_password_enrollment_revokes_only_target_state(caplog):
    db = SessionLocal()
    suffix = uuid.uuid4().hex
    target_role = Role(name=f"enrollment-test-{suffix}")
    other_role = Role(name=f"enrollment-other-{suffix}")
    target_permission = Permission(name=f"enrollment-permission-{suffix}")
    target_role.permissions.append(target_permission)
    db.add_all([target_role, other_role])
    db.flush()
    target = _user(db, email=f"Target-{suffix}@omnibioai.test", roles=[target_role])
    other = _user(db, roles=[other_role])
    target_id, other_id, email = target.id, other.id, target.email
    target_family, other_family = str(uuid.uuid4()), str(uuid.uuid4())
    license_row = LicenseKey(
        key=f"OMNI-{suffix[:4].upper()}-{suffix[4:8].upper()}-{suffix[8:12].upper()}-{suffix[12:16].upper()}",
        user_id=target.id,
        email=target.email,
        usage_count=0,
    )
    db.add(license_row)
    db.flush()
    license_id = license_row.id
    _session_and_refresh(db, target, target_family)
    _session_and_refresh(db, other, other_family)
    db.commit()

    old_permissions = [role.name for role in target.roles]
    membership_count_before = db.query(OrganizationMembership).filter_by(user_id=target_id).count()
    new_password = "A-New-Long-Test-Passphrase-720!"
    try:
        profile = _confirmed_profile(db, f"  {email.upper()}  ")
        result = enroll_existing_user_password(db, profile, new_password, new_password)
        db.refresh(target)
        assert result.user_id == target_id
        assert target.email == email
        assert verify_password(new_password, target.hashed_password)
        assert target.hashed_password != new_password
        assert [role.name for role in target.roles] == old_permissions
        assert [permission.name for permission in target.roles[0].permissions] == [target_permission.name]
        assert db.query(OrganizationMembership).filter_by(user_id=target_id).count() == membership_count_before
        saved_license = db.query(LicenseKey).filter_by(id=license_id).one()
        assert saved_license.user_id == target_id
        assert saved_license.email == email
        assert saved_license.usage_count == 0
        assert saved_license.revoked_at is None
        assert db.query(RefreshToken).filter_by(user_id=target_id, revoked=True).count() == 1
        assert db.query(UserSession).filter_by(user_id=target_id, status="revoked").count() == 1
        assert db.query(RefreshToken).filter_by(user_id=other_id, revoked=False).count() == 1
        assert db.query(UserSession).filter_by(user_id=other_id, status="active").count() == 1
        event = db.query(AuditEvent).filter_by(
            event_type="admin_password_credential_changed", target_user_id=target_id
        ).one()
        assert event.event_metadata == {
            "origin": "local_management_command",
            "revoked_refresh_token_count": 1,
            "revoked_session_count": 1,
        }
        assert event.integrity_version == 1
        assert event.integrity_digest
        assert new_password not in repr(event.event_metadata)
        assert new_password not in caplog.text
        assert db.query(User).filter_by(id=other_id).one().hashed_password != target.hashed_password
    finally:
        db.rollback()
        db.close()


def test_identity_profile_reports_only_auth_method_presence():
    db = SessionLocal()
    user = _user(db, password=None)
    email = user.email
    db.commit()
    try:
        profile = inspect_user_auth_profile(db, email.upper())
        assert profile.password_credential_present is False
        assert profile.oauth_account_count == 0
        assert profile.mfa_enabled is False
        assert profile.mfa_device_count == 0
    finally:
        db.rollback()
        db.close()


def test_existing_oauth_and_mfa_material_are_left_unchanged():
    db = SessionLocal()
    user = _user(db, password=None)
    user.mfa_enabled = True
    db.add(OAuthAccount(
        user_id=user.id,
        provider="google",
        provider_user_id=f"oauth-{uuid.uuid4().hex}",
        email=user.email,
    ))
    mfa = MFADevice(
        user_id=user.id,
        device_type="totp",
        label="test factor",
        encrypted_secret="test-encrypted-placeholder",
    )
    db.add(mfa)
    email, user_id = user.email, user.id
    db.commit()
    try:
        profile = inspect_user_auth_profile(db, email)
        assert profile.password_credential_present is False
        assert profile.oauth_account_count == 1
        assert profile.mfa_enabled is True
        assert profile.mfa_device_count == 1
        profile = _confirmed_profile(db, email)
        enroll_existing_user_password(
            db,
            profile,
            "A-New-Long-Test-Passphrase-720!",
            "A-New-Long-Test-Passphrase-720!",
        )
        assert db.query(OAuthAccount).filter_by(user_id=user_id).count() == 1
        assert db.query(MFADevice).filter_by(user_id=user_id).count() == 1
        assert db.query(User).filter_by(id=user_id).one().mfa_enabled is True
    finally:
        db.rollback()
        db.close()


@pytest.mark.parametrize("identity,password,confirmation,message", [
    ("nobody@omnibioai.test", "A-New-Long-Test-Passphrase-720!", "A-New-Long-Test-Passphrase-720!", "No user"),
    ("mismatch@omnibioai.test", "A-New-Long-Test-Passphrase-720!", "Different-Test-Passphrase-720!", "confirmation"),
])
def test_unknown_identity_and_mismatch_fail_without_mutation(identity, password, confirmation, message):
    db = SessionLocal()
    user = None
    if identity.startswith("mismatch"):
        user = _user(db, email=identity)
        before = user.hashed_password
        db.commit()
    try:
        if user:
            profile = _confirmed_profile(db, identity)
            with pytest.raises(PasswordEnrollmentError, match=message):
                enroll_existing_user_password(db, profile, password, confirmation)
        else:
            with pytest.raises(PasswordEnrollmentError, match=message):
                inspect_user_auth_profile(db, identity)
        if user:
            db.refresh(user)
            assert user.hashed_password == before
    finally:
        db.rollback()
        db.close()


def test_duplicate_normalized_identity_fails_closed():
    db = SessionLocal()
    suffix = uuid.uuid4().hex
    _user(db, email=f"duplicate-{suffix}@omnibioai.test")
    _user(db, email=f"DUPLICATE-{suffix}@omnibioai.test")
    db.commit()
    try:
        with pytest.raises(PasswordEnrollmentError, match="ambiguous"):
            inspect_user_auth_profile(db, f"duplicate-{suffix}@omnibioai.test")
    finally:
        db.rollback()
        db.close()


def test_inactive_user_fails_closed():
    db = SessionLocal()
    user = _user(db)
    email = user.email
    db.commit()
    profile = _confirmed_profile(db, email)
    user.status = "disabled"
    before = user.hashed_password
    db.commit()
    try:
        with pytest.raises(PasswordEnrollmentError, match="not active"):
            enroll_existing_user_password(
                db,
                profile,
                "A-New-Long-Test-Passphrase-720!",
                "A-New-Long-Test-Passphrase-720!",
            )
        db.refresh(user)
        assert user.hashed_password == before
    finally:
        db.rollback()
        db.close()


@pytest.mark.parametrize(
    "mutate,error", [
        (lambda db, user: setattr(user, "email", "changed@omnibioai.test"), "identity changed"),
        (lambda db, user: setattr(user, "status", "disabled"), "not active"),
        (lambda db, user: db.delete(user), "no longer exists"),
    ],
    ids=["identity_changed", "became_inactive", "user_deleted"],
)
def test_confirmed_user_id_revalidated_before_mutation(mutate, error):
    db = SessionLocal()
    user = _user(db)
    email, user_id, before = user.email, user.id, user.hashed_password
    db.commit()
    profile = _confirmed_profile(db, email)
    mutate(db, user)
    db.commit()
    try:
        with pytest.raises(PasswordEnrollmentError, match=error):
            enroll_existing_user_password(
                db, profile, "A-New-Long-Test-Passphrase-720!", "A-New-Long-Test-Passphrase-720!"
            )
        if db.query(User).filter_by(id=user_id).one_or_none():
            db.expire_all()
            assert db.query(User).filter_by(id=user_id).one().hashed_password == before
    finally:
        db.rollback()
        db.close()


def _cli_harness(monkeypatch, capsys, *, prompt_results=None, input_value=None, interactive=True):
    profile = UserAuthProfile(
        user_id=41,
        email="canonical@omnibioai.test",
        status="active",
        password_credential_present=False,
        oauth_account_count=0,
        mfa_enabled=False,
        mfa_device_count=0,
    )
    db = MagicMock()
    monkeypatch.setattr(password_cli, "SessionLocal", lambda: db)
    lookup = MagicMock(return_value=profile)
    monkeypatch.setattr(password_cli, "inspect_user_auth_profile", lookup)
    enrollment = MagicMock(return_value=PasswordEnrollmentResult(41, profile.email, 0, 0))
    monkeypatch.setattr(password_cli, "enroll_existing_user_password", enrollment)
    monkeypatch.setattr(password_cli.sys, "argv", ["set_user_password.py", "operator-input@omnibioai.test"])
    monkeypatch.setattr(password_cli.sys, "stdin", type("TTY", (), {"isatty": lambda self: interactive})())
    prompts = []
    monkeypatch.setattr(
        "builtins.input",
        lambda prompt="": (prompts.append(prompt), input_value or "SET PASSWORD FOR USER ID 41 (canonical@omnibioai.test)")[1],
    )
    if prompt_results is not None:
        replies = iter(prompt_results)

        def getpass_reply(_prompt=""):
            reply = next(replies)
            if isinstance(reply, BaseException):
                raise reply
            return reply() if callable(reply) else reply

        monkeypatch.setattr(password_cli.getpass, "getpass", MagicMock(side_effect=getpass_reply))
    return profile, db, enrollment, prompts, lookup


def test_cli_hidden_prompt_success_and_identity_confirmation(monkeypatch, capsys):
    secret = "CLI-Secret-Not-For-Output-849!"
    profile, db, enrollment, prompts, _lookup = _cli_harness(
        monkeypatch, capsys, prompt_results=[secret, secret]
    )
    assert password_cli.main() == 0
    captured = capsys.readouterr()
    assert "USER ID 41" in prompts[0]
    assert "canonical@omnibioai.test" in prompts[0]
    enrollment.assert_called_once_with(db, profile, secret, secret)
    assert secret not in captured.out
    assert secret not in captured.err
    db.rollback.assert_called_once()
    db.close.assert_called_once()


@pytest.mark.parametrize("warning_prompt", [1, 2], ids=["new_password", "confirmation"])
def test_cli_getpass_warning_aborts_without_mutation_or_secret_output(
    monkeypatch, capsys, caplog, warning_prompt
):
    secret = "CLI-Secret-Not-For-Output-849!"

    def fallback_warning():
        warnings.warn("terminal echo unavailable", getpass.GetPassWarning)
        return secret

    replies = [secret, secret]
    replies[warning_prompt - 1] = fallback_warning
    _profile, _db, enrollment, _prompts, _lookup = _cli_harness(
        monkeypatch, capsys, prompt_results=replies
    )
    assert password_cli.main() == 2
    captured = capsys.readouterr()
    assert "Secure hidden password input is unavailable; aborting." in captured.err
    assert secret not in captured.out + captured.err + caplog.text
    enrollment.assert_not_called()


@pytest.mark.parametrize(
    "failure", [EOFError, KeyboardInterrupt, OSError], ids=["eof", "interrupt", "terminal_error"]
)
def test_cli_terminal_input_failures_abort_without_mutation(monkeypatch, capsys, failure):
    failure_detail = "terminal-failure-detail-must-not-leak"
    _profile, _db, enrollment, _prompts, _lookup = _cli_harness(
        monkeypatch, capsys, prompt_results=[failure(failure_detail)]
    )
    assert password_cli.main() == 2
    captured = capsys.readouterr()
    assert failure_detail not in captured.out + captured.err
    enrollment.assert_not_called()


def test_cli_rejects_piped_input_before_lookup_or_mutation(monkeypatch, capsys):
    _profile, _db, enrollment, _prompts, lookup = _cli_harness(monkeypatch, capsys, interactive=False)
    assert password_cli.main() == 2
    assert "Interactive terminal input is required" in capsys.readouterr().err
    lookup.assert_not_called()
    enrollment.assert_not_called()


def test_cli_mismatch_error_does_not_print_either_password(monkeypatch, capsys, caplog):
    first, second = "First-Secret-Not-Printed-91!", "Second-Secret-Not-Printed-92!"
    _profile, _db, enrollment, _prompts, _lookup = _cli_harness(
        monkeypatch, capsys, prompt_results=[first, second]
    )
    enrollment.side_effect = PasswordEnrollmentError("Password confirmation does not match")
    assert password_cli.main() == 1
    captured = capsys.readouterr()
    assert first not in captured.out + captured.err + caplog.text
    assert second not in captured.out + captured.err + caplog.text
    enrollment.assert_called_once()


def test_password_policy_failure_preserves_credential():
    db = SessionLocal()
    user = _user(db)
    before = user.hashed_password
    email = user.email
    db.commit()
    profile = _confirmed_profile(db, email)
    try:
        with pytest.raises(PasswordEnrollmentError, match="security requirements"):
            enroll_existing_user_password(db, profile, "short", "short")
        db.refresh(user)
        assert user.hashed_password == before
    finally:
        db.rollback()
        db.close()


def test_audit_failure_rolls_back_credential_and_session_changes():
    db = SessionLocal()
    user = _user(db)
    family = str(uuid.uuid4())
    _session_and_refresh(db, user, family)
    before = user.hashed_password
    email = user.email
    user_id = user.id
    db.commit()
    profile = _confirmed_profile(db, email)
    try:
        with patch("app.services.password_enrollment_service.audit_service.log_event", side_effect=RuntimeError):
            with pytest.raises(PasswordEnrollmentError, match="no changes committed"):
                enroll_existing_user_password(
                    db,
                    profile,
                    "A-New-Long-Test-Passphrase-720!",
                    "A-New-Long-Test-Passphrase-720!",
                )
        db.refresh(user)
        assert user.hashed_password == before
        assert db.query(RefreshToken).filter_by(user_id=user_id, revoked=False).count() == 1
        assert db.query(UserSession).filter_by(user_id=user_id, status="active").count() == 1
    finally:
        db.rollback()
        db.close()


def test_service_source_does_not_log_or_print_password():
    from pathlib import Path

    repo_root = Path(__file__).resolve().parents[1]
    source = (repo_root / "app/services/password_enrollment_service.py").read_text()
    cli = (repo_root / "scripts/set_user_password.py").read_text()
    assert "logger." not in source
    assert "print(password" not in cli
    assert "--password" not in cli
    assert "password-file" not in cli
    assert "os.environ" not in cli
    assert "sys.stdin.read" not in cli
    assert "@router." not in source
    assert "execute(" not in source
    assert "historical_hash" not in source
