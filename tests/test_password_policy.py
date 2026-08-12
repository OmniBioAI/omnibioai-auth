"""HIPAA Phase 1 PR2: local-password security policy.

Exercises app/core/password_policy.py, app/core/compromised_password.py,
app/core/common_passwords.py, and the bcrypt_sha256 switch in
app/core/security.py, both directly and through POST /auth/register (the
one and only local-password-creation endpoint -- see
password_policy.py's module docstring for why there's no
change/reset/admin/invitation flow to also cover).

conftest.py's session-scoped `client` fixture patches
`app.core.compromised_password.httpx.get` to a default "provider
reachable, nothing found" response for the whole session -- every
pre-existing test in this suite that calls /auth/register (and this
file's own tests that don't care about the compromised-password path
specifically) rely on that default. Tests here that need a different
provider behavior patch it again themselves, for the duration of that
one test only.
"""
import uuid
from unittest.mock import MagicMock, patch

from app.core import password_policy
from app.core.config import settings
from app.core.security import hash_password, needs_rehash


def _unique_email():
    return f"pwpolicy-{uuid.uuid4().hex[:10]}@omnibioai.test"


def _hibp_response(text: str):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.text = text
    return resp


# ── Minimum / maximum length ────────────────────────────────────────────

def test_password_below_minimum_rejected(client):
    email = _unique_email()
    short = "x" * (settings.PASSWORD_MIN_LENGTH - 1)
    resp = client.post("/auth/register", json={"email": email, "password": short})
    assert resp.status_code == 400


def test_password_exactly_minimum_accepted(client):
    email = _unique_email()
    exact = "Xy9!" + "a" * (settings.PASSWORD_MIN_LENGTH - 4)
    assert len(exact) == settings.PASSWORD_MIN_LENGTH
    resp = client.post("/auth/register", json={"email": email, "password": exact})
    assert resp.status_code == 200


def test_password_above_minimum_accepted(client):
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": "Correct-Horse-Battery-1"})
    assert resp.status_code == 200


def test_password_up_to_max_length_accepted(client):
    email = _unique_email()
    long_pw = "Aa1!" + "b" * (settings.PASSWORD_MAX_LENGTH - 4)
    assert len(long_pw) == settings.PASSWORD_MAX_LENGTH
    resp = client.post("/auth/register", json={"email": email, "password": long_pw})
    assert resp.status_code == 200


def test_password_above_max_length_rejected(client):
    email = _unique_email()
    too_long = "Aa1!" + "b" * settings.PASSWORD_MAX_LENGTH
    resp = client.post("/auth/register", json={"email": email, "password": too_long})
    assert resp.status_code == 400


def test_no_silent_truncation_full_password_required_to_login(client):
    """Discovery finding this PR fixes: plain bcrypt only hashes the
    first 72 bytes of its input, so a password differing only past byte
    72 used to still verify. bcrypt_sha256 (security.py's new default
    scheme) closes this -- the full password, not just its first 72
    bytes, must match.
    """
    email = _unique_email()
    tail_a = "A" * 90 + "TAIL-ALPHA-1!"
    tail_b = "A" * 90 + "TAIL-BETA-99!"
    assert tail_a[:72] == tail_b[:72]  # identical up to byte 72

    reg = client.post("/auth/register", json={"email": email, "password": tail_a})
    assert reg.status_code == 200

    wrong_tail = client.post("/auth/login", json={"email": email, "password": tail_b})
    assert wrong_tail.status_code == 401

    correct = client.post("/auth/login", json={"email": email, "password": tail_a})
    assert correct.status_code == 200


# ── Strength / common-password behavior ─────────────────────────────────

def test_common_password_rejected(client):
    email = _unique_email()
    assert "password1234" in __import__("app.core.common_passwords", fromlist=["COMMON_PASSWORDS"]).COMMON_PASSWORDS
    resp = client.post("/auth/register", json={"email": email, "password": "password1234"})
    assert resp.status_code == 400


def test_reasonable_passphrase_accepted(client):
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": "correct horse battery staple"})
    assert resp.status_code == 200


def test_password_with_symbols_accepted(client):
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": "Tr@ffic-Light#42$Zebra"})
    assert resp.status_code == 200


def test_unicode_password_accepted(client):
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": "Correct-Häst-日本語-Пароль1"})
    assert resp.status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": "Correct-Häst-日本語-Пароль1"})
    assert login.status_code == 200


def test_password_matching_own_email_rejected(client):
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": email})
    assert resp.status_code == 400


def test_password_not_overconstrained_no_mandatory_character_classes(client):
    """No mandatory-uppercase/number/symbol rule -- a long, all-lowercase
    passphrase must be accepted (length + not-common + not-compromised
    is the whole policy)."""
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": "just a long lowercase passphrase"})
    assert resp.status_code == 200


# ── Compromised-password checking ───────────────────────────────────────

def test_known_compromised_password_rejected(client):
    password = "Compr0mised-Example-Pw!"
    _, suffix = password_policy.compromised_password._sha1_prefix_suffix(password)
    fake_text = f"{suffix}:47\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:3\n"
    with patch("app.core.compromised_password.httpx.get", return_value=_hibp_response(fake_text)):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": password})
    assert resp.status_code == 400


def test_known_safe_password_accepted(client):
    password = "Definitely-Not-Breached-Pw-42!"
    _, _suffix = password_policy.compromised_password._sha1_prefix_suffix(password)
    fake_text = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:9\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2\n"
    with patch("app.core.compromised_password.httpx.get", return_value=_hibp_response(fake_text)):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": password})
    assert resp.status_code == 200


def test_only_prefix_sent_never_plaintext_or_full_hash(client):
    password = "Never-Send-This-Plaintext-42!"
    _, real_suffix = password_policy.compromised_password._sha1_prefix_suffix(password)
    captured = {}

    def _fake_get(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return _hibp_response("")

    with patch("app.core.compromised_password.httpx.get", side_effect=_fake_get):
        client.post("/auth/register", json={"email": _unique_email(), "password": password})

    assert password not in captured["url"]
    assert real_suffix not in captured["url"]
    full_request_repr = str(captured["url"]) + str(captured["kwargs"])
    assert password not in full_request_repr


def test_provider_response_parsed_case_insensitively(client):
    password = "Case-Insensitive-Match-Pw-9!"
    _, suffix = password_policy.compromised_password._sha1_prefix_suffix(password)
    fake_text = f"{suffix.lower()}:5\n"
    with patch("app.core.compromised_password.httpx.get", return_value=_hibp_response(fake_text)):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": password})
    assert resp.status_code == 400


def test_provider_unavailable_fails_open_by_default(client):
    with patch("app.core.compromised_password.httpx.get", side_effect=ConnectionError("simulated outage")):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": "Outage-Fallback-Pw-42!"})
    assert resp.status_code == 200


def test_provider_unavailable_fails_closed_when_configured(client, monkeypatch):
    monkeypatch.setattr(settings, "PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED", True)
    with patch("app.core.compromised_password.httpx.get", side_effect=ConnectionError("simulated outage")):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": "Outage-Strict-Pw-42!"})
    assert resp.status_code == 400


def test_provider_timeout_handled_same_as_connection_error(client):
    import httpx as httpx_module
    with patch("app.core.compromised_password.httpx.get", side_effect=httpx_module.TimeoutException("timed out")):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": "Timeout-Fallback-Pw-42!"})
    assert resp.status_code == 200


def test_malformed_provider_response_does_not_crash(client):
    garbage = "not-a-valid-line\n\nnoColonHere\n:::::\n"
    with patch("app.core.compromised_password.httpx.get", return_value=_hibp_response(garbage)):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": "Malformed-Resp-Pw-42!"})
    assert resp.status_code == 200


def test_padding_decoy_lines_with_zero_count_are_not_treated_as_matches(client):
    password = "Padding-Decoy-Test-Pw-42!"
    _, suffix = password_policy.compromised_password._sha1_prefix_suffix(password)
    fake_text = f"{suffix}:0\n"  # Add-Padding decoy for this exact suffix, count=0
    with patch("app.core.compromised_password.httpx.get", return_value=_hibp_response(fake_text)):
        resp = client.post("/auth/register", json={"email": _unique_email(), "password": password})
    assert resp.status_code == 200


# ── Registration enforcement / error shape ──────────────────────────────

def test_registration_rejects_policy_violation_with_generic_message(client):
    resp = client.post("/auth/register", json={"email": _unique_email(), "password": "short"})
    assert resp.status_code == 400
    body = resp.json()
    assert body["detail"] == "This password cannot be used because it does not meet the security requirements."


def test_registration_error_does_not_reveal_which_rule_failed(client):
    common_resp = client.post("/auth/register", json={"email": _unique_email(), "password": "password1234"})
    short_resp = client.post("/auth/register", json={"email": _unique_email(), "password": "short"})
    assert common_resp.json() == short_resp.json()
    blob = str(common_resp.json()).lower()
    for leaky_term in ("breach", "pwned", "hibp", "common password", "blocklist", "too short", "too long"):
        assert leaky_term not in blob


# ── SSO / OAuth boundary ─────────────────────────────────────────────────

def test_oauth_user_creation_has_no_local_password_and_bypasses_policy(client):
    """OAuth/SSO-provisioned users get hashed_password=None (see
    oauth_service.create_user_with_oauth / license_service) -- this
    PR's policy is never consulted for them, since it only runs inside
    POST /auth/register."""
    from app.db.session import SessionLocal
    from app.services import oauth_service

    db = SessionLocal()
    try:
        user = oauth_service.create_user_with_oauth(
            db, email=_unique_email(), provider="google", provider_user_id=uuid.uuid4().hex,
        )
        assert user.hashed_password is None
    finally:
        db.close()


# ── Existing authentication / hashing regressions ───────────────────────

def test_existing_registered_user_still_authenticates(client, registered_user):
    resp = client.post("/auth/login", json=registered_user)
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_legacy_plain_bcrypt_hash_still_verifies_and_gets_upgraded(client):
    """A hash produced before this PR (plain "bcrypt" scheme) must keep
    authenticating exactly as before -- no forced reset -- and gets
    transparently upgraded to bcrypt_sha256 on that same successful
    login (auth_service.authenticate_user's needs_rehash branch)."""
    from passlib.context import CryptContext

    from app.db.models import User
    from app.db.session import SessionLocal
    from app.services.role_service import assign_default_role

    legacy_ctx = CryptContext(schemes=["bcrypt"])
    email = _unique_email()
    password = "Legacy-Bcrypt-Hash-Pw-42!"
    legacy_hash = legacy_ctx.hash(password)
    assert legacy_hash.startswith("$2b$")

    db = SessionLocal()
    try:
        user = User(email=email, hashed_password=legacy_hash, status="active")
        db.add(user)
        db.flush()
        assign_default_role(db, user)
        db.commit()
    finally:
        db.close()

    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200

    db = SessionLocal()
    try:
        refreshed = db.query(User).filter(User.email == email).first()
        assert refreshed.hashed_password.startswith("$bcrypt-sha256$")
        assert not refreshed.hashed_password.startswith("$2b$")
    finally:
        db.close()

    second_login = client.post("/auth/login", json={"email": email, "password": password})
    assert second_login.status_code == 200


def test_hash_password_produces_bcrypt_sha256_by_default():
    h = hash_password("some-password-value-1!")
    assert h.startswith("$bcrypt-sha256$")


def test_needs_rehash_true_for_legacy_false_for_current():
    from passlib.context import CryptContext

    legacy_ctx = CryptContext(schemes=["bcrypt"])
    legacy_hash = legacy_ctx.hash("whatever-1!")
    current_hash = hash_password("whatever-1!")

    assert needs_rehash(legacy_hash) is True
    assert needs_rehash(current_hash) is False


def test_needs_rehash_never_raises_on_garbage_input():
    assert needs_rehash("not-a-real-hash-at-all") is False


# ── Privacy / security regressions ──────────────────────────────────────

def test_registration_response_never_contains_password(client):
    password = "Response-Body-Leak-Check-1!"
    resp = client.post("/auth/register", json={"email": _unique_email(), "password": password})
    assert password not in resp.text


def test_hashed_password_never_in_register_or_validate_response(client):
    email = _unique_email()
    resp = client.post("/auth/register", json={"email": email, "password": "Serialization-Check-Pw-1!"})
    assert "hashed_password" not in resp.text
    login = client.post("/auth/login", json={"email": email, "password": "Serialization-Check-Pw-1!"})
    validate = client.post("/auth/validate", json={"token": login.json()["access_token"]})
    assert "hashed_password" not in validate.text
    assert "$bcrypt" not in validate.text


def test_password_not_present_in_application_logs(client, caplog):
    password = "Must-Never-Appear-In-Logs-42!"
    with caplog.at_level("DEBUG"):
        client.post("/auth/register", json={"email": _unique_email(), "password": password})
        client.post("/auth/login", json={"email": _unique_email(), "password": password})
        client.post("/auth/register", json={"email": _unique_email(), "password": "short"})
    for record in caplog.records:
        assert password not in record.getMessage()


def test_password_not_present_in_audit_events(client):
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.db.models import AuditEvent

    direct_engine = create_engine("sqlite:///./test.db")
    DirectSession = sessionmaker(bind=direct_engine)

    password = "Audit-Event-Leak-Check-Pw-42!"
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": password})
    client.post("/auth/login", json={"email": email, "password": "wrong-" + password})

    db = DirectSession()
    try:
        events = db.query(AuditEvent).filter(AuditEvent.actor_user_id.is_not(None)).all()
        for e in events:
            assert password not in str(e.event_metadata)
    finally:
        db.close()
