"""v62 SSO gating for consumer Google/GitHub/Microsoft sign-in: is_email_approved,
and the callback decision order -- linked identity signs in; an existing
account with a password needs link confirmation; a passwordless account is
linked automatically (never an admin or disabled-password one); a new account
needs a live license for its email; an unverified email is rejected. Every
outcome is audited with provider and email only.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_oauth_state_token
from app.core.oauth_providers import PROVIDERS
from app.db.models import AuditEvent, OAuthAccount, Organization, User
from app.services import license_service, oauth_service, role_service, sso_discovery_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db(client):  # depends on `client` only to guarantee setup_db has run first
    session = _DirectSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def configured_google(monkeypatch):
    monkeypatch.setitem(PROVIDERS["google"], "client_id", "test-google-client-id")
    monkeypatch.setitem(PROVIDERS["google"], "client_secret", "test-google-client-secret")


def _email(tag="gate"):
    return f"sso-{tag}-{uuid.uuid4().hex[:8]}@omnibioai.test"


def _mock_exchange(monkeypatch, provider_user_id, email):
    async def fake_exchange(provider, code, code_verifier=None):
        return provider_user_id, email
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", fake_exchange)


def _callback(client):
    state = create_oauth_state_token("google")
    return client.post("/auth/google/callback", json={"code": "fake-code", "state": state})


def _events(db, event_type, email):
    db.expire_all()
    rows = db.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()
    return [r for r in rows if (r.event_metadata or {}).get("email") == email]


def _assert_no_secrets(event):
    assert set(event.event_metadata) <= {"provider", "email", "mfa_required"}


def _license(db, email, **kwargs):
    return license_service.create_license(db, email=email, **kwargs)


def _user(db, email, hashed_password=None, roles=()):
    user = User(email=email, hashed_password=hashed_password, status="active")
    db.add(user)
    db.flush()
    user.roles = [role_service.get_role_by_name(db, name) for name in roles]
    db.commit()
    return user


# ── is_email_approved ─────────────────────────────────────────────────────────

def test_is_email_approved_matches_a_live_license(db):
    email = _email("approved")
    _license(db, email)
    assert license_service.is_email_approved(db, email) is True


def test_is_email_approved_is_case_insensitive(db):
    email = _email("case")
    _license(db, email.upper())
    assert license_service.is_email_approved(db, email) is True


def test_is_email_approved_ignores_revoked_license(db):
    email = _email("revoked")
    row = _license(db, email)
    license_service.revoke(db, row.key)
    assert license_service.is_email_approved(db, email) is False


def test_is_email_approved_ignores_expired_license(db):
    email = _email("expired")
    row = _license(db, email)
    row.expires_at = datetime.utcnow() - timedelta(days=1)
    db.commit()
    assert license_service.is_email_approved(db, email) is False


def test_is_email_approved_false_without_license(db):
    assert license_service.is_email_approved(db, _email("none")) is False


# ── Callback decision order ───────────────────────────────────────────────────

def test_linked_identity_signs_in_even_after_license_expires(client, configured_google, monkeypatch, db):
    """An expired trial blocks only new accounts: a linked identity keeps signing in."""
    email = _email("linked")
    row = _license(db, email)
    _mock_exchange(monkeypatch, "g-linked", email)
    assert _callback(client).json()["status"] == "ok"

    row.expires_at = datetime.utcnow() - timedelta(days=1)
    db.commit()
    resp = _callback(client)
    assert resp.status_code == 200 and resp.json()["status"] == "ok"
    assert len(_events(db, "oauth_login", email)) == 2


def test_existing_account_with_password_requires_link_confirmation(client, configured_google, monkeypatch, registered_user, db):
    _mock_exchange(monkeypatch, "g-has-password", registered_user["email"])
    resp = _callback(client)
    assert resp.json()["status"] == "link_required"
    events = _events(db, "oauth_link_required", registered_user["email"])
    assert len(events) == 1
    _assert_no_secrets(events[0])


def test_existing_passwordless_account_is_linked_automatically(client, configured_google, monkeypatch, db):
    """A passwordless account (e.g. from license activation) is linked and signed in; the email
    match ignores case."""
    email = _email("nopw")
    user = _user(db, email)
    _mock_exchange(monkeypatch, "g-nopw", email.upper())

    resp = _callback(client)
    assert resp.status_code == 200 and resp.json()["status"] == "ok"
    db.expire_all()
    link = db.query(OAuthAccount).filter_by(provider="google", provider_user_id="g-nopw").one()
    assert link.user_id == user.id
    assert len(_events(db, "oauth_linked", email.upper())) == 1
    assert len(_events(db, "oauth_login", email.upper())) == 1


def test_passwordless_admin_is_never_linked_automatically(client, configured_google, monkeypatch, db):
    email = _email("admin")
    _user(db, email, roles=("admin",))
    _mock_exchange(monkeypatch, "g-admin", email)
    assert _callback(client).json()["status"] == "link_required"
    assert db.query(OAuthAccount).filter_by(provider_user_id="g-admin").count() == 0


def test_disabled_password_marker_is_not_treated_as_no_password(client, configured_google, monkeypatch, db):
    email = _email("disabled")
    _user(db, email, hashed_password="!disabled")
    _mock_exchange(monkeypatch, "g-disabled", email)
    assert _callback(client).json()["status"] == "link_required"
    assert db.query(OAuthAccount).filter_by(provider_user_id="g-disabled").count() == 0


def test_approved_new_email_creates_an_account(client, configured_google, monkeypatch, db):
    email = _email("new")
    _license(db, email)
    _mock_exchange(monkeypatch, "g-new", email)

    resp = _callback(client)
    assert resp.status_code == 200 and resp.json()["status"] == "ok"
    db.expire_all()
    user = db.query(User).filter(User.email == email).one()
    assert [r.name for r in user.roles] == ["user"]
    created = _events(db, "oauth_account_created", email)
    assert len(created) == 1 and created[0].target_user_id == user.id
    _assert_no_secrets(created[0])


def test_unapproved_new_email_is_rejected_and_creates_nothing(client, configured_google, monkeypatch, db):
    email = _email("unapproved")
    _mock_exchange(monkeypatch, "g-unapproved", email)

    resp = _callback(client)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "not_approved"
    assert "Request beta access at omnibioai.org" in resp.json()["detail"]["message"]
    db.expire_all()
    assert db.query(User).filter(User.email == email).count() == 0
    assert db.query(OAuthAccount).filter_by(provider_user_id="g-unapproved").count() == 0
    rejected = _events(db, "oauth_rejected_not_approved", email)
    assert len(rejected) == 1
    _assert_no_secrets(rejected[0])


def test_unapproved_email_get_callback_redirects_with_reason(client, configured_google, monkeypatch):
    email = _email("redirect")
    _mock_exchange(monkeypatch, "g-redirect", email)
    state = create_oauth_state_token("google")
    resp = client.get(f"/auth/google/callback?code=fake-code&state={state}", follow_redirects=False)
    params = parse_qs(urlparse(resp.headers["location"]).query)
    assert params["status"] == ["error"]
    assert params["reason"] == ["not_approved"]


def test_unverified_email_is_rejected_before_any_lookup(client, configured_google, monkeypatch, registered_user, db):
    """Even an email matching an existing account is rejected when the provider didn't verify it."""
    async def unverified(provider, code, code_verifier=None):
        raise oauth_service.OAuthUnverifiedEmail(provider, registered_user["email"])
    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", unverified)

    resp = _callback(client)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "unverified_email"
    rejected = _events(db, "oauth_rejected_unverified_email", registered_user["email"])
    assert len(rejected) == 1
    _assert_no_secrets(rejected[0])
    assert not _events(db, "oauth_link_required", registered_user["email"])


def test_org_sso_enforcement_still_wins_over_approval(client, configured_google, monkeypatch, db):
    """An enforcing org's member is sent to their org's SSO, approved or not."""
    org = Organization(slug=f"enforced-{uuid.uuid4().hex[:8]}", name="Enforced Org")
    db.add(org)
    db.commit()
    email = _email("enforced")
    _license(db, email)
    _mock_exchange(monkeypatch, "g-enforced", email)
    monkeypatch.setattr(
        sso_discovery_service, "find_enforced_org_for_email",
        lambda _db, _email: SimpleNamespace(organization_id=org.id),
    )

    resp = _callback(client)
    assert resp.status_code == 403
    assert resp.json()["detail"]["reason"] == "sso_required"
    db.expire_all()
    assert db.query(User).filter(User.email == email).count() == 0
