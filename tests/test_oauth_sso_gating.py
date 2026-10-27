"""Security gates for consumer Google, GitHub, and Microsoft OAuth sign-in.

The callback decision order is security-sensitive: reject an unverified
provider email; enforce organization SSO; sign in a linked identity; link an
ordinary passwordless account; require confirmation for password accounts;
and provision a new active user only when a live license approves the email.
"""

import uuid
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import create_oauth_state_token
from app.core.oauth_providers import (
    MICROSOFT_CONSUMER_TENANT_ID,
    PROVIDERS,
    UnverifiedEmailError,
    parse_userinfo,
)
from app.db.models import AuditEvent, OAuthAccount, User
from app.services import license_service, oauth_service, role_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db(client):
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
    return client.post(
        "/auth/google/callback", json={"code": "fake-code", "state": state}
    )


def _license(db, email, *, expires_days=None):
    return license_service.create_license(
        db,
        email=email,
        user_id=None,
        organization_id=None,
        expires_days=expires_days,
    )


def _user(db, email, hashed_password=None, roles=()):
    user = User(email=email, hashed_password=hashed_password, status="active")
    db.add(user)
    db.flush()
    user.roles = [role_service.get_role_by_name(db, role) for role in roles]
    db.commit()
    return user


def _events(db, event_type, email):
    db.expire_all()
    rows = db.query(AuditEvent).filter(AuditEvent.event_type == event_type).all()
    return [row for row in rows if (row.event_metadata or {}).get("email") == email]


# Provider email assertions happen before account lookup or linking.


@pytest.mark.parametrize("verified", [False, None, "false", 0])
def test_google_rejects_email_without_verified_assertion(verified):
    with pytest.raises(UnverifiedEmailError):
        parse_userinfo(
            "google",
            {"sub": "google-1", "email": "victim@example.test", "email_verified": verified},
        )


@pytest.mark.parametrize("verified", [True, "true", "True", "1", 1])
def test_google_accepts_provider_verified_email(verified):
    assert parse_userinfo(
        "google",
        {"sub": "google-1", "email": "owner@example.test", "email_verified": verified},
    ) == ("google-1", "owner@example.test")


def test_microsoft_never_uses_preferred_username_for_account_matching():
    with pytest.raises(UnverifiedEmailError) as exc:
        parse_userinfo(
            "microsoft",
            {
                "sub": "microsoft-1",
                "preferred_username": "victim@example.test",
            },
            id_token_claims={"xms_edov": True},
        )
    assert exc.value.email is None


def test_microsoft_rejects_email_without_provider_verification():
    with pytest.raises(UnverifiedEmailError) as exc:
        parse_userinfo(
            "microsoft",
            {
                "sub": "microsoft-1",
                "email": "victim@example.test",
                "preferred_username": "other@example.test",
            },
            id_token_claims={"xms_edov": False},
        )
    assert exc.value.email == "victim@example.test"


@pytest.mark.parametrize(
    "claims",
    [
        {"xms_edov": True},
        {"xms_edov": "true"},
        {"tid": MICROSOFT_CONSUMER_TENANT_ID},
    ],
)
def test_microsoft_accepts_only_vouched_for_email(claims):
    assert parse_userinfo(
        "microsoft",
        {
            "sub": "microsoft-1",
            "email": "owner@example.test",
            "preferred_username": "ignored@example.test",
        },
        id_token_claims=claims,
    ) == ("microsoft-1", "owner@example.test")


def test_github_uses_verified_email_endpoint_result():
    assert parse_userinfo(
        "github",
        {"id": 42, "email": None},
        [
            {"email": "bad@example.test", "primary": True, "verified": False},
            {"email": "good@example.test", "primary": False, "verified": True},
        ],
    ) == ("42", "good@example.test")


# License/provisioning and account-linking decision order.


def test_is_email_approved_matches_live_license_case_insensitively(db):
    email = _email("approved")
    _license(db, email.upper())
    assert license_service.is_email_approved(db, email) is True


def test_is_email_approved_ignores_revoked_or_expired_license(db):
    revoked_email = _email("revoked")
    revoked = _license(db, revoked_email)
    revoked.revoked_at = license_service.utc_now()
    expired_email = _email("expired")
    expired = _license(db, expired_email)
    expired.expires_at = license_service.utc_now() - timedelta(seconds=1)
    db.commit()
    assert license_service.is_email_approved(db, revoked_email) is False
    assert license_service.is_email_approved(db, expired_email) is False


def test_unapproved_unknown_identity_creates_nothing(
    client, configured_google, monkeypatch, db
):
    email = _email("unapproved")
    _mock_exchange(monkeypatch, "g-unapproved", email)
    response = _callback(client)
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "not_approved"
    db.expire_all()
    assert db.query(User).filter(User.email == email).count() == 0
    assert db.query(OAuthAccount).filter_by(provider_user_id="g-unapproved").count() == 0
    assert len(_events(db, "oauth_rejected_not_approved", email)) == 1


def test_approved_unknown_identity_creates_active_account(
    client, configured_google, monkeypatch, db
):
    email = _email("new")
    _license(db, email)
    _mock_exchange(monkeypatch, "g-new", email)
    response = _callback(client)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    db.expire_all()
    user = db.query(User).filter(User.email == email).one()
    assert user.status == "active"
    assert len(_events(db, "oauth_account_created", email)) == 1


def test_existing_passwordless_account_auto_links_verified_identity(
    client, configured_google, monkeypatch, db
):
    email = _email("passwordless")
    user = _user(db, email)
    _mock_exchange(monkeypatch, "g-passwordless", email.upper())
    response = _callback(client)
    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    db.expire_all()
    link = db.query(OAuthAccount).filter_by(provider_user_id="g-passwordless").one()
    assert link.user_id == user.id


def test_existing_password_account_requires_confirmation(
    client, configured_google, monkeypatch, registered_user
):
    _mock_exchange(monkeypatch, "g-password", registered_user["email"])
    response = _callback(client)
    assert response.status_code == 200
    assert response.json()["status"] == "link_required"


def test_passwordless_privileged_account_is_not_silently_linked(
    client, configured_google, monkeypatch, db
):
    email = _email("privileged")
    _user(db, email, roles=("admin",))
    _mock_exchange(monkeypatch, "g-privileged", email)
    response = _callback(client)
    assert response.status_code == 200
    assert response.json()["status"] == "link_required"
    assert db.query(OAuthAccount).filter_by(provider_user_id="g-privileged").count() == 0


def test_unverified_email_is_rejected_before_account_lookup(
    client, configured_google, monkeypatch, registered_user, db
):
    async def unverified(provider, code, code_verifier=None):
        raise oauth_service.OAuthUnverifiedEmail(provider, registered_user["email"])

    monkeypatch.setattr(oauth_service, "exchange_code_for_userinfo", unverified)
    response = _callback(client)
    assert response.status_code == 403
    assert response.json()["detail"]["reason"] == "unverified_email"
    assert len(
        _events(db, "oauth_rejected_unverified_email", registered_user["email"])
    ) == 1
    assert not _events(db, "oauth_link_required", registered_user["email"])
