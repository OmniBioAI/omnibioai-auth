"""Isolated regression coverage for organization invitation lifecycle."""
import re
import uuid
import os
import time
import urllib.parse
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from cryptography.fernet import Fernet
import pytest

from app.core import crypto
from app.core.config import settings
from app.db.models import (
    AuditEvent, MFADevice, Organization, OrganizationInvitation,
    OrganizationMFAPolicy, OrganizationMembership, User,
)
from app.db.session import SessionLocal
from app.services import email_delivery_service, mfa_service, role_service
from app.services.org_service import ORG_MEMBER_ROLE


@pytest.fixture(autouse=True)
def _configure_invitation_test_delivery(monkeypatch):
    """Keep lifecycle tests deterministic despite the production-safe
    default-off feature flag and absent outbound email credentials.
    Individual tests may override either setting or the delivery stub.
    """
    monkeypatch.setattr(settings, "ORG_INVITATIONS_ENABLED", True)
    monkeypatch.setattr(settings, "ORG_INVITATION_ACCEPT_URL", "https://admin.example.com/invitations/accept")
    monkeypatch.setattr(email_delivery_service, "send_organization_invitation", lambda *_args, **_kwargs: None)


def _register_login(client, email=None):
    email = email or f"inviter-{uuid.uuid4().hex[:10]}@omnibioai.test"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    return email, password, {"Authorization": f"Bearer {login.json()['access_token']}"}


def _org(client, headers):
    response = client.post("/orgs", json={"name": "Invitation Test", "slug": f"invite-{uuid.uuid4().hex[:10]}"}, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["id"]


def _admin_headers(client):
    result = client.post("/auth/login", json={
        "email": "admin@omnibioai", "password": os.environ["ADMIN_BOOTSTRAP_PASSWORD"],
    })
    assert result.status_code == 200
    return {"Authorization": f"Bearer {result.json()['access_token']}"}


def _enable_delivery(monkeypatch):
    delivered = {}
    monkeypatch.setattr(settings, "ORG_INVITATIONS_ENABLED", True)
    monkeypatch.setattr(settings, "ORG_INVITATION_ACCEPT_URL", "https://admin.example.com/invitations/accept")
    monkeypatch.setattr(email_delivery_service, "send_organization_invitation", lambda recipient, **kw: delivered.update(recipient=recipient, url=kw["accept_url"]))
    return delivered


def _require_org_mfa(org_id):
    with SessionLocal() as db:
        db.add(OrganizationMFAPolicy(organization_id=org_id, required=True))
        db.commit()


def _token_from_delivery(delivered):
    return re.search(r"#token=([A-Za-z0-9_-]+)$", delivered["url"]).group(1)


def _totp_from_uri(uri):
    return urllib.parse.parse_qs(urllib.parse.urlparse(uri).query)["secret"][0]


def test_new_user_invitation_acceptance_activates_membership_and_hashes_token(client, monkeypatch):
    delivered = _enable_delivery(monkeypatch)
    _email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    invitee = f"new-{uuid.uuid4().hex[:10]}@omnibioai.test"
    response = client.post(f"/orgs/{org_id}/invitations", json={"email": invitee, "roles": ["org_member"]}, headers=headers)
    assert response.status_code == 201, response.text
    assert "token" not in response.text.lower()
    token = re.search(r"#token=([A-Za-z0-9_-]+)$", delivered["url"]).group(1)
    preview = client.post("/organization-invitations/preview", json={"token": token})
    assert preview.status_code == 200 and preview.json()["existing_user"] is False
    issue_payload = {
        "full_name": "Synthetic Invitee", "email": invitee, "persona": "application_user",
        "validity_days": 30, "organization_id": org_id,
        "confirm_role_change": True, "confirm_replace_existing": False,
    }
    before_membership = client.post(
        "/platform/licenses", json=issue_payload,
        headers={**_admin_headers(client), "Idempotency-Key": uuid.uuid4().hex},
    )
    assert before_membership.status_code == 409
    assert before_membership.json()["detail"]["code"] == "provisioning_required"
    accepted = client.post("/organization-invitations/accept", json={"token": token, "password": "StrongerNewPassphrase!2036"})
    assert accepted.status_code == 200
    after_membership = client.post(
        "/platform/licenses", json=issue_payload,
        headers={**_admin_headers(client), "Idempotency-Key": uuid.uuid4().hex},
    )
    assert after_membership.status_code == 200, after_membership.text
    with SessionLocal() as db:
        invitation = db.query(OrganizationInvitation).filter_by(invited_email=invitee).one()
        member = db.query(OrganizationMembership).filter_by(organization_id=org_id, user_id=accepted.json()["user_id"]).one()
        assert invitation.status == "accepted"
        assert invitation.token_hash != token
        assert invitation.active_key is None
        assert member.status == "active"
        events = db.query(AuditEvent).filter(AuditEvent.resource_id == str(invitation.id)).all()
        assert {event.event_type for event in events} >= {
            "organization_invitation_created", "organization_invitation_accepted",
        }
        assert all(token not in repr((event.before_state, event.after_state, event.event_metadata)) for event in events)
    retry = client.post("/organization-invitations/accept", json={"token": token, "password": "StrongerNewPassphrase!2036"})
    assert retry.status_code == 200


def test_existing_user_invitation_requires_same_authenticated_identity(client, monkeypatch):
    delivered = _enable_delivery(monkeypatch)
    _inviter_email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    invitee_email, _invitee_password, invitee_headers = _register_login(client)
    response = client.post(f"/orgs/{org_id}/invitations", json={"email": invitee_email}, headers=headers)
    assert response.status_code == 201
    token = re.search(r"#token=([A-Za-z0-9_-]+)$", delivered["url"]).group(1)
    preview = client.post("/organization-invitations/preview", json={"token": token})
    assert preview.status_code == 200 and preview.json()["existing_user"] is True
    issue_payload = {
        "full_name": "Existing Invitee", "email": invitee_email, "persona": "application_user",
        "validity_days": 30, "organization_id": org_id,
        "confirm_role_change": True, "confirm_replace_existing": False,
    }
    pending_issue = client.post(
        "/platform/licenses", json=issue_payload,
        headers={**_admin_headers(client), "Idempotency-Key": uuid.uuid4().hex},
    )
    assert pending_issue.status_code == 404
    assert pending_issue.json()["detail"]["code"] == "organization_membership_required"
    accepted = client.post("/organization-invitations/accept-existing", json={"token": token}, headers=invitee_headers)
    assert accepted.status_code == 200, accepted.text
    active_issue = client.post(
        "/platform/licenses", json=issue_payload,
        headers={**_admin_headers(client), "Idempotency-Key": uuid.uuid4().hex},
    )
    assert active_issue.status_code == 200, active_issue.text
    assert client.post("/organization-invitations/accept-existing", json={"token": token}, headers=invitee_headers).status_code == 200


def test_invitation_scope_and_duplicate_are_enforced(client, monkeypatch):
    delivered = _enable_delivery(monkeypatch)
    _email_a, _password_a, headers_a = _register_login(client)
    org_a, org_b = _org(client, headers_a), _org(client, headers_a)
    invitee = f"scope-{uuid.uuid4().hex[:10]}@omnibioai.test"
    first = client.post(f"/orgs/{org_a}/invitations", json={"email": invitee}, headers=headers_a)
    assert first.status_code == 201, first.text
    duplicate = client.post(f"/orgs/{org_a}/invitations", json={"email": invitee}, headers=headers_a)
    assert duplicate.status_code == 409
    _email_b, _password_b, headers_b = _register_login(client)
    cross_tenant = client.post(f"/orgs/{org_b}/invitations", json={"email": "target@omnibioai.test"}, headers=headers_b)
    assert cross_tenant.status_code in (403, 404)
    assert delivered["recipient"] == invitee


def test_revoked_invitation_cannot_be_accepted(client, monkeypatch):
    delivered = _enable_delivery(monkeypatch)
    _email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    created = client.post(f"/orgs/{org_id}/invitations", json={"email": f"revoke-{uuid.uuid4().hex[:10]}@omnibioai.test"}, headers=headers)
    token = re.search(r"#token=([A-Za-z0-9_-]+)$", delivered["url"]).group(1)
    invitation_id = created.json()["id"]
    revoked = client.post(f"/orgs/{org_id}/invitations/{invitation_id}/revoke", headers=headers)
    assert revoked.status_code == 200 and revoked.json()["status"] == "revoked"
    assert client.post("/organization-invitations/mfa-setup", json={"token": token}).status_code == 410
    assert client.post("/organization-invitations/preview", json={"token": token}).status_code == 410


def test_expired_invitation_is_marked_and_rejected(client, monkeypatch):
    from datetime import datetime, timedelta

    delivered = _enable_delivery(monkeypatch)
    _email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    created = client.post(f"/orgs/{org_id}/invitations", json={"email": f"expired-{uuid.uuid4().hex[:10]}@omnibioai.test"}, headers=headers)
    token = re.search(r"#token=([A-Za-z0-9_-]+)$", delivered["url"]).group(1)
    with SessionLocal() as db:
        invitation = db.query(OrganizationInvitation).filter_by(id=created.json()["id"]).one()
        invitation.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.commit()
    assert client.post("/organization-invitations/preview", json={"token": token}).status_code == 410
    with SessionLocal() as db:
        invitation = db.query(OrganizationInvitation).filter_by(id=created.json()["id"]).one()
        assert invitation.status == "expired" and invitation.active_key is None


def test_invitation_feature_disabled_is_rejected(client, monkeypatch):
    monkeypatch.setattr(settings, "ORG_INVITATIONS_ENABLED", False)
    _email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    response = client.post(f"/orgs/{org_id}/invitations", json={"email": "disabled@omnibioai.test"}, headers=headers)
    assert response.status_code == 503


def test_invitation_accept_url_rejects_http_and_internal_hosts(client, monkeypatch):
    _email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    monkeypatch.setattr(settings, "ORG_INVITATIONS_ENABLED", True)
    for accept_url in (
        "http://admin.example.com/invitations/accept",
        "https://obai-admin-acceptance-v1-vite/invitations/accept",
        "https://127.0.0.1/invitations/accept",
        "https://auth.internal/invitations/accept",
    ):
        monkeypatch.setattr(settings, "ORG_INVITATION_ACCEPT_URL", accept_url)
        response = client.post(
            f"/orgs/{org_id}/invitations",
            json={"email": f"url-{uuid.uuid4().hex[:10]}@omnibioai.test"},
            headers=headers,
        )
        assert response.status_code == 503
        assert response.json()["detail"]["code"] == "invitation_configuration"


def test_organization_member_cannot_create_invitations(client, monkeypatch):
    _enable_delivery(monkeypatch)
    _email, _password, admin_headers = _register_login(client)
    org_id = _org(client, admin_headers)
    member_email, _member_password, member_headers = _register_login(client)
    with SessionLocal() as db:
        member = db.query(User).filter_by(email=member_email).one()
        organization = db.query(Organization).filter_by(id=org_id).one()
        role = role_service.get_or_create_role(db, ORG_MEMBER_ROLE, [])
        db.add(OrganizationMembership(organization_id=organization.id, user_id=member.id, status="active", roles=[role]))
        db.commit()
    denied = client.post(f"/orgs/{org_id}/invitations", json={"email": "denied@omnibioai.test"}, headers=member_headers)
    assert denied.status_code == 403
    assert client.get(f"/orgs/{org_id}/invitations", headers=member_headers).status_code == 403
    with SessionLocal() as db:
        denial = db.query(AuditEvent).filter_by(
            event_type="organization_invitation_denied", organization_id=org_id,
        ).order_by(AuditEvent.id.desc()).first()
        assert denial is not None
        assert denial.event_metadata.get("reason") == "authorization_denied"
        assert "token" not in str(denial.event_metadata).lower()


def test_invitation_management_authorization_matrix(client, monkeypatch):
    """Invitation admin routes distinguish non-members, members, managers,
    and platform admins, and keep invitation IDs tenant-bound.
    """
    delivered = _enable_delivery(monkeypatch)
    _owner_a_email, _password_a, owner_a_headers = _register_login(client)
    org_a = _org(client, owner_a_headers)
    owner_b_email, _password_b, owner_b_headers = _register_login(client)
    org_b = _org(client, owner_b_headers)

    # An authenticated user with no membership is forbidden on an existing
    # org's invitation management surface.
    assert client.get(f"/orgs/{org_a}/invitations", headers=owner_b_headers).status_code == 403

    member_email, _member_password, member_headers = _register_login(client)
    manager_email, _manager_password, manager_headers = _register_login(client)
    with SessionLocal() as db:
        org_member_role = role_service.get_or_create_role(db, ORG_MEMBER_ROLE, [])
        manager_role = role_service.get_or_create_role(db, "invitation_manager_test", ["manage_org"])
        for email, role in ((member_email, org_member_role), (manager_email, manager_role)):
            user = db.query(User).filter_by(email=email).one()
            db.add(OrganizationMembership(
                organization_id=org_a, user_id=user.id, status="active", roles=[role],
            ))
        db.commit()

    assert client.get(f"/orgs/{org_a}/invitations", headers=member_headers).status_code == 403
    assert client.get(f"/orgs/{org_a}/invitations", headers=manager_headers).status_code == 200

    platform_email, _platform_password, _platform_headers = _register_login(client)
    with SessionLocal() as db:
        platform_user = db.query(User).filter_by(email=platform_email).one()
        platform_role = role_service.get_or_create_role(db, "platform_admin", ["manage_all_orgs"])
        platform_user.roles.append(platform_role)
        db.commit()
    platform_login = client.post("/auth/login", json={
        "email": platform_email, "password": "TestPassword123!",
    })
    platform_headers = {"Authorization": f"Bearer {platform_login.json()['access_token']}"}
    assert client.get(f"/orgs/{org_a}/invitations", headers=platform_headers).status_code == 200

    # A manager of org A cannot use an invitation ID owned by org B.
    invitee = f"foreign-{uuid.uuid4().hex[:10]}@omnibioai.test"
    created = client.post(
        f"/orgs/{org_b}/invitations", json={"email": invitee}, headers=owner_b_headers,
    )
    assert created.status_code == 201, created.text
    foreign_revoke = client.post(
        f"/orgs/{org_a}/invitations/{created.json()['id']}/revoke", headers=manager_headers,
    )
    assert foreign_revoke.status_code in (404, 403)
    assert delivered["recipient"] == invitee


def test_invitation_management_unknown_organization_remains_404(client):
    _email, _password, headers = _register_login(client)
    response = client.get("/orgs/2147483647/invitations", headers=headers)
    assert response.status_code == 404


def test_delivery_failure_leaves_no_pending_invitation(client, monkeypatch):
    monkeypatch.setattr(settings, "ORG_INVITATIONS_ENABLED", True)
    monkeypatch.setattr(settings, "ORG_INVITATION_ACCEPT_URL", "https://admin.example.com/invitations/accept")
    def fail_delivery(*_args, **_kwargs):
        raise email_delivery_service.EmailDeliveryError("sanitized")
    monkeypatch.setattr(email_delivery_service, "send_organization_invitation", fail_delivery)
    _email, _password, headers = _register_login(client)
    org_id = _org(client, headers)
    invitee = f"failed-{uuid.uuid4().hex[:10]}@omnibioai.test"
    failed = client.post(f"/orgs/{org_id}/invitations", json={"email": invitee}, headers=headers)
    assert failed.status_code == 503
    with SessionLocal() as db:
        assert db.query(OrganizationInvitation).filter_by(invited_email=invitee).count() == 0


def test_new_user_mfa_required_invitation_requires_setup_and_valid_totp(client, monkeypatch):
    delivered = _enable_delivery(monkeypatch)
    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    _email, _password, inviter_headers = _register_login(client)
    org_id = _org(client, inviter_headers)
    _require_org_mfa(org_id)
    invited_email = f"mfa-new-{uuid.uuid4().hex[:10]}@omnibioai.test"
    created = client.post(
        f"/orgs/{org_id}/invitations", json={"email": invited_email}, headers=inviter_headers,
    )
    assert created.status_code == 201
    token = _token_from_delivery(delivered)

    setup = client.post("/organization-invitations/mfa-setup", json={"token": token})
    assert setup.status_code == 200
    secret = _totp_from_uri(setup.json()["otpauth_uri"])
    assert setup.json()["secret"] == secret
    with SessionLocal() as db:
        invite = db.query(OrganizationInvitation).filter_by(id=created.json()["id"]).one()
        assert invite.mfa_secret_encrypted and secret not in invite.mfa_secret_encrypted

    password = "StrongerNewPassphrase!2040"
    missing_mfa = client.post(
        "/organization-invitations/accept", json={"token": token, "password": password},
    )
    assert missing_mfa.status_code == 403
    invalid_code = "000000" if mfa_service._totp_code_at(secret, int(time.time())) != "000000" else "000001"
    rejected = client.post(
        "/organization-invitations/accept",
        json={"token": token, "password": password, "totp_code": invalid_code},
    )
    assert rejected.status_code == 400
    with SessionLocal() as db:
        assert db.query(User).filter_by(email=invited_email).count() == 0
        assert db.query(OrganizationMembership).filter_by(organization_id=org_id).count() == 1

    code = mfa_service._totp_code_at(secret, int(time.time()))
    accepted = client.post(
        "/organization-invitations/accept",
        json={"token": token, "password": password, "totp_code": code},
    )
    assert accepted.status_code == 200, accepted.text
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=invited_email).one()
        invitation = db.query(OrganizationInvitation).filter_by(id=created.json()["id"]).one()
        membership = db.query(OrganizationMembership).filter_by(
            organization_id=org_id, user_id=user.id,
        ).one()
        assert user.mfa_enabled is True
        assert db.query(MFADevice).filter(
            MFADevice.user_id == user.id, MFADevice.verified_at.isnot(None),
        ).count() == 1
        assert membership.status == "active"
        assert invitation.status == "accepted"
        events = db.query(AuditEvent).filter(AuditEvent.organization_id == org_id).all()
        blob = repr([(e.before_state, e.after_state, e.event_metadata) for e in events])
        for sensitive_value in (token, password, secret, code, invalid_code):
            assert sensitive_value not in blob


def test_existing_user_mfa_required_invitation_rejects_missing_and_invalid_step_up(client, monkeypatch):
    delivered = _enable_delivery(monkeypatch)
    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    _inviter_email, _password, inviter_headers = _register_login(client)
    org_id = _org(client, inviter_headers)
    _require_org_mfa(org_id)
    invitee_email, invitee_password, invitee_headers = _register_login(client)
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=invitee_email).one()
        secret = mfa_service.generate_totp_secret()
        user.mfa_enabled = True
        user.mfa_status = "enabled"
        user.mfa_primary_method = "totp"
        db.add(MFADevice(
            user_id=user.id, device_type="totp", label="test device",
            encrypted_secret=crypto.encrypt(secret), verified_at=datetime.utcnow(),
        ))
        db.commit()
    created = client.post(f"/orgs/{org_id}/invitations", json={"email": invitee_email}, headers=inviter_headers)
    assert created.status_code == 201
    token = _token_from_delivery(delivered)
    missing = client.post(
        "/organization-invitations/accept-existing", json={"token": token}, headers=invitee_headers,
    )
    assert missing.status_code == 400
    bad_code = "000000" if mfa_service._totp_code_at(secret, int(time.time())) != "000000" else "000001"
    rejected = client.post(
        "/organization-invitations/accept-existing",
        json={"token": token, "totp_code": bad_code}, headers=invitee_headers,
    )
    assert rejected.status_code == 400
    with SessionLocal() as db:
        assert db.query(OrganizationMembership).filter_by(
            organization_id=org_id, user_id=db.query(User.id).filter_by(email=invitee_email).scalar(),
        ).count() == 0
    code = mfa_service._totp_code_at(secret, int(time.time()))
    accepted = client.post(
        "/organization-invitations/accept-existing",
        json={"token": token, "totp_code": code}, headers=invitee_headers,
    )
    assert accepted.status_code == 200, accepted.text
    with SessionLocal() as db:
        events = db.query(AuditEvent).filter(AuditEvent.organization_id == org_id).all()
        blob = repr([(e.before_state, e.after_state, e.event_metadata) for e in events])
        for sensitive_value in (token, invitee_password, secret, code, bad_code):
            assert sensitive_value not in blob


def test_concurrent_new_user_acceptance_creates_single_membership_and_no_license(client, monkeypatch):
    from app.db.models import LicenseKey

    delivered = _enable_delivery(monkeypatch)
    _email, _password, inviter_headers = _register_login(client)
    org_id = _org(client, inviter_headers)
    invited_email = f"race-{uuid.uuid4().hex[:10]}@omnibioai.test"
    created = client.post(f"/orgs/{org_id}/invitations", json={"email": invited_email}, headers=inviter_headers)
    assert created.status_code == 201
    token = _token_from_delivery(delivered)
    password = "StrongerRacePassphrase!2041"
    barrier = threading.Barrier(2)

    def accept():
        barrier.wait(timeout=5)
        return client.post("/organization-invitations/accept", json={"token": token, "password": password})

    with ThreadPoolExecutor(max_workers=2) as executor:
        responses = list(executor.map(lambda _index: accept(), range(2)))
    assert all(response.status_code in (200, 409) for response in responses), [r.status_code for r in responses]
    with SessionLocal() as db:
        user = db.query(User).filter_by(email=invited_email).one()
        assert db.query(OrganizationMembership).filter_by(
            organization_id=org_id, user_id=user.id, status="active",
        ).count() == 1
        invitation = db.query(OrganizationInvitation).filter_by(id=created.json()["id"]).one()
        assert invitation.status == "accepted" and invitation.accepted_user_id == user.id
        assert db.query(LicenseKey).filter_by(user_id=user.id, organization_id=org_id).count() == 0
