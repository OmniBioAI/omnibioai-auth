"""Administrator-authorized canonical email change workflow."""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, LicenseKey, OAuthAccount, RefreshToken, Role, User, UserSession

_engine = create_engine("sqlite:///./test.db")
_Session = sessionmaker(bind=_engine)


def _auth(token):
    return {"Authorization": f"Bearer {token}"}


def _register_login(client, prefix):
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    login = client.post("/auth/login", json={"email": email, "password": password})
    assert login.status_code == 200
    identity = client.post("/auth/validate", json={"token": login.json()["access_token"]}).json()
    return {"id": identity["user_id"], "email": email, "password": password, **login.json()}


def _platform_owner(client):
    owner = _register_login(client, "email-owner")
    db = _Session()
    try:
        user = db.query(User).filter(User.id == owner["id"]).one()
        role = db.query(Role).filter(Role.name == "platform_admin").one()
        user.roles.append(role)
        db.commit()
    finally:
        db.close()
    login = client.post("/auth/login", json={"email": owner["email"], "password": owner["password"]})
    owner.update(login.json())
    owner["headers"] = _auth(owner["access_token"])
    return owner


def test_unauthorized_email_change_is_rejected(client):
    caller = _register_login(client, "email-ordinary")
    target = _register_login(client, "email-target")
    response = client.patch(
        f"/platform/users/{target['id']}/email",
        json={"email": f"changed-{uuid.uuid4().hex[:8]}@omnibioai.test", "reason": "test"},
        headers=_auth(caller["access_token"]),
    )
    assert response.status_code == 403


def test_invalid_email_and_collision_are_rejected(client):
    owner = _platform_owner(client)
    target = _register_login(client, "email-collision-target")
    existing = _register_login(client, "email-collision-existing")
    invalid = client.patch(
        f"/platform/users/{target['id']}/email",
        json={"email": "not-an-email", "reason": "test"}, headers=owner["headers"],
    )
    assert invalid.status_code == 422
    collision = client.patch(
        f"/platform/users/{target['id']}/email",
        json={"email": existing["email"], "reason": "test"}, headers=owner["headers"],
    )
    assert collision.status_code == 409


def test_email_change_preserves_relationships_audits_and_revokes_stale_sessions(client):
    owner = _platform_owner(client)
    target = _register_login(client, "email-preserve")
    old_email = target["email"]
    new_email = f"email-preserved-{uuid.uuid4().hex[:8]}@omnibioai.test"

    db = _Session()
    try:
        user = db.query(User).filter(User.id == target["id"]).one()
        role_ids = {r.id for r in user.roles}
        db.add(OAuthAccount(user_id=user.id, provider="google", provider_user_id=uuid.uuid4().hex, email=old_email))
        db.add(LicenseKey(key=f"OMNI-{uuid.uuid4().hex[:4].upper()}-AAAA-BBBB-CCCC", user_id=user.id, email=old_email))
        db.commit()
    finally:
        db.close()

    changed = client.patch(
        f"/platform/users/{target['id']}/email",
        json={"email": new_email.upper(), "reason": "canonical domain correction"},
        headers=owner["headers"],
    )
    assert changed.status_code == 200, changed.text
    assert changed.json()["id"] == target["id"]
    assert changed.json()["email"] == new_email

    db = _Session()
    try:
        user = db.query(User).filter(User.id == target["id"]).one()
        assert {r.id for r in user.roles} == role_ids
        assert db.query(OAuthAccount).filter(OAuthAccount.user_id == user.id).one().email == new_email
        assert db.query(LicenseKey).filter(LicenseKey.user_id == user.id).one().email == new_email
        assert db.query(RefreshToken).filter(RefreshToken.user_id == user.id, RefreshToken.revoked.is_(False)).count() == 0
        sessions = db.query(UserSession).filter(UserSession.user_id == user.id).all()
        assert sessions and all(s.status == "revoked" for s in sessions)
        event = db.query(AuditEvent).filter(
            AuditEvent.event_type == "user_email_changed", AuditEvent.target_user_id == user.id
        ).one()
        assert event.before_state == {"email": old_email}
        assert event.after_state == {"email": new_email}
    finally:
        db.close()

    assert client.get("/orgs", headers=_auth(target["access_token"])).status_code == 401
    assert client.post("/auth/refresh", json={"refresh_token": target["refresh_token"]}).status_code == 401

