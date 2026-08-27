"""#443: POST /service/mint-user-token. Covers the least-privilege
boundary (service_token.mint is not implied by any other permission --
mirrors test_saml_enforcement.py's "org admin cannot self-service the
override" boundary test, applied here as "an ordinary permission holder
cannot mint tokens"), the lightweight-mint design decision (no session/
refresh-token row, no last_login_at write), JIT-provisioning vs.
existing-user reuse, and the audit trail.
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import decode_token
from app.db.models import AuditEvent, RefreshToken, User, UserSession
from app.services.role_service import get_or_create_role

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None, password="TestPassword123!"):
    email = email or f"mint-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _grant_role(email: str, role_name: str, permission_names: list[str]) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = get_or_create_role(db, role_name, permission_names)
        if role not in user.roles:
            user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _mint_caller(client):
    """A real user holding service_token.mint via a dedicated role --
    mirrors ensure_bio_agent_service_role's real shape, built directly in
    the test DB since the test app boots without BIO_AGENT_SVC_EMAIL set."""
    caller = _register_and_login(client)
    _grant_role(caller["email"], "bio_agent_service", ["service_token.mint"])
    relogged = client.post(
        "/auth/login", json={"email": caller["email"], "password": caller["password"]}
    ).json()
    return {**caller, "access_token": relogged["access_token"]}


def _user_row(email: str):
    db = _DirectSession()
    try:
        return db.query(User).filter(User.email == email).first()
    finally:
        db.close()


# ── Least-privilege boundary ─────────────────────────────────────────────────


def test_mint_rejected_for_a_caller_with_no_permissions_at_all(client):
    caller = _register_and_login(client)
    resp = client.post(
        "/service/mint-user-token",
        json={"email": "someone@example.test"},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 403


def test_mint_rejected_for_scientist_role_holder(client):
    """The one thing service_token.mint must never be implied by: an
    ordinary "scientist" (workflow.execute) holder -- the same role
    svc-bio-agent itself holds for its other TES calls -- must not
    incidentally gain the ability to mint tokens for other users."""
    caller = _register_and_login(client)
    _grant_role(caller["email"], "scientist", ["workflow.execute"])
    relogged = client.post(
        "/auth/login", json={"email": caller["email"], "password": caller["password"]}
    ).json()

    resp = client.post(
        "/service/mint-user-token",
        json={"email": "someone@example.test"},
        headers=_auth_header(relogged["access_token"]),
    )
    assert resp.status_code == 403


# ── Happy path ────────────────────────────────────────────────────────────────


def test_mint_succeeds_for_a_caller_holding_service_token_mint(client):
    caller = _mint_caller(client)
    target_email = f"chat-user-{uuid.uuid4().hex[:8]}@example.test"

    resp = client.post(
        "/service/mint-user-token",
        json={"email": target_email},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["token_type"] == "bearer"
    assert body["expires_in"] == 15 * 60  # settings.ACCESS_TOKEN_EXPIRE_MINUTES default
    assert body["access_token"]


def test_minted_token_carries_the_target_users_own_identity_not_the_callers(client):
    caller = _mint_caller(client)
    target_email = f"chat-user-{uuid.uuid4().hex[:8]}@example.test"

    resp = client.post(
        "/service/mint-user-token",
        json={"email": target_email},
        headers=_auth_header(caller["access_token"]),
    )
    claims = decode_token(resp.json()["access_token"])
    target_user = _user_row(target_email)

    assert claims["email"] == target_email
    assert claims["sub"] == str(target_user.id)
    assert claims["sub"] != str(_user_row(caller["email"]).id)
    assert claims["auth_method"] == "service_mint"


# ── User resolution: JIT-provision vs. reuse existing ───────────────────────


def test_mint_jit_provisions_a_real_user_for_an_unknown_email(client):
    caller = _mint_caller(client)
    target_email = f"brand-new-chat-user-{uuid.uuid4().hex[:8]}@example.test"
    assert _user_row(target_email) is None

    resp = client.post(
        "/service/mint-user-token",
        json={"email": target_email},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 200
    created = _user_row(target_email)
    assert created is not None
    assert created.hashed_password is None  # never a password account


def test_mint_reuses_an_existing_account_rather_than_duplicating_it(client):
    caller = _mint_caller(client)
    existing = _register_and_login(client)

    resp = client.post(
        "/service/mint-user-token",
        json={"email": existing["email"]},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 200
    claims = decode_token(resp.json()["access_token"])
    assert claims["sub"] == str(_user_row(existing["email"]).id)

    db = _DirectSession()
    try:
        count = db.query(User).filter(User.email == existing["email"]).count()
    finally:
        db.close()
    assert count == 1


# ── Lightweight-mint design decision: no session churn ──────────────────────


def test_mint_creates_no_refresh_token_or_session_row(client):
    caller = _mint_caller(client)
    target_email = f"chat-user-{uuid.uuid4().hex[:8]}@example.test"

    resp = client.post(
        "/service/mint-user-token",
        json={"email": target_email},
        headers=_auth_header(caller["access_token"]),
    )
    assert resp.status_code == 200
    target_user = _user_row(target_email)

    db = _DirectSession()
    try:
        assert db.query(RefreshToken).filter(RefreshToken.user_id == target_user.id).count() == 0
        assert db.query(UserSession).filter(UserSession.user_id == target_user.id).count() == 0
    finally:
        db.close()


def test_mint_does_not_write_last_login_at(client):
    caller = _mint_caller(client)
    target_email = f"chat-user-{uuid.uuid4().hex[:8]}@example.test"

    client.post(
        "/service/mint-user-token",
        json={"email": target_email},
        headers=_auth_header(caller["access_token"]),
    )
    target_user = _user_row(target_email)
    assert target_user.last_login_at is None


# ── Audit trail ───────────────────────────────────────────────────────────────


def test_mint_is_audit_logged_with_actor_and_target(client):
    caller = _mint_caller(client)
    target_email = f"chat-user-{uuid.uuid4().hex[:8]}@example.test"

    client.post(
        "/service/mint-user-token",
        json={"email": target_email},
        headers=_auth_header(caller["access_token"]),
    )
    target_user = _user_row(target_email)
    caller_user = _user_row(caller["email"])

    db = _DirectSession()
    try:
        events = db.query(AuditEvent).filter(AuditEvent.target_user_id == target_user.id).all()
    finally:
        db.close()

    assert len(events) == 1
    event = events[0]
    assert event.event_type == "service_token_minted"
    assert event.actor_user_id == caller_user.id
    assert event.actor_user_id != target_user.id
    assert event.event_metadata["target_email"] == target_email
