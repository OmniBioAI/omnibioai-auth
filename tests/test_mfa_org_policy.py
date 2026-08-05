"""PR11.5.5 (Enterprise Organization MFA Policy). See
docs/pr11-mfa-org-policy-discovery.md for the full design rationale.
Follows this repo's established convention (tests/test_org_sso.py,
tests/test_mfa_login_challenge.py): real HTTP calls through real
routes/services against the shared sqlite test DB, audit rows read back
via a second, direct session -- never mocks of auth_service/mfa_service
themselves. Each test file is self-contained (local helpers), matching
this repo's per-file duplication convention.
"""
import os
import time
import urllib.parse
import uuid

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent
from app.services import mfa_service

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"mfa-org-policy-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, "access_token": login.json()["access_token"]}


def _user_id(client, access_token):
    return client.post("/auth/validate", json={"token": access_token}).json()["user_id"]


@pytest.fixture(scope="session")
def admin_token(client):
    resp = client.post(
        "/auth/login",
        json={"email": "admin@omnibioai", "password": os.environ["ADMIN_BOOTSTRAP_PASSWORD"]},
    )
    assert resp.status_code == 200
    return resp.json()["access_token"]


@pytest.fixture
def admin_headers(admin_token):
    return _auth_header(admin_token)


def _grant_platform_admin(email: str) -> None:
    """manage_all_orgs lives on the "platform_admin" role, never assigned
    to the bootstrap admin@omnibioai account by default (see
    app/db/init_admin.py::ensure_platform_admin_role's own docstring) --
    distinct from admin@omnibioai's "admin" role, which only holds
    override_sso_enforcement. Same technique tests/test_orgs.py's own
    _grant_platform_admin uses for the identical reason."""
    from app.db.models import Role, User

    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None, "ensure_platform_admin_role should have created this at startup"
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


@pytest.fixture
def platform_admin_headers(client):
    """A user holding manage_all_orgs -- the permission this PR's own
    break-glass override routes require, per the discovery doc SS6.
    Deliberately not admin_headers/admin@omnibioai -- see
    _grant_platform_admin's docstring."""
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post(
        "/auth/login", json={"email": admin["email"], "password": admin["password"]}
    ).json()
    return _auth_header(relogged["access_token"])


@pytest.fixture
def org(client):
    """Owner becomes an org_admin member with status="active" (see
    org_service.create_organization), so resolve_primary_membership picks
    them up immediately -- unlike org_service.invite_member's
    status="invited" members, which this codebase has no accept-flow for
    yet. Using the owner as the test subject for login-enforcement tests
    below avoids that unrelated gap entirely."""
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "MFA Policy Test Org", "slug": f"mfa-policy-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


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
                "organization_id": r.organization_id, "resource_type": r.resource_type,
                "resource_id": r.resource_id, "before_state": r.before_state,
                "after_state": r.after_state, "metadata": r.event_metadata,
            }
            for r in rows
        ]
    finally:
        db.close()


def _assert_no_secret_leakage(event: dict) -> None:
    blob = str(event["before_state"]) + str(event["after_state"]) + str(event["metadata"])
    for forbidden in ("secret", "code", "token", "recovery_code", "otpauth://", "challenge_token"):
        assert forbidden not in blob.lower(), f"{forbidden!r} leaked into audit event: {event}"


@pytest.fixture
def configured_crypto(monkeypatch):
    """Same technique as tests/test_mfa_login_challenge.py's fixture of
    the same name -- app.core.crypto's Fernet instance is computed once
    at import time, so patch the already-imported module's singleton."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def _extract_secret(otpauth_uri: str) -> str:
    return urllib.parse.parse_qs(urllib.parse.urlparse(otpauth_uri).query)["secret"][0]


def _enable_mfa(client, headers) -> str:
    """Enrolls + verifies a TOTP device for the caller. Requires
    configured_crypto to be in effect."""
    enroll = client.post("/users/me/mfa/totp/enroll", headers=headers).json()
    secret = _extract_secret(enroll["otpauth_uri"])
    code = mfa_service._totp_code_at(secret, int(time.time()))
    verify = client.post(
        "/users/me/mfa/totp/verify", json={"device_id": enroll["device_id"], "code": code}, headers=headers
    )
    assert verify.status_code == 200
    return secret


# ── 1. Policy CRUD ────────────────────────────────────────────────────────


def test_create_policy_defaults_to_not_required(client, org):
    resp = client.post(f"/orgs/{org['id']}/mfa-policy", json={}, headers=org["owner_headers"])
    assert resp.status_code == 201
    data = resp.json()
    assert data["required"] is False
    assert data["override_active"] is False
    assert data["enabled_at"] is None


def test_create_policy_required_true_sets_enabled_at_and_emits_event(client, org):
    resp = client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    assert resp.status_code == 201
    data = resp.json()
    assert data["required"] is True
    assert data["enabled_at"] is not None

    events = _events(organization_id=org["id"], event_type="mfa_policy_enabled")
    assert len(events) == 1
    assert events[0]["after_state"] == {"required": True}


def test_create_second_policy_for_same_org_rejected(client, org):
    first = client.post(f"/orgs/{org['id']}/mfa-policy", json={}, headers=org["owner_headers"])
    assert first.status_code == 201

    second = client.post(f"/orgs/{org['id']}/mfa-policy", json={}, headers=org["owner_headers"])
    assert second.status_code == 409


def test_get_policy_404_when_none_exists(client, org):
    resp = client.get(f"/orgs/{org['id']}/mfa-policy", headers=org["owner_headers"])
    assert resp.status_code == 404


def test_patch_enable_policy_emits_event_with_reason(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": False}, headers=org["owner_headers"])

    resp = client.patch(
        f"/orgs/{org['id']}/mfa-policy",
        json={"required": True, "reason": "compliance rollout"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    assert resp.json()["required"] is True

    events = _events(organization_id=org["id"], event_type="mfa_policy_enabled")
    assert len(events) == 1
    assert events[0]["metadata"]["reason"] == "compliance rollout"


def test_patch_disable_policy_emits_event(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    resp = client.patch(
        f"/orgs/{org['id']}/mfa-policy", json={"required": False}, headers=org["owner_headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["required"] is False

    events = _events(organization_id=org["id"], event_type="mfa_policy_disabled")
    assert len(events) == 1


def test_patch_with_no_actual_flip_emits_no_event(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    before = len(_events(organization_id=org["id"]))

    resp = client.patch(
        f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"]
    )
    assert resp.status_code == 200
    after = len(_events(organization_id=org["id"]))
    assert after == before


def test_member_without_manage_sso_receives_403(client, org, admin_headers):
    owner_id = _user_id(client, org["owner"]["access_token"])

    narrow_role = f"mfa-policy-narrow-{uuid.uuid4().hex[:8]}"
    client.post("/roles", json={"name": narrow_role, "permissions": ["manage_org"]}, headers=admin_headers)
    downgrade = client.put(
        f"/orgs/{org['id']}/members/{owner_id}/roles",
        json={"roles": [narrow_role]},
        headers=org["owner_headers"],
    )
    assert downgrade.status_code == 200

    resp = client.post(f"/orgs/{org['id']}/mfa-policy", json={}, headers=org["owner_headers"])
    assert resp.status_code == 403


# ── 2. Organization isolation ────────────────────────────────────────────


def test_org_a_cannot_view_org_b_policy(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    client.post(
        "/orgs",
        json={"name": "Org B", "slug": f"mfa-policy-org-b-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    )

    resp = client.get(f"/orgs/{org['id']}/mfa-policy", headers=other_headers)
    assert resp.status_code == 404


def test_org_a_cannot_update_org_b_policy(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": False}, headers=org["owner_headers"])

    other_owner = _register_and_login(client)
    other_headers = _auth_header(other_owner["access_token"])
    client.post(
        "/orgs",
        json={"name": "Org C", "slug": f"mfa-policy-org-c-{uuid.uuid4().hex[:8]}"},
        headers=other_headers,
    )

    resp = client.patch(
        f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=other_headers
    )
    assert resp.status_code == 404

    still_there = client.get(f"/orgs/{org['id']}/mfa-policy", headers=org["owner_headers"])
    assert still_there.json()["required"] is False


# ── 3. Authentication -- the compatibility matrix from the discovery doc ──


def test_personal_mfa_enabled_policy_absent_still_challenges(client, org, configured_crypto):
    """Personal MFA (mirrors PR11.5.3's own unaffected behavior) --
    no org policy configured at all."""
    _enable_mfa(client, org["owner_headers"])

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 200
    assert resp.json()["mfa_required"] is True


def test_no_mfa_no_policy_normal_login_unchanged(client):
    user = _register_and_login(client)
    resp = client.post("/auth/login", json={"email": user["email"], "password": user["password"]})
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "mfa_required" not in data


def test_personal_mfa_enabled_policy_enabled_challenges_not_enrollment_required(client, org, configured_crypto):
    """Personal MFA always wins, per the discovery doc's compatibility
    table -- org policy is moot once the user has their own TOTP."""
    _enable_mfa(client, org["owner_headers"])
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 200
    assert resp.json()["mfa_required"] is True


def test_no_personal_mfa_policy_required_returns_enrollment_required(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 403
    detail = resp.json()["detail"]
    assert detail["error"] == "mfa_enrollment_required"


def test_no_personal_mfa_policy_disabled_normal_login(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": False}, headers=org["owner_headers"])

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "mfa_required" not in data


def test_license_login_respects_org_mfa_policy(client, org, admin_headers):
    """Closes the PR11.5 discovery finding: routes_license.py already
    funnels through generate_tokens_or_mfa_challenge since PR11.5.3, so
    org policy enforcement applies here too, with no license-specific
    bypass. See docs/pr11-mfa-org-policy-discovery.md SS5."""
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    gen = client.post(
        "/license/generate",
        json={"email": org["owner"]["email"], "plan": "pro"},
        headers=admin_headers,
    )
    key = gen.json()["key"]

    resp = client.post(
        "/license/validate",
        json={"key": key, "email": org["owner"]["email"], "platform": "web"},
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "mfa_enrollment_required"


# ── 4. Break-glass override ─────────────────────────────────────────────


def test_override_requires_manage_all_orgs_not_org_admin(client, org):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    resp = client.post(
        f"/orgs/{org['id']}/mfa-policy/override",
        json={"reason": "org admin trying to self-serve"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 403


def test_override_active_bypasses_enrollment_requirement(client, org, platform_admin_headers):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])

    override = client.post(
        f"/orgs/{org['id']}/mfa-policy/override",
        json={"reason": "locked out during rollout"},
        headers=platform_admin_headers,
    )
    assert override.status_code == 200
    assert override.json()["required"] is True  # org's own setting untouched
    assert override.json()["override_active"] is True

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert "mfa_required" not in data


def test_override_removed_restores_enforcement(client, org, platform_admin_headers):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    client.post(
        f"/orgs/{org['id']}/mfa-policy/override", json={"reason": "temporary"}, headers=platform_admin_headers
    )

    cleared = client.delete(f"/orgs/{org['id']}/mfa-policy/override", headers=platform_admin_headers)
    assert cleared.status_code == 200
    assert cleared.json()["override_active"] is False

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 403
    assert resp.json()["detail"]["error"] == "mfa_enrollment_required"


def test_override_active_does_not_disable_personal_mfa(client, org, platform_admin_headers, configured_crypto):
    """Discovery doc SS3: the override only ever suspends the org's own
    requirement -- a user's independently-chosen personal MFA is never
    affected by it."""
    _enable_mfa(client, org["owner_headers"])
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    client.post(
        f"/orgs/{org['id']}/mfa-policy/override", json={"reason": "unrelated org rollout"},
        headers=platform_admin_headers,
    )

    resp = client.post(
        "/auth/login", json={"email": org["owner"]["email"], "password": org["owner"]["password"]}
    )
    assert resp.status_code == 200
    assert resp.json()["mfa_required"] is True


# ── 5. Audit / security validation ──────────────────────────────────────


def test_override_events_contain_org_actor_reason_and_no_secrets(client, org, platform_admin_headers):
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    client.post(
        f"/orgs/{org['id']}/mfa-policy/override", json={"reason": "incident-1234"},
        headers=platform_admin_headers,
    )
    client.delete(f"/orgs/{org['id']}/mfa-policy/override", headers=platform_admin_headers)

    created = _events(organization_id=org["id"], event_type="mfa_policy_override_created")
    removed = _events(organization_id=org["id"], event_type="mfa_policy_override_removed")
    assert len(created) == 1
    assert len(removed) == 1

    for event in created + removed:
        assert event["organization_id"] == org["id"]
        assert event["actor_user_id"] is not None
        assert event["metadata"]["reason"] is not None
        _assert_no_secret_leakage(event)

    assert created[0]["metadata"]["reason"] == "incident-1234"
    # Removal event carries the *outgoing* override's own reason, per the
    # discovery doc's SS7 -- context about what's being closed out.
    assert removed[0]["metadata"]["reason"] == "incident-1234"


def test_policy_enable_disable_events_no_secret_leakage(client, org, configured_crypto):
    _enable_mfa(client, org["owner_headers"])
    client.post(f"/orgs/{org['id']}/mfa-policy", json={"required": True}, headers=org["owner_headers"])
    client.patch(
        f"/orgs/{org['id']}/mfa-policy", json={"required": False}, headers=org["owner_headers"]
    )

    events = _events(organization_id=org["id"])
    assert len(events) >= 2
    for event in events:
        _assert_no_secret_leakage(event)
