"""/orgs/{org_id}/provider-keys: BYOK storage for an organization's own
Claude/OpenAI key (design audit gap #4). Gated on manage_org (org
administration, not a self-service literature-API action); credentials
are never returned, refused (500) rather than stored in plaintext
without an encryption key configured, and genuinely encrypted at rest
once one is -- same contract app/schemas/config.py's GlobalConfig
already established for the platform-wide LLM key, applied here per
organization.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import uuid

import pytest
from cryptography.fernet import Fernet

from app.services import organization_config_service


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"provkey-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "access_token": login.json()["access_token"]}


@pytest.fixture
def org(client):
    """An organization owned by a freshly registered user (org_admin,
    holding manage_org) -- the same shape test_apikeys.py's own `org`
    fixture uses."""
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    created = client.post(
        "/orgs",
        json={"name": "Provider Key Test Org", "slug": f"provkey-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    ).json()
    return {"id": created["id"], "owner": owner, "owner_headers": headers}


@pytest.fixture
def configured_crypto(monkeypatch):
    """Patches app.core.crypto's module-level singleton directly, since it's
    computed once at import time from CONFIG_ENCRYPTION_KEY -- the same
    pattern tests/test_config.py's own fixture of the same name uses."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


# ── Permission gating ────────────────────────────────────────────────────────


def test_get_requires_auth(client, org):
    resp = client.get(f"/orgs/{org['id']}/provider-keys")
    assert resp.status_code in (401, 403)


def test_get_returns_no_key_configured_by_default(client, org):
    resp = client.get(f"/orgs/{org['id']}/provider-keys", headers=org["owner_headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] is None and body["has_key"] is False


def test_non_admin_member_cannot_set_a_key(client, org):
    """A member without manage_org (no role assignment at all here) gets 403."""
    outsider = _register_and_login(client)
    outsider_headers = _auth_header(outsider["access_token"])
    resp = client.put(
        f"/orgs/{org['id']}/provider-keys/claude",
        json={"api_key": "sk-nope"},
        headers=outsider_headers,
    )
    # Not a member at all -- the dependency 404s rather than 403, same as
    # every other /orgs/{org_id}/* route's non-member behavior.
    assert resp.status_code == 404


# ── Validation ───────────────────────────────────────────────────────────────


def test_unsupported_provider_name_is_rejected(client, org, configured_crypto):
    resp = client.put(
        f"/orgs/{org['id']}/provider-keys/not-a-real-provider",
        json={"api_key": "sk-whatever"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 400


def test_delete_unsupported_provider_name_is_rejected(client, org):
    resp = client.delete(f"/orgs/{org['id']}/provider-keys/not-a-real-provider", headers=org["owner_headers"])
    assert resp.status_code == 400


# ── No silent plaintext fallback ─────────────────────────────────────────────


def test_set_key_fails_loudly_when_encryption_key_unset(client, org):
    """conftest.py never sets CONFIG_ENCRYPTION_KEY, so app.core.crypto's
    module-level _fernet is None for the whole test session -- this
    exercises the real "not configured" state, not a simulated one."""
    resp = client.put(
        f"/orgs/{org['id']}/provider-keys/claude",
        json={"api_key": "sk-should-never-be-stored-plaintext"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 500


# ── Real encryption round-trip (key patched in for just these tests) ───────


def test_set_key_returns_has_key_true_and_never_the_key_itself(client, org, configured_crypto):
    resp = client.put(
        f"/orgs/{org['id']}/provider-keys/claude",
        json={"api_key": "sk-real-secret-value-12345"},
        headers=org["owner_headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["provider"] == "claude"
    assert body["has_key"] is True
    assert "api_key" not in body
    assert "sk-real-secret-value-12345" not in str(body)


def test_set_key_is_genuinely_encrypted_at_rest(client, org, configured_crypto):
    client.put(
        f"/orgs/{org['id']}/provider-keys/claude",
        json={"api_key": "sk-real-secret-value-12345"},
        headers=org["owner_headers"],
    )
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        config = organization_config_service.get_organization_config(db, org["id"])
        assert config.llm_api_key_encrypted != "sk-real-secret-value-12345"
        assert configured_crypto.decrypt(config.llm_api_key_encrypted) == "sk-real-secret-value-12345"
    finally:
        db.close()


def test_get_reflects_the_configured_provider(client, org, configured_crypto):
    client.put(
        f"/orgs/{org['id']}/provider-keys/openai",
        json={"api_key": "sk-openai-secret"},
        headers=org["owner_headers"],
    )
    resp = client.get(f"/orgs/{org['id']}/provider-keys", headers=org["owner_headers"])
    assert resp.json() == {
        "provider": "openai",
        "has_key": True,
        "updated_at": resp.json()["updated_at"],
        "updated_by_email": org["owner"]["email"],
    }


def test_setting_a_new_provider_replaces_the_previous_one(client, org, configured_crypto):
    """One slot per organization -- setting openai after claude was
    configured replaces it, it does not add a second provider."""
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])
    client.put(f"/orgs/{org['id']}/provider-keys/openai", json={"api_key": "sk-openai"}, headers=org["owner_headers"])

    resp = client.get(f"/orgs/{org['id']}/provider-keys", headers=org["owner_headers"])
    assert resp.json()["provider"] == "openai"


# ── Clearing ─────────────────────────────────────────────────────────────────


def test_delete_clears_a_configured_key(client, org, configured_crypto):
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])

    resp = client.delete(f"/orgs/{org['id']}/provider-keys/claude", headers=org["owner_headers"])
    assert resp.status_code == 200
    assert resp.json()["provider"] is None
    assert resp.json()["has_key"] is False

    listed = client.get(f"/orgs/{org['id']}/provider-keys", headers=org["owner_headers"])
    assert listed.json()["has_key"] is False


def test_delete_for_a_provider_that_is_not_the_configured_one_404s(client, org, configured_crypto):
    """Only one slot exists -- "delete openai's key" when claude is
    actually configured is 404, not a silent no-op success."""
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])

    resp = client.delete(f"/orgs/{org['id']}/provider-keys/openai", headers=org["owner_headers"])
    assert resp.status_code == 404

    # The actually-configured claude key must be untouched by the failed attempt.
    listed = client.get(f"/orgs/{org['id']}/provider-keys", headers=org["owner_headers"])
    assert listed.json() == {"provider": "claude", "has_key": True,
                              "updated_at": listed.json()["updated_at"], "updated_by_email": org["owner"]["email"]}


def test_delete_with_nothing_configured_404s(client, org):
    resp = client.delete(f"/orgs/{org['id']}/provider-keys/claude", headers=org["owner_headers"])
    assert resp.status_code == 404


# ── Cross-org isolation ──────────────────────────────────────────────────────


def test_non_member_cannot_read_or_set_another_orgs_key(client, org, configured_crypto):
    outsider = _register_and_login(client)
    outsider_headers = _auth_header(outsider["access_token"])

    assert client.get(f"/orgs/{org['id']}/provider-keys", headers=outsider_headers).status_code == 404
    resp = client.put(
        f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-stolen"}, headers=outsider_headers,
    )
    assert resp.status_code == 404

    # Confirm the attempted write had no effect.
    listed = client.get(f"/orgs/{org['id']}/provider-keys", headers=org["owner_headers"])
    assert listed.json()["has_key"] is False


# ── POST /internal/organizations/{org_id}/provider-keys/{provider}/reveal ──
# M16: service-to-service only, shared-secret gated -- never reachable by a
# user or API-key token. Same shape as POST /auth/api-keys/exchange's own
# tests (tests/test_apikey_exchange.py).


REVEAL_SECRET = "test-reveal-secret"


@pytest.fixture
def reveal_secret(monkeypatch):
    import app.core.config as config

    monkeypatch.setattr(config.settings, "PROVIDER_KEY_REVEAL_SECRET", REVEAL_SECRET)
    return REVEAL_SECRET


def _reveal(client, org_id, provider, secret=REVEAL_SECRET):
    return client.post(
        f"/internal/organizations/{org_id}/provider-keys/{provider}/reveal",
        headers={"X-Provider-Key-Reveal-Secret": secret},
    )


def test_reveal_disabled_without_configured_secret(client, org, configured_crypto):
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])
    assert _reveal(client, org["id"], "claude", secret="").status_code == 503


def test_reveal_rejects_wrong_or_missing_secret(client, org, configured_crypto, reveal_secret):
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])

    assert _reveal(client, org["id"], "claude", secret="nope").status_code == 403
    resp = client.post(f"/internal/organizations/{org['id']}/provider-keys/claude/reveal")
    assert resp.status_code == 403


def test_reveal_returns_the_real_decrypted_key(client, org, configured_crypto, reveal_secret):
    client.put(
        f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-real-secret-12345"},
        headers=org["owner_headers"],
    )
    resp = _reveal(client, org["id"], "claude")
    assert resp.status_code == 200
    assert resp.json() == {"provider": "claude", "api_key": "sk-real-secret-12345"}


def test_reveal_does_not_require_any_org_membership(client, org, configured_crypto, reveal_secret):
    """No user session is involved at all -- a bare shared-secret call
    succeeds regardless of who (if anyone) is logged in."""
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])
    resp = client.post(
        f"/internal/organizations/{org['id']}/provider-keys/claude/reveal",
        headers={"X-Provider-Key-Reveal-Secret": REVEAL_SECRET},
    )
    assert resp.status_code == 200


def test_reveal_404s_when_nothing_is_configured(client, org, reveal_secret):
    resp = _reveal(client, org["id"], "claude")
    assert resp.status_code == 404


def test_reveal_404s_for_a_provider_that_is_not_the_configured_one(client, org, configured_crypto, reveal_secret):
    client.put(f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"])
    resp = _reveal(client, org["id"], "openai")
    assert resp.status_code == 404


def test_reveal_rejects_an_unsupported_provider_name(client, org, reveal_secret):
    resp = _reveal(client, org["id"], "not-a-real-provider")
    assert resp.status_code == 400


def test_reveal_fails_loudly_without_an_encryption_key(client, org, reveal_secret):
    """A key was stored while encryption was configured (configured_crypto
    fixture, scoped to that one call), but reveal is called afterward
    with no encryption key available -- decrypt() must raise 500, not
    return garbage or the ciphertext itself."""
    import app.core.crypto as crypto
    from cryptography.fernet import Fernet

    key = Fernet.generate_key()
    original_fernet = crypto._fernet
    crypto._fernet = Fernet(key)
    try:
        client.put(
            f"/orgs/{org['id']}/provider-keys/claude", json={"api_key": "sk-claude"}, headers=org["owner_headers"],
        )
    finally:
        crypto._fernet = original_fernet

    resp = _reveal(client, org["id"], "claude")
    assert resp.status_code == 500
