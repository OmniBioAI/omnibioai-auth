"""The /auth/config endpoint: reading requires authentication and updating
requires the manage_config permission; credential fields are never returned and
are refused (500) rather than stored in plaintext when no encryption key is
configured; with a key they are stored encrypted; and app.core.crypto refuses
to load a malformed key.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import importlib
import os
import uuid

import pytest
from cryptography.fernet import Fernet


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


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


@pytest.fixture
def user_headers(client):
    email = f"config-test-{uuid.uuid4().hex[:8]}@omnibioai.test"
    resp = client.post("/auth/register", json={"email": email, "password": "TestPassword123!"})
    assert resp.status_code == 200
    resp = client.post("/auth/login", json={"email": email, "password": "TestPassword123!"})
    assert resp.status_code == 200
    return _auth_header(resp.json()["access_token"])


# ── Permission gating ────────────────────────────────────────────────────────

def test_get_config_requires_auth(client):
    """GET /auth/config without credentials returns 401."""
    resp = client.get("/auth/config")
    assert resp.status_code == 401


def test_get_config_allowed_for_any_authenticated_user(client, user_headers):
    """GET /auth/config returns 200 for an ordinary authenticated user and never includes
    llm_api_key or cloud_credentials.
    """
    resp = client.get("/auth/config", headers=user_headers)
    assert resp.status_code == 200
    # Never present, regardless of role -- write-only fields.
    assert "llm_api_key" not in resp.json()
    assert "cloud_credentials" not in resp.json()


def test_update_config_requires_manage_config_permission(client, user_headers):
    """PUT /auth/config by a user without the manage_config permission returns 403."""
    resp = client.put("/auth/config", json={"work_directory": "/data/work"}, headers=user_headers)
    assert resp.status_code == 403


def test_update_config_allowed_for_admin(client, admin_headers):
    """An admin can PUT /auth/config and the updated work_directory is returned."""
    resp = client.put("/auth/config", json={"work_directory": "/data/work-admin"}, headers=admin_headers)
    assert resp.status_code == 200
    assert resp.json()["work_directory"] == "/data/work-admin"


# ── No silent plaintext fallback ────────────────────────────────────────────

def test_update_config_with_credentials_fails_loudly_when_key_unset(client, admin_headers):
    """With no CONFIG_ENCRYPTION_KEY configured, submitting an LLM API key returns 500 instead of
    dropping it or storing it in plaintext.
    """
    # conftest.py never sets CONFIG_ENCRYPTION_KEY, so app.core.crypto's
    # module-level _fernet is None for the whole test session -- this
    # exercises the real "not configured" state, not a simulated one.
    resp = client.put(
        "/auth/config",
        json={"llm_provider": "claude", "llm_api_key": "sk-should-never-be-stored-plaintext"},
        headers=admin_headers,
    )
    # Must NOT be a 200 with the key silently dropped or stored in plaintext.
    assert resp.status_code == 500


def test_update_config_non_credential_fields_work_without_encryption_key(client, admin_headers):
    """Non-credential settings (data directory, cloud provider) can be updated without an encryption
    key, and has_cloud_credentials remains false.
    """
    # Deliberate design: only the specific credential fields require the
    # key -- an admin can still update work/data directories or provider
    # names on a deployment that hasn't set up encryption yet.
    resp = client.put(
        "/auth/config",
        json={"data_directory": "/data/pubmed", "cloud_provider": "aws"},
        headers=admin_headers,
    )
    assert resp.status_code == 200
    assert resp.json()["data_directory"] == "/data/pubmed"
    assert resp.json()["cloud_provider"] == "aws"
    assert resp.json()["has_cloud_credentials"] is False


# ── Real encryption round-trip (key patched in for just these tests) ───────

@pytest.fixture
def configured_crypto(monkeypatch):
    """Patches app.core.crypto's module-level singleton directly, since it's
    computed once at import time from CONFIG_ENCRYPTION_KEY -- setting the
    env var mid-test wouldn't retroactively affect the already-imported
    module. Simulates "properly configured" without needing a subprocess."""
    import app.core.crypto as crypto

    key = Fernet.generate_key()
    monkeypatch.setattr(crypto, "_fernet", Fernet(key))
    return crypto


def test_update_config_encrypts_credentials_at_rest(client, admin_headers, configured_crypto):
    """With an encryption key configured, the response exposes only has_* flags for credentials, and
    the stored LLM key is ciphertext that decrypts back to the submitted value.
    """
    resp = client.put(
        "/auth/config",
        json={
            "llm_provider": "claude",
            "llm_api_key": "sk-real-secret-value-12345",
            "cloud_provider": "gcp",
            "cloud_credentials": {"service_account_json": "{...}"},
        },
        headers=admin_headers,
    )
    assert resp.status_code == 200
    body = resp.json()
    # Response never contains the raw values, only presence flags.
    assert "llm_api_key" not in body
    assert "cloud_credentials" not in body
    assert body["has_llm_api_key"] is True
    assert body["has_cloud_credentials"] is True

    # DB-level check: stored value is not plaintext, and decrypts back to
    # the original via the same key -- proves it's genuinely encrypted,
    # not just omitted from the API response while stored in the clear.
    from app.services import config_service
    from app.db.session import SessionLocal

    db = SessionLocal()
    try:
        config = config_service.get_config(db)
        assert config.llm_api_key_encrypted != "sk-real-secret-value-12345"
        assert configured_crypto.decrypt(config.llm_api_key_encrypted) == "sk-real-secret-value-12345"
    finally:
        db.close()


# ── Malformed key refuses to start ──────────────────────────────────────────

def test_crypto_module_refuses_to_load_with_malformed_key(monkeypatch):
    """Reloading app.core.crypto with a malformed CONFIG_ENCRYPTION_KEY raises RuntimeError ("not a
    valid Fernet key").
    """
    monkeypatch.setenv("CONFIG_ENCRYPTION_KEY", "not-a-valid-fernet-key")
    import app.core.crypto as crypto

    with pytest.raises(RuntimeError, match="not a valid Fernet key"):
        importlib.reload(crypto)

    # Restore the module to its normal (unconfigured) state so it doesn't
    # leak a broken reload into any test that runs after this one.
    monkeypatch.delenv("CONFIG_ENCRYPTION_KEY", raising=False)
    importlib.reload(crypto)
