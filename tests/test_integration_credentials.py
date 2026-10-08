"""Security contract for generic integration credentials and references."""

import json
import uuid

import httpx
import pytest
from cryptography.fernet import Fernet

from app.db.models import AuditEvent, IntegrationCredential
from app.db.session import SessionLocal
from app.services import integration_credential_service as service
from app.services import integration_provider_client as provider_client

SECRET = "svc-test-integration-secret"

POLICIES = {
    "github": {
        "provider_id": "github",
        "authentication": {
            "type": "token", "allowed_scopes": ["user", "organization"],
            "anonymous_access": False, "resolution_policy": ["user", "organization"],
            "fields": [{"name": "token", "secret": True, "required": True}],
        },
        "connection_test_supported": False,
    },
    "ncbi": {
        "provider_id": "ncbi",
        "authentication": {
            "type": "optional_api_key", "allowed_scopes": ["user", "organization", "platform"],
            "anonymous_access": True, "resolution_policy": ["user", "organization", "platform", "anonymous"],
            "fields": [{"name": "api_key", "secret": True, "required": False}],
        },
        "connection_test_supported": False,
    },
}


def _headers(token):
    return {"Authorization": f"Bearer {token}"}


def _register(client, prefix="cred"):
    email = f"{prefix}-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    token = client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]
    return {"email": email, "password": password, "token": token}


def _create_org(client, user, prefix="cred-org"):
    response = client.post(
        "/orgs", json={"name": "Credential Test Org", "slug": f"{prefix}-{uuid.uuid4().hex[:8]}"},
        headers=_headers(user["token"]),
    )
    assert response.status_code == 201
    user["token"] = client.post(
        "/auth/login", json={"email": user["email"], "password": user["password"]}
    ).json()["access_token"]
    return response.json()["id"]


@pytest.fixture(autouse=True)
def foundation(monkeypatch):
    import app.core.crypto as crypto
    import app.core.config as config

    monkeypatch.setattr(crypto, "_fernet", Fernet(Fernet.generate_key()))
    monkeypatch.setattr(config.settings, "INTEGRATION_CREDENTIAL_SERVICE_SECRET", SECRET)
    monkeypatch.setattr(service, "get_provider_policy", lambda provider: POLICIES[provider])


def _put(client, user, provider="github", scope="user", value="ghp_super_secret_123456"):
    field = "api_key" if provider == "ncbi" else "token"
    return client.put(
        f"/integrations/credentials/{provider}/{scope}",
        json={"credentials": {field: value}, "display_metadata": {"label": "test account"}},
        headers=_headers(user["token"]),
    )


def _reference(client, user, provider="github"):
    return client.post(
        f"/integrations/credentials/{provider}/references",
        json={"consumer": "workbench", "purpose": "integration_execution"},
        headers=_headers(user["token"]),
    )


def _resolve(client, reference, provider="github", consumer="workbench", purpose="integration_execution", secret=SECRET):
    return client.post(
        "/internal/integration-credentials/resolve",
        json={"credential_ref": reference, "provider_id": provider, "consumer": consumer, "purpose": purpose},
        headers={"X-Integration-Credential-Service-Secret": secret},
    )


def test_write_only_encrypted_user_credential(client):
    user = _register(client)
    plaintext = "ghp_super_secret_123456"
    response = _put(client, user, value=plaintext)
    assert response.status_code == 200
    assert plaintext not in response.text
    assert "credentials" not in response.json()
    listed = client.get("/integrations/credentials", headers=_headers(user["token"]))
    assert listed.status_code == 200 and plaintext not in listed.text
    db = SessionLocal()
    try:
        row = db.query(IntegrationCredential).filter_by(provider_id="github", scope="user").order_by(IntegrationCredential.id.desc()).first()
        assert row.encrypted_payload != plaintext
        assert json.loads(__import__("app.core.crypto", fromlist=["decrypt"]).decrypt(row.encrypted_payload))["token"] == plaintext
    finally:
        db.close()


def test_create_replace_invalidates_old_reference_and_audits_without_secret(client):
    user = _register(client)
    assert _put(client, user, value="first_secret_123456").status_code == 200
    old_ref = _reference(client, user).json()["credential_ref"]
    replaced = _put(client, user, value="second_secret_654321")
    assert replaced.status_code == 200
    assert _resolve(client, old_ref).status_code == 404
    new_ref = _reference(client, user).json()["credential_ref"]
    assert _resolve(client, new_ref).json()["credentials"] == {"token": "second_secret_654321"}
    db = SessionLocal()
    try:
        events = db.query(AuditEvent).filter(AuditEvent.event_type.like("integration_credential_%")).all()
        serialized = json.dumps([
            {"before": event.before_state, "after": event.after_state, "metadata": event.event_metadata}
            for event in events
        ])
        assert "first_secret" not in serialized and "second_secret" not in serialized
        assert any(event.event_type == "integration_credential_replaced" for event in events)
    finally:
        db.close()


def test_reference_is_opaque_bound_and_requires_internal_auth(client):
    user = _register(client)
    _put(client, user)
    body = _reference(client, user).json()
    reference = body["credential_ref"]
    assert len(reference) >= 32
    assert str(body).find(user["email"]) == -1
    assert _resolve(client, reference, secret="wrong").status_code == 403
    assert _resolve(client, reference, provider="ncbi").status_code == 404
    bad_consumer = client.post(
        "/internal/integration-credentials/resolve",
        json={"credential_ref": reference, "provider_id": "github", "consumer": "other", "purpose": "integration_execution"},
        headers={"X-Integration-Credential-Service-Secret": SECRET},
    )
    assert bad_consumer.status_code == 422
    bad_purpose = client.post(
        "/internal/integration-credentials/resolve",
        json={"credential_ref": reference, "provider_id": "github", "consumer": "workbench", "purpose": "reveal"},
        headers={"X-Integration-Credential-Service-Secret": SECRET},
    )
    assert bad_purpose.status_code == 422


def test_cross_user_isolation_for_metadata_mutation_and_reference(client):
    user_a = _register(client, "a")
    user_b = _register(client, "b")
    _put(client, user_a)
    assert client.get("/integrations/credentials", headers=_headers(user_b["token"])).json() == []
    assert client.delete("/integrations/credentials/github/user", headers=_headers(user_b["token"])).status_code == 404
    assert _reference(client, user_b).status_code == 404


def test_org_scope_is_server_derived_and_cross_org_isolated(client):
    user_a = _register(client, "orga")
    org_a = _create_org(client, user_a, "orga")
    user_b = _register(client, "orgb")
    org_b = _create_org(client, user_b, "orgb")
    assert org_a != org_b
    assert _put(client, user_a, scope="organization").status_code == 200
    body = client.get("/integrations/credentials", headers=_headers(user_b["token"])).json()
    assert body == []
    assert _reference(client, user_b).status_code == 404
    injected = client.put(
        "/integrations/credentials/github/organization",
        json={"credentials": {"token": "nope_secret_12345"}, "organization_id": org_a},
        headers=_headers(user_b["token"]),
    )
    assert injected.status_code == 422


def test_personal_precedes_org_and_ncbi_anonymous_fallback(client):
    user = _register(client)
    _create_org(client, user)
    _put(client, user, scope="organization", value="org_secret_123456")
    _put(client, user, scope="user", value="user_secret_123456")
    reference = _reference(client, user).json()
    assert reference["resolved_scope"] == "user"
    assert _resolve(client, reference["credential_ref"]).json()["credentials"]["token"] == "user_secret_123456"
    anonymous = _reference(client, user, provider="ncbi")
    assert anonymous.status_code == 200
    assert anonymous.json() == {"provider_id": "ncbi", "resolved_scope": "anonymous", "credential_ref": None, "expires_at": None}


def test_no_unauthorized_fallback_for_required_provider(client):
    user = _register(client)
    response = _reference(client, user, provider="github")
    assert response.status_code == 404


def test_reference_rechecks_issuing_organization_membership(client):
    user = _register(client)
    org_id = _create_org(client, user)
    assert _put(client, user, scope="user").status_code == 200
    reference = _reference(client, user).json()["credential_ref"]
    db = SessionLocal()
    try:
        from app.db.models import OrganizationMembership, User

        user_row = db.query(User).filter_by(email=user["email"]).one()
        membership = db.query(OrganizationMembership).filter_by(
            organization_id=org_id, user_id=user_row.id
        ).one()
        membership.status = "inactive"
        db.commit()
    finally:
        db.close()
    assert _resolve(client, reference).status_code == 404


def test_revoke_clears_ciphertext_and_reference(client):
    user = _register(client)
    _put(client, user)
    reference = _reference(client, user).json()["credential_ref"]
    deleted = client.delete("/integrations/credentials/github/user", headers=_headers(user["token"]))
    assert deleted.status_code == 204
    assert _resolve(client, reference).status_code == 404
    db = SessionLocal()
    try:
        row = db.query(IntegrationCredential).filter_by(provider_id="github", scope="user").order_by(IntegrationCredential.id.desc()).first()
        assert row.status == "revoked" and row.encrypted_payload is None
    finally:
        db.close()


def test_org_mutation_requires_manage_org(client):
    owner = _register(client, "owner")
    org_id = _create_org(client, owner)
    member = _register(client, "member")
    db = SessionLocal()
    try:
        from app.db.models import OrganizationMembership, User
        member_row = db.query(User).filter_by(email=member["email"]).one()
        db.add(OrganizationMembership(organization_id=org_id, user_id=member_row.id, status="active"))
        db.commit()
    finally:
        db.close()
    # Mint an ordinary access token with the live org context; authorization
    # still comes from the membership's live roles, not this claim.
    from app.core.jwt import create_access_token
    db = SessionLocal()
    try:
        member_row = db.query(__import__("app.db.models", fromlist=["User"]).User).filter_by(email=member["email"]).one()
        member["token"] = create_access_token({"sub": str(member_row.id), "email": member["email"], "org_id": org_id, "roles": [], "permissions": [], "type": "access"})
    finally:
        db.close()
    assert _put(client, member, scope="organization").status_code == 403


def test_status_and_connection_test_are_authoritative_and_sanitized(client):
    user = _register(client)
    assert client.get("/integrations/credentials/github/status", headers=_headers(user["token"])).json()["status"] == "NOT_CONFIGURED"
    _put(client, user)
    assert client.get("/integrations/credentials/github/status", headers=_headers(user["token"])).json()["status"] == "CONNECTED_USER"
    tested = client.post("/integrations/credentials/github/test", headers=_headers(user["token"]))
    assert tested.status_code == 200 and tested.json()["status"] == "TEST_NOT_SUPPORTED"


def test_unauthenticated_mutations_rejected_and_no_plaintext_read_route(client):
    assert client.put("/integrations/credentials/github/user", json={"credentials": {"token": "secret"}}).status_code in (401, 403)
    assert client.get("/internal/integration-credentials/resolve/1/plaintext").status_code == 404


def test_display_metadata_cannot_echo_secret(client):
    user = _register(client)
    response = client.put(
        "/integrations/credentials/github/user",
        json={"credentials": {"token": "secret-value-123456"}, "display_metadata": {"label": "secret-value-123456"}},
        headers=_headers(user["token"]),
    )
    assert response.status_code == 400
    assert "secret-value-123456" not in response.text


def test_payload_and_metadata_validation_security_branches():
    policy = POLICIES["github"]
    invalid_payloads = [
        None,
        {"unknown": "value"},
        {},
        {"token": ""},
        {"token": 7},
        {"token": "x" * 8193},
    ]
    for payload in invalid_payloads:
        with pytest.raises(service.CredentialError):
            service._validate_payload(policy, payload)
    with pytest.raises(service.CredentialError, match="At least one"):
        service._validate_payload(POLICIES["ncbi"], {})
    assert service._masked_hint({"token": "short"}) is None
    assert service._display_metadata(None, ["secret"]) is None
    for metadata_value in ({"other": "value"}, {"label": ""}, {"label": 7}):
        with pytest.raises(service.CredentialError):
            service._display_metadata(metadata_value, ["secret"])
    with pytest.raises(service.CredentialError, match="Platform"):
        service._owner("platform", {"sub": "1"}, None)


def test_provider_policy_client_is_fail_closed_and_service_bound(monkeypatch):
    monkeypatch.setattr(provider_client.settings, "INTEGRATION_CREDENTIAL_SERVICE_SECRET", SECRET)
    captured = {}

    class Response:
        status_code = 200

        @staticmethod
        def json():
            return POLICIES["github"]

    def get(url, **kwargs):
        captured.update({"url": url, **kwargs})
        return Response()

    monkeypatch.setattr(provider_client.httpx, "get", get)
    assert provider_client.get_provider_policy("github")["provider_id"] == "github"
    assert captured["headers"] == {"X-Integration-Credential-Service-Secret": SECRET}
    assert captured["timeout"] == 3.0

    for invalid in (None, "Bad Provider", "x" * 65):
        with pytest.raises(provider_client.ProviderPolicyUnavailable):
            provider_client.get_provider_policy(invalid)

    monkeypatch.setattr(provider_client.settings, "INTEGRATION_CREDENTIAL_SERVICE_SECRET", "")
    with pytest.raises(provider_client.ProviderPolicyUnavailable, match="not configured"):
        provider_client.get_provider_policy("github")


@pytest.mark.parametrize(
    "response",
    [
        (404, {}),
        (200, {"provider_id": "gitlab", "authentication": {}}),
        (200, {"provider_id": "github", "authentication": "token"}),
    ],
)
def test_provider_policy_client_rejects_bad_upstream_responses(monkeypatch, response):
    monkeypatch.setattr(provider_client.settings, "INTEGRATION_CREDENTIAL_SERVICE_SECRET", SECRET)

    class Response:
        status_code = response[0]

        @staticmethod
        def json():
            return response[1]

    monkeypatch.setattr(provider_client.httpx, "get", lambda *args, **kwargs: Response())
    with pytest.raises(provider_client.ProviderPolicyUnavailable):
        provider_client.get_provider_policy("github")


def test_provider_policy_client_sanitizes_transport_error(monkeypatch):
    monkeypatch.setattr(provider_client.settings, "INTEGRATION_CREDENTIAL_SERVICE_SECRET", SECRET)

    def fail(*args, **kwargs):
        raise httpx.ConnectError("sensitive transport detail")

    monkeypatch.setattr(provider_client.httpx, "get", fail)
    with pytest.raises(provider_client.ProviderPolicyUnavailable, match="unavailable") as caught:
        provider_client.get_provider_policy("github")
    assert "sensitive" not in str(caught.value)


def test_encryption_and_internal_resolution_fail_closed_without_secret_echo(client, monkeypatch):
    user = _register(client)
    plaintext = "never-echo-this-secret"
    monkeypatch.setattr("app.core.crypto.encrypt", lambda value: (_ for _ in ()).throw(RuntimeError(value)))
    response = _put(client, user, value=plaintext)
    assert response.status_code == 503
    assert plaintext not in response.text

    import app.core.config as config

    monkeypatch.setattr(config.settings, "INTEGRATION_CREDENTIAL_SERVICE_SECRET", "")
    unavailable = _resolve(client, "opaque-reference-that-is-long-enough")
    assert unavailable.status_code == 503


def test_unknown_provider_unsupported_scope_and_public_status(client):
    user = _register(client)
    assert client.get("/integrations/credentials/unknown/status", headers=_headers(user["token"])).status_code == 404
    assert _put(client, user, scope="platform").status_code == 400
    assert client.delete("/integrations/credentials/github/platform", headers=_headers(user["token"])).status_code == 400
    status = client.get("/integrations/credentials/ncbi/status", headers=_headers(user["token"]))
    assert status.json() == {"provider_id": "ncbi", "status": "READY_NO_CREDENTIALS", "scope": "anonymous"}
