"""Security contract tests for the service-only TES -> ToolServer registration credential.

POST /service/delegations/toolserver/registration exchanges a TES
client_credentials token (scope toolserver.register) for a short-lived,
ToolServer-audience `toolserver_registration` token with no user principal;
POST /service/delegations/toolserver/registration/introspect is what ToolServer
asks before accepting POST /register_tools.

Developer: Manish Kumar <manish@omnibioai.org>
"""
import hashlib
import uuid
from datetime import datetime, timedelta

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.jwt import _sign, decode_token_for_audience
from app.db.models import AuditEvent, OAuthClient, RevokedToken, User

_engine = create_engine("sqlite:///./test.db")
Session = sessionmaker(bind=_engine)

REG = "/service/delegations/toolserver/registration"
REG_INTROSPECT = "/service/delegations/toolserver/registration/introspect"
DELEGATION_INTROSPECT = "/service/delegations/toolserver/introspect"


def header(token):
    return {"Authorization": f"Bearer {token}"}


def make_service(client, scopes=("toolserver.register",), request_scope=None):
    """Create a user + org and an active OAuth client with `scopes`; return its client_credentials token."""
    email = f"reg-{uuid.uuid4().hex[:8]}@test.invalid"
    password = "TestPassword123!"
    assert client.post("/auth/register", json={"email": email, "password": password}).status_code == 200
    user_token = client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]
    org = client.post("/orgs", json={"name": "Reg Org", "slug": f"reg-{uuid.uuid4().hex[:8]}"},
                      headers=header(user_token)).json()
    db = Session()
    try:
        user = db.query(User).filter(User.email == email).first()
        client_id, secret = f"tes-{uuid.uuid4().hex}", f"secret-{uuid.uuid4().hex}"
        db.add(OAuthClient(
            organization_id=org["id"], created_by_user_id=user.id, client_id=client_id,
            client_secret_hash=hashlib.sha256(secret.encode()).hexdigest(), name="TES",
            scopes=list(scopes), status="active",
        ))
        db.commit()
    finally:
        db.close()
    form = {"grant_type": "client_credentials", "client_id": client_id, "client_secret": secret}
    if request_scope:
        form["scope"] = request_scope
    service = client.post("/oauth/token", data=form)
    assert service.status_code == 200
    return {"service": service.json()["access_token"], "client_id": client_id, "org": org, "user": user_token}


def issue(client, data):
    return client.post(REG, headers=header(data["service"]))


def introspect(client, token):
    return client.post(REG_INTROSPECT, json={"token": token}).json()


def _set_client(client_id, **fields):
    db = Session()
    try:
        row = db.query(OAuthClient).filter(OAuthClient.client_id == client_id).first()
        for k, v in fields.items():
            setattr(row, k, v)
        db.commit()
    finally:
        db.close()


def test_tes_service_gets_short_lived_toolserver_audience_service_only_token(client):
    data = make_service(client)
    response = issue(client, data)
    assert response.status_code == 200
    body = response.json()
    assert body["expires_in"] == 300
    claims = decode_token_for_audience(body["access_token"], "omnibioai-toolserver")
    assert claims["type"] == "toolserver_registration"
    assert claims["aud"] == "omnibioai-toolserver"
    assert claims["client_id"] == data["client_id"]
    assert claims["scopes"] == ["toolserver.register"]
    assert "sub" not in claims and "email" not in claims and "permissions" not in claims
    assert claims["exp"] - claims["iat"] == 300
    result = introspect(client, body["access_token"])
    assert result["valid"] is True
    assert result["client_id"] == data["client_id"]
    assert result["scopes"] == ["toolserver.register"]


def test_issuance_requires_the_toolserver_register_scope_on_client_and_token(client):
    # Client without the scope (a non-TES service, e.g. one holding only toolserver.delegate).
    assert issue(client, make_service(client, scopes=("toolserver.delegate", "workflow.execute"))).status_code == 403
    # Client has the scope but the presented token was narrowed to a different one.
    narrowed = make_service(client, scopes=("toolserver.register", "toolserver.delegate"),
                            request_scope="toolserver.delegate")
    assert issue(client, narrowed).status_code == 403
    # Least-privilege token narrowed to exactly toolserver.register works.
    exact = make_service(client, scopes=("toolserver.register", "toolserver.delegate"),
                         request_scope="toolserver.register")
    assert issue(client, exact).status_code == 200


def test_user_tokens_and_garbage_cannot_obtain_registration(client):
    data = make_service(client)
    assert client.post(REG, headers=header(data["user"])).status_code == 403
    assert client.post(REG, headers=header("not.a.token")).status_code == 401
    assert client.post(REG).status_code in (401, 403)


def test_registration_token_is_not_a_user_or_delegated_credential(client):
    token = issue(client, make_service(client)).json()["access_token"]
    assert client.post("/auth/validate", json={"token": token}).json()["valid"] is False
    assert client.get("/auth/me", headers=header(token)).status_code in (401, 403, 404)
    assert client.get("/service/me", headers=header(token)).status_code in (401, 403)
    # It cannot pass the delegated-execution introspection ToolServer uses for /runs and /validate.
    assert client.post(DELEGATION_INTROSPECT, json={"token": token}).json()["valid"] is False


def test_delegated_and_user_tokens_are_rejected_by_registration_introspection(client):
    data = make_service(client)
    assert introspect(client, data["user"])["valid"] is False
    assert introspect(client, data["service"])["valid"] is False  # platform-audience service token


def test_introspection_rejects_expired_wrong_audience_wrong_type_and_forged(client):
    data = make_service(client)
    now = datetime.utcnow()
    base = {"client_id": data["client_id"], "org_id": data["org"]["id"], "scopes": ["toolserver.register"],
            "type": "toolserver_registration", "iat": now, "exp": now + timedelta(minutes=5),
            "jti": str(uuid.uuid4()), "aud": "omnibioai-toolserver"}
    assert introspect(client, _sign(base))["valid"] is True  # control
    assert introspect(client, _sign({**base, "exp": now - timedelta(seconds=1)}))["valid"] is False
    assert introspect(client, _sign({**base, "aud": "omnibioai-platform"}))["valid"] is False
    assert introspect(client, _sign({**base, "type": "delegated_execution"}))["valid"] is False
    assert introspect(client, _sign({**base, "scopes": ["toolserver.register", "workflow.execute"]}))["valid"] is False
    assert introspect(client, _sign({**base, "sub": "1"}))["valid"] is False
    assert introspect(client, _sign({**base, "org_id": 999999}))["valid"] is False
    assert introspect(client, _sign({**base, "client_id": "not-a-client"}))["valid"] is False
    good = _sign(base)
    assert introspect(client, good[:-4] + ("AAAA" if not good.endswith("AAAA") else "BBBB"))["valid"] is False


def test_introspection_rechecks_live_client_state(client):
    data = make_service(client)
    token = issue(client, data).json()["access_token"]
    assert introspect(client, token)["valid"] is True
    _set_client(data["client_id"], scopes=["toolserver.delegate"])
    assert introspect(client, token)["valid"] is False
    _set_client(data["client_id"], scopes=["toolserver.register"])
    assert introspect(client, token)["valid"] is True
    _set_client(data["client_id"], expires_at=datetime.utcnow() - timedelta(seconds=1))
    assert introspect(client, token)["valid"] is False
    _set_client(data["client_id"], expires_at=None, status="revoked")
    assert introspect(client, token)["valid"] is False


def test_revoked_registration_token_jti_is_rejected(client):
    data = make_service(client)
    token = issue(client, data).json()["access_token"]
    jti = decode_token_for_audience(token, "omnibioai-toolserver")["jti"]
    db = Session()
    try:
        db.add(RevokedToken(token_jti=jti))
        db.commit()
    finally:
        db.close()
    assert introspect(client, token)["valid"] is False


def test_issuance_is_audited_without_the_raw_token(client):
    data = make_service(client)
    token = issue(client, data).json()["access_token"]
    assert issue(client, make_service(client, scopes=("workflow.execute",))).status_code == 403
    db = Session()
    try:
        issued = db.query(AuditEvent).filter(AuditEvent.event_type == "toolserver_registration_token_issued").all()
        denied = db.query(AuditEvent).filter(AuditEvent.event_type == "toolserver_registration_token_denied").all()
        assert any((e.event_metadata or {}).get("client_id") == data["client_id"] for e in issued)
        assert denied
        blob = repr([(e.event_metadata, e.before_state, e.after_state) for e in issued + denied])
        assert token not in blob and data["service"] not in blob
    finally:
        db.close()


def test_registration_only_client_cannot_obtain_user_delegation(client):
    """Client A (toolserver.register only) can never mint an execution credential,
    even with a real org member's token as the initiating identity."""
    data = make_service(client, scopes=("toolserver.register",))
    body = {"initiating_token": data["user"], "organization_id": data["org"]["id"],
            "permissions": ["workflow.execute"], "audience": "omnibioai-toolserver"}
    assert client.post("/service/delegations/toolserver", json=body, headers=header(data["service"])).status_code == 403
    registration = issue(client, data).json()["access_token"]
    assert client.post("/service/delegations/toolserver", json=body, headers=header(registration)).status_code in (401, 403)


def test_execution_client_cannot_obtain_registration(client):
    """Client B (toolserver.delegate + workflow.execute + runs.read) cannot mint a registration credential."""
    data = make_service(client, scopes=("toolserver.delegate", "workflow.execute", "runs.read"))
    assert issue(client, data).status_code == 403
