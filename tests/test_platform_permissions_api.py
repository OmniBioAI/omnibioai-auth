"""PR5 (Enterprise IAM Foundation): GET /platform/permissions -- read-only
exposure of the Permission Registry (app/core/permission_names.py). Gated
by require_permission(MANAGE_ALL_ORGS) only, mirroring
test_platform_roles_api.py's own conventions exactly.
"""
import uuid

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.permission_names import REGISTRY
from app.db.models import Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)

FUTURE_NAMES = {
    "workflow.execute",
    "workflow.read",
    "workflow.publish",
    "workflow.manage",
    "runs.read",
    "model.use",
    "model.resolve_ownership",
    "model.read",
    "dataset.read",
    "usage.read",
    "billing.read",
    "billing.manage",
    "subscription.manage",
    "marketplace.install",
}

# #443: kept separate from FUTURE_NAMES above -- that set's own
# test_future_permissions_present_and_correctly_flagged asserts every
# member is scope=="both", which service_token.mint genuinely isn't (see
# test_permission_registry.py's SERVICE_MINT_NAMES for the GLOBAL-scope
# assertion). Still a non-legacy entry, so it still counts toward
# `future_permissions` in registry_stats() -- see the stats test below.
SERVICE_MINT_NAMES = {"service_token.mint"}

LEGACY_NAMES = {
    "manage_roles",
    "manage_licenses",
    "manage_config",
    "override_sso_enforcement",
    "manage_all_orgs",
    "platform.manage_infra",
    "platform.manage_cron",
    "platform.manage_content",
    "manage_org",
    "manage_teams",
    "manage_api_keys",
    "manage_oauth_clients",
    "manage_sso",
}


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"pp-api-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _grant_platform_admin(email: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None, "ensure_platform_admin_role should have created this at startup"
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _platform_admin(client):
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post("/auth/login", json={"email": admin["email"], "password": admin["password"]}).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


# ── Authorized access ────────────────────────────────────────────────────────


def test_platform_admin_can_list_permissions(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    assert resp.status_code == 200


def test_response_contains_all_registered_permissions(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    names = {p["name"] for p in resp.json()}
    assert names == set(REGISTRY.keys())
    assert len(resp.json()) == len(REGISTRY)
    # 13 legacy (5 platform + 3 PR3D + 5 org) + 7 future enterprise entries
    # + 3 omnibioai-workflow-bundles entries (workflow.read/publish/manage)
    # + 2 omnibioai-tes entries (workflow.execute, now consumed by that
    # repo instead of sitting unenforced, + runs.read)
    # + 1 omnibioai-model-registry Phase 2E entry (model.resolve_ownership)
    # + 1 Model Registry read/use authorization split audit entry
    # (model.read)
    # + 1 #443 entry (service_token.mint).
    # PR4's own docs undercounted this as "20" -- corrected here to the
    # actual registry size rather than perpetuating that error.
    assert len(REGISTRY) == 28


def test_response_fields_match_permission_def_as_dict(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    by_name = {p["name"]: p for p in resp.json()}
    for name, perm in REGISTRY.items():
        assert by_name[name] == perm.as_dict()


def test_response_has_no_extra_fields(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    expected_keys = {
        "name", "resource", "action", "scope", "category",
        "description", "legacy", "deprecated", "deprecated_reason",
    }
    for row in resp.json():
        assert set(row.keys()) == expected_keys


def test_response_is_sorted_by_name(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    names = [p["name"] for p in resp.json()]
    assert names == sorted(names)


# ── Future enterprise permissions present ───────────────────────────────────


def test_future_permissions_present_and_correctly_flagged(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    by_name = {p["name"]: p for p in resp.json()}
    for name in FUTURE_NAMES:
        assert name in by_name, f"{name} missing from response"
        assert by_name[name]["legacy"] is False
        assert by_name[name]["scope"] == "both"
        assert by_name[name]["deprecated"] is False


def test_service_mint_permission_present_and_correctly_flagged(client):
    # #443: kept separate from the loop above -- GLOBAL-scoped, not BOTH.
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    by_name = {p["name"]: p for p in resp.json()}
    for name in SERVICE_MINT_NAMES:
        assert name in by_name, f"{name} missing from response"
        assert by_name[name]["legacy"] is False
        assert by_name[name]["scope"] == "global"
        assert by_name[name]["deprecated"] is False


# ── Legacy permissions present ───────────────────────────────────────────────


def test_legacy_permissions_present_and_correctly_flagged(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    by_name = {p["name"]: p for p in resp.json()}
    for name in LEGACY_NAMES:
        assert name in by_name, f"{name} missing from response"
        assert by_name[name]["legacy"] is True


# ── Unauthorized access ──────────────────────────────────────────────────────


def test_non_platform_admin_cannot_list_permissions(client):
    owner = _register_and_login(client)
    resp = client.get("/platform/permissions", headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 403


def test_missing_token_rejected(client):
    resp = client.get("/platform/permissions")
    assert resp.status_code in (401, 403)


# ── Registry search / filtering (PR6) ────────────────────────────────────────


def test_filter_by_category(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", params={"category": "billing"}, headers=admin["headers"])
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert names == {"usage.read", "billing.read", "billing.manage", "subscription.manage"}
    assert all(p["category"] == "billing" for p in resp.json())


def test_filter_by_scope(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", params={"scope": "org"}, headers=admin["headers"])
    assert resp.status_code == 200
    assert all(p["scope"] == "org" for p in resp.json())
    assert len(resp.json()) == 5


def test_filter_by_legacy(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", params={"legacy": "true"}, headers=admin["headers"])
    assert resp.status_code == 200
    assert all(p["legacy"] is True for p in resp.json())
    assert len(resp.json()) == len(LEGACY_NAMES)


def test_filter_by_deprecated(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", params={"deprecated": "true"}, headers=admin["headers"])
    assert resp.status_code == 200
    assert resp.json() == []


def test_filter_by_search(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", params={"search": "model"}, headers=admin["headers"])
    assert resp.status_code == 200
    names = {p["name"] for p in resp.json()}
    assert "model.use" in names


def test_filter_combines_category_and_scope(client):
    admin = _platform_admin(client)
    resp = client.get(
        "/platform/permissions", params={"category": "workflow", "scope": "both"}, headers=admin["headers"],
    )
    assert resp.status_code == 200
    assert {p["name"] for p in resp.json()} == {
        "workflow.execute", "workflow.read", "workflow.publish", "workflow.manage", "runs.read",
    }


def test_no_filters_returns_full_unfiltered_list_unchanged(client):
    """Backward compatibility: PR5's original no-query-params behavior."""
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", headers=admin["headers"])
    assert len(resp.json()) == len(REGISTRY)


def test_invalid_category_returns_422(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions", params={"category": "not-a-category"}, headers=admin["headers"])
    assert resp.status_code == 422


# ── Registry statistics (PR6) ────────────────────────────────────────────────


def test_platform_admin_can_get_registry_stats(client):
    admin = _platform_admin(client)
    resp = client.get("/platform/permissions/stats", headers=admin["headers"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["total_permissions"] == len(REGISTRY)
    assert body["legacy_permissions"] == len(LEGACY_NAMES)
    assert body["future_permissions"] == len(FUTURE_NAMES) + len(SERVICE_MINT_NAMES)
    assert body["deprecated_permissions"] == 0
    assert sum(body["by_scope"].values()) == len(REGISTRY)
    assert sum(body["by_category"].values()) == len(REGISTRY)


def test_non_platform_admin_cannot_get_registry_stats(client):
    owner = _register_and_login(client)
    resp = client.get("/platform/permissions/stats", headers=_auth_header(owner["access_token"]))
    assert resp.status_code == 403
