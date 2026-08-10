"""PR-B5-A (Interaction Read API): GET /platform/interactions[/{id}] --
platform-admin-only retrieval of the `interactions` table PR-B2 created
and PR-B3/PR-B4 populate.

Helper shape (_auth_header/_register_and_login/_platform_admin) mirrors
tests/test_audit_ledger.py's own local helpers exactly -- the closest
existing precedent for "grant a test user manage_all_orgs, then call a
/platform/* route" -- rather than a new fixture, matching this repo's
established per-file-helper convention for this exact need.
"""
import uuid
from datetime import datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db.models import Interaction, Role, User

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


def _auth_header(token):
    return {"Authorization": f"Bearer {token}"}


def _register_and_login(client, email=None):
    email = email or f"interactions-{uuid.uuid4().hex[:8]}@omnibioai.test"
    password = "TestPassword123!"
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    return {"email": email, "password": password, **login.json()}


def _grant_platform_admin(email: str) -> None:
    db = _DirectSession()
    try:
        user = db.query(User).filter(User.email == email).first()
        role = db.query(Role).filter(Role.name == "platform_admin").first()
        assert role is not None
        user.roles.append(role)
        db.commit()
    finally:
        db.close()


def _platform_admin(client):
    """/platform/interactions is gated by manage_all_orgs (the
    platform_admin role) -- a freshly self-registered user has neither."""
    admin = _register_and_login(client)
    _grant_platform_admin(admin["email"])
    relogged = client.post(
        "/auth/login", json={"email": admin["email"], "password": admin["password"]}
    ).json()
    return {**admin, **relogged, "headers": _auth_header(relogged["access_token"])}


def _seed_interaction(**overrides) -> Interaction:
    db = _DirectSession()
    try:
        defaults = dict(
            interaction_id=str(uuid.uuid4()),
            organization_id=1,
            user_id=1,
            session_id=None,
            trace_id=None,
            service="rag",
            interaction_type="query",
            action="rag.query",
            resource_type="study",
            resource_id="default",
            status="success",
            decision=None,
            event_metadata={},
            created_at=datetime.utcnow(),
        )
        defaults.update(overrides)
        row = Interaction(**defaults)
        db.add(row)
        db.commit()
        db.refresh(row)
        db.expunge(row)
        return row
    finally:
        db.close()


def _cleanup_interactions(interaction_ids: list[str]) -> None:
    """Test isolation: this repo's tests share one session-scoped test.db
    (see tests/conftest.py's own session-scoped setup_db), so seeded rows
    must not leak into other test functions' unfiltered queries."""
    db = _DirectSession()
    try:
        db.query(Interaction).filter(Interaction.interaction_id.in_(interaction_ids)).delete(
            synchronize_session=False
        )
        db.commit()
    finally:
        db.close()


@pytest.fixture
def platform_admin(client):
    return _platform_admin(client)


# ── Authentication ──────────────────────────────────────────────────────

def test_list_interactions_missing_token_401(client):
    resp = client.get("/platform/interactions")
    assert resp.status_code == 401


def test_list_interactions_invalid_token_401(client):
    resp = client.get("/platform/interactions", headers=_auth_header("not-a-real-token"))
    assert resp.status_code == 401


# ── Authorization ────────────────────────────────────────────────────────

def test_list_interactions_without_manage_all_orgs_403(client):
    ordinary = _register_and_login(client)
    resp = client.get("/platform/interactions", headers=_auth_header(ordinary["access_token"]))
    assert resp.status_code == 403


def test_list_interactions_platform_admin_200(client, platform_admin):
    resp = client.get("/platform/interactions", headers=platform_admin["headers"])
    assert resp.status_code == 200


def test_org_member_does_not_gain_access_via_own_org(client):
    """An ordinary org member (not a platform admin) must not reach this
    endpoint merely by belonging to (even owning) an organization --
    /platform/interactions has no org-membership bypass, only
    manage_all_orgs."""
    owner = _register_and_login(client)
    headers = _auth_header(owner["access_token"])
    client.post(
        "/orgs", json={"name": "Org Member Org", "slug": f"om-org-{uuid.uuid4().hex[:8]}"},
        headers=headers,
    )
    relogged = client.post(
        "/auth/login", json={"email": owner["email"], "password": owner["password"]}
    ).json()
    resp = client.get(
        "/platform/interactions", headers=_auth_header(relogged["access_token"])
    )
    assert resp.status_code == 403


# ── List: empty / single / multiple ────────────────────────────────────

def test_list_interactions_empty_result(client, platform_admin):
    resp = client.get(
        "/platform/interactions",
        params={"organization_id": 999999},
        headers=platform_admin["headers"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body == {"items": [], "total": 0, "page": 1, "page_size": 20, "total_pages": 0}


def test_list_interactions_single_result(client, platform_admin):
    org_id = 424242
    row = _seed_interaction(organization_id=org_id)
    try:
        resp = client.get(
            "/platform/interactions",
            params={"organization_id": org_id},
            headers=platform_admin["headers"],
        )
        body = resp.json()
        assert resp.status_code == 200
        assert body["total"] == 1
        assert body["items"][0]["interaction_id"] == row.interaction_id
    finally:
        _cleanup_interactions([row.interaction_id])


def test_list_interactions_multiple_results(client, platform_admin):
    org_id = 424243
    rows = [_seed_interaction(organization_id=org_id) for _ in range(3)]
    try:
        resp = client.get(
            "/platform/interactions",
            params={"organization_id": org_id},
            headers=platform_admin["headers"],
        )
        body = resp.json()
        assert resp.status_code == 200
        assert body["total"] == 3
        assert len(body["items"]) == 3
    finally:
        _cleanup_interactions([r.interaction_id for r in rows])


# ── Pagination ───────────────────────────────────────────────────────────

def test_list_interactions_pagination(client, platform_admin):
    org_id = 424244
    rows = [_seed_interaction(organization_id=org_id) for _ in range(5)]
    try:
        page1 = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "page": 1, "page_size": 2},
            headers=platform_admin["headers"],
        ).json()
        page2 = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "page": 2, "page_size": 2},
            headers=platform_admin["headers"],
        ).json()
        page3 = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "page": 3, "page_size": 2},
            headers=platform_admin["headers"],
        ).json()

        assert page1["total"] == 5
        assert page1["total_pages"] == 3
        assert len(page1["items"]) == 2
        assert len(page2["items"]) == 2
        assert len(page3["items"]) == 1
        # No overlap across pages.
        seen_ids = {i["interaction_id"] for i in page1["items"] + page2["items"] + page3["items"]}
        assert seen_ids == {r.interaction_id for r in rows}
    finally:
        _cleanup_interactions([r.interaction_id for r in rows])


def test_list_interactions_page_size_default(client, platform_admin):
    resp = client.get("/platform/interactions", headers=platform_admin["headers"])
    assert resp.json()["page_size"] == 20


def test_list_interactions_page_size_maximum_accepted(client, platform_admin):
    resp = client.get(
        "/platform/interactions", params={"page_size": 100}, headers=platform_admin["headers"]
    )
    assert resp.status_code == 200
    assert resp.json()["page_size"] == 100


def test_list_interactions_page_size_above_maximum_rejected(client, platform_admin):
    resp = client.get(
        "/platform/interactions", params={"page_size": 101}, headers=platform_admin["headers"]
    )
    assert resp.status_code == 422


def test_list_interactions_page_below_one_rejected(client, platform_admin):
    resp = client.get(
        "/platform/interactions", params={"page": 0}, headers=platform_admin["headers"]
    )
    assert resp.status_code == 422


# ── Filtering ────────────────────────────────────────────────────────────

def test_filter_by_organization_id(client, platform_admin):
    org_a, org_b = 434201, 434202
    row_a = _seed_interaction(organization_id=org_a)
    row_b = _seed_interaction(organization_id=org_b)
    try:
        resp = client.get(
            "/platform/interactions", params={"organization_id": org_a},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert row_a.interaction_id in ids
        assert row_b.interaction_id not in ids
    finally:
        _cleanup_interactions([row_a.interaction_id, row_b.interaction_id])


def test_filter_by_user_id(client, platform_admin):
    org_id = 434203
    row_a = _seed_interaction(organization_id=org_id, user_id=5001)
    row_b = _seed_interaction(organization_id=org_id, user_id=5002)
    try:
        resp = client.get(
            "/platform/interactions", params={"organization_id": org_id, "user_id": 5001},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert row_a.interaction_id in ids
        assert row_b.interaction_id not in ids
    finally:
        _cleanup_interactions([row_a.interaction_id, row_b.interaction_id])


def test_filter_by_service(client, platform_admin):
    org_id = 434204
    row_a = _seed_interaction(organization_id=org_id, service="rag")
    row_b = _seed_interaction(organization_id=org_id, service="lims")
    try:
        resp = client.get(
            "/platform/interactions", params={"organization_id": org_id, "service": "rag"},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert row_a.interaction_id in ids
        assert row_b.interaction_id not in ids
    finally:
        _cleanup_interactions([row_a.interaction_id, row_b.interaction_id])


def test_filter_by_interaction_type(client, platform_admin):
    org_id = 434205
    row_a = _seed_interaction(organization_id=org_id, interaction_type="query")
    row_b = _seed_interaction(organization_id=org_id, interaction_type="ingest")
    try:
        resp = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "interaction_type": "query"},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert row_a.interaction_id in ids
        assert row_b.interaction_id not in ids
    finally:
        _cleanup_interactions([row_a.interaction_id, row_b.interaction_id])


def test_filter_by_status(client, platform_admin):
    org_id = 434206
    row_a = _seed_interaction(organization_id=org_id, status="success")
    row_b = _seed_interaction(organization_id=org_id, status="error")
    try:
        resp = client.get(
            "/platform/interactions", params={"organization_id": org_id, "status": "error"},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert row_b.interaction_id in ids
        assert row_a.interaction_id not in ids
    finally:
        _cleanup_interactions([row_a.interaction_id, row_b.interaction_id])


def test_filter_by_start_and_end_date(client, platform_admin):
    org_id = 434207
    old = _seed_interaction(organization_id=org_id, created_at=datetime(2020, 1, 1))
    recent = _seed_interaction(organization_id=org_id, created_at=datetime.utcnow())
    try:
        resp = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "start_date": "2024-01-01T00:00:00"},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert recent.interaction_id in ids
        assert old.interaction_id not in ids

        resp2 = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "end_date": "2020-06-01T00:00:00"},
            headers=platform_admin["headers"],
        ).json()
        ids2 = {i["interaction_id"] for i in resp2["items"]}
        assert old.interaction_id in ids2
        assert recent.interaction_id not in ids2
    finally:
        _cleanup_interactions([old.interaction_id, recent.interaction_id])


def test_multi_filter_and_combination(client, platform_admin):
    org_id = 434208
    match = _seed_interaction(organization_id=org_id, service="rag", status="success")
    wrong_service = _seed_interaction(organization_id=org_id, service="lims", status="success")
    wrong_status = _seed_interaction(organization_id=org_id, service="rag", status="error")
    try:
        resp = client.get(
            "/platform/interactions",
            params={"organization_id": org_id, "service": "rag", "status": "success"},
            headers=platform_admin["headers"],
        ).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert ids == {match.interaction_id}
    finally:
        _cleanup_interactions(
            [match.interaction_id, wrong_service.interaction_id, wrong_status.interaction_id]
        )


# ── Sorting ──────────────────────────────────────────────────────────────

def test_sorting_created_at_desc(client, platform_admin):
    org_id = 434209
    older = _seed_interaction(organization_id=org_id, created_at=datetime(2023, 1, 1))
    newer = _seed_interaction(organization_id=org_id, created_at=datetime(2024, 1, 1))
    try:
        resp = client.get(
            "/platform/interactions", params={"organization_id": org_id},
            headers=platform_admin["headers"],
        ).json()
        returned_ids = [i["interaction_id"] for i in resp["items"]]
        assert returned_ids == [newer.interaction_id, older.interaction_id]
    finally:
        _cleanup_interactions([older.interaction_id, newer.interaction_id])


def test_sorting_id_desc_tiebreak_on_identical_created_at(client, platform_admin):
    org_id = 434210
    same_ts = datetime(2024, 6, 1, 12, 0, 0)
    first = _seed_interaction(organization_id=org_id, created_at=same_ts)
    second = _seed_interaction(organization_id=org_id, created_at=same_ts)
    try:
        assert second.id > first.id
        resp = client.get(
            "/platform/interactions", params={"organization_id": org_id},
            headers=platform_admin["headers"],
        ).json()
        returned_ids = [i["interaction_id"] for i in resp["items"]]
        # Higher id (inserted later) must come first when created_at ties.
        assert returned_ids == [second.interaction_id, first.interaction_id]
    finally:
        _cleanup_interactions([first.interaction_id, second.interaction_id])


# ── Single record ────────────────────────────────────────────────────────

def test_get_interaction_existing_200(client, platform_admin):
    row = _seed_interaction()
    try:
        resp = client.get(
            f"/platform/interactions/{row.interaction_id}", headers=platform_admin["headers"]
        )
        assert resp.status_code == 200
        assert resp.json()["interaction_id"] == row.interaction_id
    finally:
        _cleanup_interactions([row.interaction_id])


def test_get_interaction_nonexistent_404(client, platform_admin):
    resp = client.get(
        f"/platform/interactions/{uuid.uuid4()}", headers=platform_admin["headers"]
    )
    assert resp.status_code == 404


def test_get_interaction_without_manage_all_orgs_403(client):
    ordinary = _register_and_login(client)
    resp = client.get(
        f"/platform/interactions/{uuid.uuid4()}", headers=_auth_header(ordinary["access_token"])
    )
    assert resp.status_code == 403


# ── Organization behavior (platform-admin cross-org visibility) ─────────

def test_platform_admin_lists_across_organizations_without_filter(client, platform_admin):
    org_a, org_b = 434211, 434212
    row_a = _seed_interaction(organization_id=org_a)
    row_b = _seed_interaction(organization_id=org_b)
    try:
        resp = client.get("/platform/interactions", headers=platform_admin["headers"]).json()
        ids = {i["interaction_id"] for i in resp["items"]}
        assert row_a.interaction_id in ids
        assert row_b.interaction_id in ids
    finally:
        _cleanup_interactions([row_a.interaction_id, row_b.interaction_id])


# ── Response schema ──────────────────────────────────────────────────────

def test_nullable_fields_serialize_as_null(client, platform_admin):
    row = _seed_interaction(user_id=None, session_id=None, trace_id=None, decision=None)
    try:
        resp = client.get(
            f"/platform/interactions/{row.interaction_id}", headers=platform_admin["headers"]
        ).json()
        assert resp["user_id"] is None
        assert resp["session_id"] is None
        assert resp["trace_id"] is None
        assert resp["decision"] is None
    finally:
        _cleanup_interactions([row.interaction_id])


def test_metadata_returned_under_metadata_field_name(client, platform_admin):
    row = _seed_interaction(event_metadata={"mode": "rag", "top_k": 5})
    try:
        resp = client.get(
            f"/platform/interactions/{row.interaction_id}", headers=platform_admin["headers"]
        ).json()
        assert resp["metadata"] == {"mode": "rag", "top_k": 5}
        assert "event_metadata" not in resp
    finally:
        _cleanup_interactions([row.interaction_id])


def test_no_internal_orm_leakage(client, platform_admin):
    row = _seed_interaction()
    try:
        resp = client.get(
            f"/platform/interactions/{row.interaction_id}", headers=platform_admin["headers"]
        ).json()
        assert set(resp.keys()) == {
            "id", "interaction_id", "organization_id", "user_id", "session_id",
            "trace_id", "service", "interaction_type", "action", "resource_type",
            "resource_id", "status", "decision", "metadata", "created_at",
        }
    finally:
        _cleanup_interactions([row.interaction_id])


def test_session_id_returned_exactly_as_persisted(client, platform_admin):
    """PR-B2 leaves session_id as an unvalidated value correlation -- B5-A
    must not join/validate it against UserSession, only echo it back."""
    row = _seed_interaction(session_id="not-a-real-session-uuid")
    try:
        resp = client.get(
            f"/platform/interactions/{row.interaction_id}", headers=platform_admin["headers"]
        ).json()
        assert resp["session_id"] == "not-a-real-session-uuid"
    finally:
        _cleanup_interactions([row.interaction_id])


# ── Privacy ──────────────────────────────────────────────────────────────

def test_secret_shaped_metadata_key_in_seeded_row_is_returned_as_persisted(client, platform_admin):
    """B5-A adds no second redaction layer (per its own brief): redaction
    already happens at the write boundary (interaction_service.py::
    _redact_metadata, and app/workers/interaction_consumer.py's reuse of
    it for stream-sourced events). A row that reaches the DB with a
    secret-shaped key already bypassed that boundary -- not something a
    read API can retroactively fix -- so this test documents current,
    intentional behavior (echoes exactly what's persisted) rather than
    asserting a redaction the API layer was explicitly told not to add.
    Synthetic, non-real value only -- never a real credential.
    """
    row = _seed_interaction(event_metadata={"mode": "rag", "note": "no-secret-here"})
    try:
        resp = client.get(
            f"/platform/interactions/{row.interaction_id}", headers=platform_admin["headers"]
        ).json()
        assert resp["metadata"] == {"mode": "rag", "note": "no-secret-here"}
    finally:
        _cleanup_interactions([row.interaction_id])
