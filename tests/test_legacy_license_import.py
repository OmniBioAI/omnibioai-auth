"""Phase 1 PR4: scripts/import_legacy_licenses.py correctness -- correct
field mapping from the legacy license_server.py schema, transactional,
idempotent, never overwrites a real collision.
"""

import datetime

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from app.db.base import Base
from app.db.models import LicenseKey, Organization
from scripts.import_legacy_licenses import _fetch_legacy_rows, import_legacy_licenses

_direct_engine = create_engine("sqlite:///./test.db")
_DirectSession = sessionmaker(bind=_direct_engine)


@pytest.fixture
def db(client):
    # `client` fixture (unused directly) guarantees app.main has already
    # run -- which is what actually creates the Default Organization this
    # import requires to exist (app/db/init_admin.py's
    # ensure_default_organization(), called at app import time).
    session = _DirectSession()
    try:
        yield session
    finally:
        session.close()


def _legacy_row(
    key,
    email="legacy@omnibioai.test",
    tier="pro",
    expiry="2099-12-31",
    machine_id=None,
    created_at="2026-01-01",
    activated_at=None,
    is_active=1,
):
    return {
        "key": key,
        "email": email,
        "tier": tier,
        "expiry": expiry,
        "machine_id": machine_id,
        "created_at": created_at,
        "activated_at": activated_at,
        "is_active": is_active,
    }


def _default_org(db):
    return db.query(Organization).filter(Organization.slug == "default").first()


# ── Field mapping / correctness ─────────────────────────────────────────────


def test_import_maps_fields_correctly(db):
    row = _legacy_row(
        key="OMNI-LEGA-CY01-TEST-0001",
        email="mapped@omnibioai.test",
        tier="enterprise",
        expiry="2030-06-15",
        machine_id="legacy-machine-abc",
        created_at="2025-01-10",
        activated_at="2025-02-01",
        is_active=1,
    )

    result = import_legacy_licenses(db, [row], verify_only=False)
    assert result["imported"] == 1
    assert result["collisions"] == []

    lic = db.query(LicenseKey).filter(LicenseKey.key == "OMNI-LEGA-CY01-TEST-0001").first()
    assert lic is not None
    assert lic.email == "mapped@omnibioai.test"
    assert lic.plan == "enterprise"  # tier -> plan
    assert lic.platform == "desktop"
    assert lic.machine_id == "legacy-machine-abc"
    assert lic.organization_id == _default_org(db).id
    assert lic.expires_at == datetime.datetime(2030, 6, 15, 23, 59, 59, 999999)
    assert lic.created_at == datetime.datetime(2025, 1, 10, 0, 0, 0)
    assert lic.last_used_at == datetime.datetime(2025, 2, 1, 0, 0, 0)
    assert lic.usage_count == 1  # activated_at present -> was in use
    assert lic.revoked_at is None
    # Not a hard usage cap like the new schema's default of 1 -- the old
    # service had no cap at all, and every /validate call increments
    # usage_count, so a low max_uses would lock an active user out.
    assert lic.max_uses >= 1_000_000


def test_import_maps_inactive_license_as_revoked(db):
    row = _legacy_row(key="OMNI-LEGA-CY02-TEST-0002", is_active=0)

    import_legacy_licenses(db, [row], verify_only=False)

    lic = db.query(LicenseKey).filter(LicenseKey.key == "OMNI-LEGA-CY02-TEST-0002").first()
    assert lic.revoked_at is not None
    assert "legacy" in lic.revoked_reason


def test_import_never_activated_license_has_zero_usage(db):
    row = _legacy_row(key="OMNI-LEGA-CY03-TEST-0003", activated_at=None, machine_id=None)

    import_legacy_licenses(db, [row], verify_only=False)

    lic = db.query(LicenseKey).filter(LicenseKey.key == "OMNI-LEGA-CY03-TEST-0003").first()
    assert lic.usage_count == 0
    assert lic.last_used_at is None
    assert lic.machine_id is None


# ── Idempotency ──────────────────────────────────────────────────────────────


def test_import_is_idempotent(db):
    row = _legacy_row(key="OMNI-LEGA-CY04-TEST-0004")

    first = import_legacy_licenses(db, [row], verify_only=False)
    assert first["imported"] == 1

    second = import_legacy_licenses(db, [row], verify_only=False)
    assert second["imported"] == 0
    assert second["already_present"] == 1
    assert second["collisions"] == []

    count = db.query(LicenseKey).filter(LicenseKey.key == "OMNI-LEGA-CY04-TEST-0004").count()
    assert count == 1  # no duplicate row


# ── Collision handling ───────────────────────────────────────────────────────


def test_import_flags_real_collision_without_overwriting(db):
    """A key that already exists in license_keys for a DIFFERENT license
    (not a prior run of this import) must be left completely untouched and
    reported, never silently overwritten."""
    org = _default_org(db)
    existing = LicenseKey(
        key="OMNI-COLL-IDE0-TEST-0005",
        email="native@omnibioai.test",
        plan="beta",
        platform="web",
        organization_id=org.id,
        max_uses=1,
        usage_count=0,
    )
    db.add(existing)
    db.commit()

    colliding_row = _legacy_row(
        key="OMNI-COLL-IDE0-TEST-0005", email="legacy-someone-else@omnibioai.test", tier="pro"
    )

    result = import_legacy_licenses(db, [colliding_row], verify_only=False)
    assert result["imported"] == 0
    assert len(result["collisions"]) == 1
    assert result["collisions"][0]["key"] == "OMNI-COLL-IDE0-TEST-0005"

    db.refresh(existing)
    assert existing.email == "native@omnibioai.test"  # untouched
    assert existing.plan == "beta"  # untouched


# ── Verify-only mode ─────────────────────────────────────────────────────────


def test_verify_mode_writes_nothing(db):
    row = _legacy_row(key="OMNI-LEGA-CY06-TEST-0006")

    result = import_legacy_licenses(db, [row], verify_only=True)
    assert result["imported"] == 1  # would-be count reported

    count = db.query(LicenseKey).filter(LicenseKey.key == "OMNI-LEGA-CY06-TEST-0006").count()
    assert count == 0  # but nothing was actually written


# ── Missing Default Organization ────────────────────────────────────────────


def test_raises_without_default_organization(tmp_path):
    """Isolated throwaway DB, deliberately never running
    ensure_default_organization -- confirms the import fails loudly rather
    than silently landing rows with no organization."""
    import app.db.models  # noqa: F401 -- registers all tables on Base.metadata

    db_file = tmp_path / "no_default_org.db"
    engine = create_engine(f"sqlite:///{db_file}")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    try:
        with pytest.raises(RuntimeError, match="No Default Organization found"):
            import_legacy_licenses(session, [_legacy_row(key="OMNI-NOOR-G000-TEST-0007")], verify_only=True)
    finally:
        session.close()


# ── Legacy DB read layer ─────────────────────────────────────────────────────


def test_fetch_legacy_rows_reads_old_schema_shape():
    """Exercises the actual SQL against a throwaway table built with the
    exact column set license_server.py's init_db() creates, independent of
    the mapping logic tested above (which takes plain dicts)."""
    legacy_engine = create_engine("sqlite:///:memory:")
    with legacy_engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE licenses (
                    `key` VARCHAR(255) PRIMARY KEY,
                    email VARCHAR(255) NOT NULL,
                    tier VARCHAR(50) NOT NULL,
                    expiry VARCHAR(20) NOT NULL,
                    machine_id VARCHAR(255),
                    created_at VARCHAR(20) NOT NULL,
                    activated_at VARCHAR(20),
                    is_active INTEGER DEFAULT 1
                )
                """
            )
        )
        conn.execute(
            text(
                "INSERT INTO licenses (`key`, email, tier, expiry, machine_id, created_at, activated_at, is_active) "
                "VALUES ('OMNI-FETC-H000-TEST-0008', 'fetch@omnibioai.test', 'beta', '2099-01-01', NULL, '2026-01-01', NULL, 1)"
            )
        )

    rows = _fetch_legacy_rows(legacy_engine)
    assert len(rows) == 1
    assert rows[0]["key"] == "OMNI-FETC-H000-TEST-0008"
    assert rows[0]["email"] == "fetch@omnibioai.test"
    assert rows[0]["tier"] == "beta"
    assert rows[0]["is_active"] == 1
