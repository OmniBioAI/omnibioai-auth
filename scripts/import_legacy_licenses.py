#!/usr/bin/env python3
"""Phase 1 PR4, one-off: imports every row from the standalone
license_server.py's `omnibioai_licenses.licenses` table into this
service's `license_keys` table, ahead of decommissioning that service.

Field mapping:
    key                     -> key            (unique across both systems --
                                                see collision handling below)
    email                   -> email
    tier                    -> plan
    expiry (date string)    -> expires_at      (end of that day, matching
                                                the old service's inclusive
                                                `today > expiry_date` check)
    machine_id              -> machine_id
    created_at (date str)   -> created_at
    activated_at            -> last_used_at    (closest existing analog --
                                                this service has no separate
                                                "activated_at" column)
    is_active == 0          -> revoked_at set  (the old service's only
                                                notion of deactivation)

Every imported row gets platform="desktop" (the only client the old
service ever had) and organization_id = Default Org (the same convention
scripts/backfill_default_org.py uses -- per-email org resolution has no
implementation anywhere in org_service.py yet).

max_uses is set to a large sentinel (_EFFECTIVELY_UNLIMITED), not 1: the
old service had no usage cap at all (a license was checked on every app
launch, forever), but license_service.mark_used() increments usage_count
on every successful /validate. Importing with the new schema's max_uses
default of 1 would lock an already-active legacy user out on their very
next launch.

Guarantees:
- Transactional: every row is imported in a single commit, or (on any
  error) none are -- see main()'s rollback-and-re-raise.
- Idempotent / safe to re-run: a key already present from a prior run of
  this same script is skipped, not duplicated.
- Never overwrites: a key that exists in license_keys but was NOT created
  by a prior run of this script (i.e. a real collision between the two
  independently-keyspaced systems) is flagged for manual review and left
  untouched, exactly like it was found.

Usage:
    python scripts/import_legacy_licenses.py            # apply
    python scripts/import_legacy_licenses.py --verify    # check only, writes nothing
"""

import argparse
import datetime
import os
import sys
from pathlib import Path

# See scripts/backfill_default_org.py for why this is needed: run as a
# plain script (not via pytest), only this file's own directory lands on
# sys.path -- on a machine with sibling omnibioai-* repos pip-installed
# editable (several also use the generic top-level package name "app"),
# `import app...` can silently resolve to a different repo entirely
# without this. Explicit insert at position 0 guarantees this repo's own
# app/ wins.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine, text

from app.core.config import settings
from app.db.models import LicenseKey, Organization
from app.db.session import SessionLocal

# Legacy DB lives on the same MySQL instance as this service's own DB (per
# docker-compose.yml), just a different database name -- the one
# license_server.py's MYSQL_DATABASE env var defaulted to. No cross-network
# export/import needed.
_LEGACY_DB_NAME = os.getenv("LEGACY_LICENSE_DB_NAME", "omnibioai_licenses")

_EFFECTIVELY_UNLIMITED = 1_000_000

_IMPORT_REASON_PREFIX = "imported from legacy license_server:"


def _legacy_engine():
    legacy_url = (
        f"mysql+pymysql://{settings.DB_USER}:{settings.DB_PASSWORD}"
        f"@{settings.DB_HOST}:{settings.DB_PORT}/{_LEGACY_DB_NAME}"
    )
    return create_engine(legacy_url, pool_pre_ping=True)


def _fetch_legacy_rows(legacy_engine):
    with legacy_engine.connect() as conn:
        result = conn.execute(
            text(
                "SELECT `key`, email, tier, expiry, machine_id, created_at, "
                "activated_at, is_active FROM licenses"
            )
        )
        return [dict(row._mapping) for row in result]


def _parse_date(value: str | None) -> datetime.date | None:
    if not value:
        return None
    return datetime.date.fromisoformat(value)


def _get_default_org(db) -> Organization:
    org = db.query(Organization).filter(Organization.slug == "default").first()
    if not org:
        raise RuntimeError(
            "No Default Organization found -- app/db/init_admin.py's "
            "ensure_default_organization() must have run at least once "
            "before this import can run."
        )
    return org


def import_legacy_licenses(db, legacy_rows: list[dict], verify_only: bool = False) -> dict:
    org = _get_default_org(db)

    imported = 0
    already_present = 0
    collisions = []

    for row in legacy_rows:
        key = row["key"]
        existing = db.query(LicenseKey).filter(LicenseKey.key == key).first()

        if existing:
            imported_by_this_script = (
                existing.revoked_reason is not None
                and existing.revoked_reason.startswith(_IMPORT_REASON_PREFIX)
            ) or existing.email == row["email"] and existing.plan == row["tier"]
            if imported_by_this_script:
                already_present += 1
                continue
            collisions.append(
                {
                    "key": key,
                    "reason": "key_exists_in_license_keys_from_a_different_source",
                    "legacy_email": row["email"],
                    "existing_email": existing.email,
                }
            )
            continue

        if verify_only:
            imported += 1  # would-be count; nothing written in verify mode
            continue

        expiry_date = _parse_date(row["expiry"])
        created_date = _parse_date(row["created_at"])
        activated_date = _parse_date(row["activated_at"])
        is_active = bool(row["is_active"])

        license_key = LicenseKey(
            key=key,
            email=row["email"],
            plan=row["tier"],
            platform="desktop",
            organization_id=org.id,
            machine_id=row["machine_id"],
            max_uses=_EFFECTIVELY_UNLIMITED,
            usage_count=1 if activated_date else 0,
            expires_at=(
                datetime.datetime.combine(expiry_date, datetime.time.max)
                if expiry_date
                else None
            ),
            created_at=(
                datetime.datetime.combine(created_date, datetime.time.min)
                if created_date
                else datetime.datetime.utcnow()
            ),
            last_used_at=(
                datetime.datetime.combine(activated_date, datetime.time.min)
                if activated_date
                else None
            ),
            revoked_at=None if is_active else datetime.datetime.utcnow(),
            revoked_reason=(
                None if is_active else f"{_IMPORT_REASON_PREFIX} was inactive in legacy system"
            ),
        )
        db.add(license_key)
        imported += 1

    if not verify_only:
        db.commit()

    return {
        "total_legacy_rows": len(legacy_rows),
        "imported": imported,
        "already_present": already_present,
        "collisions": collisions,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verify", action="store_true", help="Check only, write nothing.")
    args = parser.parse_args()

    legacy_rows = _fetch_legacy_rows(_legacy_engine())

    db = SessionLocal()
    try:
        result = import_legacy_licenses(db, legacy_rows, verify_only=args.verify)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    mode = "VERIFY" if args.verify else "APPLY"
    print(
        f"[{mode}] total_legacy_rows={result['total_legacy_rows']} "
        f"imported={result['imported']} "
        f"already_present={result['already_present']} "
        f"collisions={len(result['collisions'])}"
    )
    for c in result["collisions"]:
        print(f"  COLLISION key={c['key']} legacy_email={c['legacy_email']} existing_email={c['existing_email']}")

    return 1 if result["collisions"] else 0


if __name__ == "__main__":
    sys.exit(main())
