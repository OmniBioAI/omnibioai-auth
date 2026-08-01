#!/usr/bin/env python3
"""One-off backfill: copies every existing user's global role assignment
(user_roles) into an organization_memberships/membership_roles entry under
the Default Organization, so JWT v2's org_id/org_role reflect real
membership the moment this has run, instead of every pre-PR3 account
carrying org_id=None forever.

Guarantees:
- Never modifies the original user_roles table -- this is a copy of the
  assignment (reusing the same Role rows), not a migration of that data.
  user_roles remains fully intact and is still what require_permission's
  JWT-embedded `permissions` claim is computed from.
- Never touches global_config -- this script does not read or write it at
  all. (Copying it into organization_config, per the Phase 1 design doc,
  is separate work, not part of this script.)
- Transactional: every user is backfilled in a single commit, or (on any
  error) none are -- see main()'s rollback-and-re-raise.
- Idempotent / safe to re-run: a user who already has a Default Org
  membership is skipped, not duplicated. If an existing membership's
  permissions have drifted from their current global permissions, that's
  reported as a mismatch rather than silently overwritten.

Usage:
    python scripts/backfill_default_org.py            # apply
    python scripts/backfill_default_org.py --verify    # check only, writes nothing
"""

import argparse
import sys

from app.db.models import Organization, OrganizationMembership, User
from app.db.session import SessionLocal
from app.services import role_service


def _get_default_org(db) -> Organization:
    org = db.query(Organization).filter(Organization.slug == "default").first()
    if not org:
        raise RuntimeError(
            "No Default Organization found -- app/db/init_admin.py's "
            "ensure_default_organization() must have run at least once "
            "(i.e. the auth-service must have started at least once since "
            "Phase 1 PR2) before this backfill can run."
        )
    return org


def backfill(db, verify_only: bool = False) -> dict:
    org = _get_default_org(db)

    users = db.query(User).all()
    already_present = 0
    backfilled = 0
    mismatches = []

    for user in users:
        existing = (
            db.query(OrganizationMembership)
            .filter(
                OrganizationMembership.organization_id == org.id,
                OrganizationMembership.user_id == user.id,
            )
            .first()
        )
        global_perms = role_service.permissions_for_roles(user.roles)

        if existing:
            already_present += 1
            org_perms = role_service.permissions_for_roles(existing.roles)
            if org_perms != global_perms:
                mismatches.append(
                    {
                        "user_id": user.id,
                        "reason": "existing_default_org_membership_diverged",
                        "global": sorted(global_perms),
                        "org": sorted(org_perms),
                    }
                )
            continue

        if verify_only:
            backfilled += 1  # would-be count; nothing written in verify mode
            continue

        membership = OrganizationMembership(
            organization_id=org.id,
            user_id=user.id,
            status="active",
        )
        # Same Role rows the user already holds globally -- not a new
        # org_admin/org_member catalog entry (that convention is for
        # brand-new orgs created via the API, see org_service.py). This is
        # a byte-for-byte permission-preserving copy, which is exactly why
        # a mismatch after this runs would mean the script itself is wrong.
        membership.roles = list(user.roles)
        db.add(membership)
        backfilled += 1

    if not verify_only:
        db.commit()

    return {
        "total_users": len(users),
        "already_present": already_present,
        "backfilled": backfilled,
        "mismatches": mismatches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--verify", action="store_true", help="Check only, write nothing.")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        result = backfill(db, verify_only=args.verify)
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    mode = "VERIFY" if args.verify else "APPLY"
    print(
        f"[{mode}] total_users={result['total_users']} "
        f"already_present={result['already_present']} "
        f"backfilled={result['backfilled']} "
        f"mismatches={len(result['mismatches'])}"
    )
    for m in result["mismatches"]:
        print(f"  MISMATCH user_id={m['user_id']} global={m['global']} org={m['org']}")

    return 1 if result["mismatches"] else 0


if __name__ == "__main__":
    sys.exit(main())
