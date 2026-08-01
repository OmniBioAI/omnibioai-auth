# Migration Deployment Checklist (omnibioai-auth)

Generic checklist for applying an Alembic migration to a real environment.
Reusable for future revisions, not just `0001`/`0002`. See `MIGRATIONS.md` for
background on why the baseline is `stamp`ed rather than `upgrade`d.

## Before touching anything

- [ ] Full `mysqldump` taken and stored somewhere other than the database's
      own disk/volume (see `MIGRATIONS.md` → Backup procedure)
- [ ] `alembic current` run against the target database — confirm which
      revision (if any) it's already at, so you know whether `stamp` or
      `upgrade` is the correct next command
- [ ] `alembic history --verbose` reviewed so the exact set of revisions
      about to be applied is known ahead of time, not discovered mid-deploy
- [ ] For a **first-time** rollout of Alembic to an environment that
      predates it (i.e. `alembic current` shows no revision but the tables
      already exist): confirm the plan is `alembic stamp 0001_baseline` +
      `alembic upgrade head`, not a plain `alembic upgrade head` from empty
- [ ] If this is production (or any environment whose data matters): the
      "Required verification before production use" steps in
      `MIGRATIONS.md` have been completed against a restored snapshot first

## Applying the migration

- [ ] Confirm no other deploy/migration is in flight against the same
      database (single MySQL instance, no read replica — there is only one
      copy of this data)
- [ ] Run the migration command(s) directly against the target database,
      outside of application startup (this repo's `app/main.py` does not
      run migrations itself — see `MIGRATIONS.md`)
- [ ] Run `python scripts/verify_schema.py --expect-revision <target>`
      immediately after, before deploying any application code that depends
      on the new schema
- [ ] Only after verification passes: deploy application code changes, if
      any accompany this migration (for `0001`+`0002` specifically: none —
      no application code depends on the new tables yet, so this step is a
      no-op for this particular migration)

## If something goes wrong mid-migration

- [ ] Stop — do not attempt to "fix forward" by hand-editing the database
- [ ] Restore from the pre-migration backup taken above
- [ ] Re-run `alembic current` against the restored database to confirm it's
      back at the expected starting revision
- [ ] Diagnose the migration script itself against a scratch copy of the
      backup before attempting to re-apply it anywhere real

## Rollback (if the migration applied cleanly but needs to be reversed)

- [ ] `alembic downgrade <previous-revision>` — for `0002_multi_tenant_schema`
      specifically, this drops the 7 new tables and the 3 new `license_keys`
      columns, and is safe: nothing in the application reads or writes them
      yet
- [ ] Never run `alembic downgrade base` (past `0001_baseline`) against an
      environment with real data — it drops the original auth tables
- [ ] Re-run `scripts/verify_schema.py --expect-revision <previous-revision>`
      to confirm the rollback landed where expected

## Zero-downtime note

Schema-only changes in this migration (`0001` stamp + `0002` upgrade) do not
require restarting the `auth-service` container — they're additive DDL against
tables/columns no running code references yet. No application deploy is
bundled with this particular migration. If a future migration does pair a
schema change with an application code change, see the zero-downtime
discussion in the Phase 1 migration strategy document for what this
single-MySQL-instance, single-`auth-service`-container Docker Compose setup
can and cannot do without added blue-green infrastructure.
