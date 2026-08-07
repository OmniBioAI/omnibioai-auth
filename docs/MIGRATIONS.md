# Database Migrations (omnibioai-auth)

This service used to create its schema purely via `Base.metadata.create_all(bind=engine)`
at startup (`app/main.py`), with no versioned migration history. Alembic is now
initialized (see `alembic/`), but `create_all()` has **not** been removed from
`app/main.py` yet — that removal is deliberately deferred to a later, separate
change once Alembic has proven itself in real deployments (see "Known risk:
create_all() vs. Alembic drift" below — this is not a free lunch).

> **Note (2026-08-06):** the paragraph that used to be here claimed
> `create_all()` and Alembic "manage disjoint sets of tables" because the
> newer multi-tenant/org/audit/MFA tables were "not backed by any ORM class
> yet". That's no longer true and hasn't been for a while — nearly every
> table this service owns (`organizations`, `teams`, `api_keys`,
> `oauth_clients`, `organization_sso_configs`, `audit_events`,
> `mfa_devices`, `mfa_recovery_codes`, `organization_mfa_policies`, ...) is
> now backed by an ORM class in `app/db/models.py`, registered on the same
> `Base.metadata` `create_all()` walks at every startup. See the section
> below for what that actually means in practice.

## Known risk: `create_all()` vs. Alembic drift

`create_all()` only ever issues `CREATE TABLE IF NOT EXISTS` — for any
table that already exists, it does **nothing**, including when the ORM's
Python-side `Column` definitions have gained a new column since the table
was created. Only `alembic upgrade head` actually alters an existing
table.

This is exactly what caused a production crash-loop on 2026-08-06:
`alembic/versions/0016_role_org_scope.py` added `roles.organization_id` to
the `Role` ORM class and a matching migration, but the migration was never
run against the deployed database. `create_all()` ran at every startup and
silently did nothing (the `roles` table already existed), so the missing
column went unnoticed until `create_admin()`'s bootstrap code issued the
first query that referenced it, which crashed with a raw
`pymysql.err.OperationalError (1054, "Unknown column 'roles.organization_id'
in 'field list'")` deep inside SQLAlchemy — an opaque failure with no
indication of what to actually do about it, repeating on every container
restart.

**Fix applied for this incident:** `alembic upgrade head` was run directly
against the affected database (`0015_refresh_token_length` →
`0016_role_org_scope`), per the procedure this document already
prescribed — the gap was that nothing enforced it actually happening
before the container was (re)started.

**Structural fix (`app/db/schema_guard.py`):** `app/main.py` now calls
`assert_schema_matches_models(engine, Base.metadata)` immediately after
`create_all()` and before any bootstrap query runs. It diffs every
already-existing table's live columns against what the ORM currently
declares and refuses to start — with a message naming the missing
columns and pointing at `alembic upgrade head` — if any are missing,
rather than letting bootstrap crash on whichever query happens to touch
the gap first. It does not run migrations itself and does not consult
Alembic's own bookkeeping table; it only checks "does the live schema
already satisfy what the code needs". This is a diagnostic/fail-fast net,
not a substitute for actually running migrations before deploying —
`create_all()` is still not removed, and its removal is still deferred
(see the note above) since a straightforward removal would leave any
environment that has never run Alembic at all with zero tables at
startup instead of a clear error.

Historically, the two mechanisms mostly coexisted without conflict
because they manage overlapping but not-identical concerns:
`create_all()` only ever touches tables backed by an ORM class registered
on `app.db.base.Base`, and can create a brand-new such table from scratch
(matching *today's* model definition, columns included) if the migration
that's supposed to create it hasn't run yet. What it cannot do — ever —
is bring an *existing* table's columns up to date, which is the specific
gap `schema_guard.py` now catches instead of letting it crash bootstrap.

## Revision history

**This table is only maintained through `0010_role_description`.** Revisions
`0011` through `0016` (audit events, MFA foundation/recovery/org-policy,
refresh token length, `roles.organization_id` — see "Known risk" above) all
exist and are all purely additive in the same spirit as the rows below; run
`alembic history --verbose` against `alembic/` for the authoritative,
current list rather than trusting this table to be exhaustive. An
out-of-date table like this one is itself a symptom of the drift risk
described above — treat it as a caveat, not a promise.

| Revision | What it does | How to apply it |
|---|---|---|
| `0001_baseline` | Describes the schema exactly as it existed before Alembic was introduced (`users`, `roles`, `permissions`, `user_roles`, `role_permissions`, `refresh_tokens`, `revoked_tokens`, `oauth_accounts`, `global_config`, `license_keys`). Hand-authored from the live schema (`DESCRIBE`/`SHOW CREATE TABLE` output), not autogenerated. | **On any environment where these tables already exist (every current environment): `alembic stamp 0001_baseline`, never `alembic upgrade`.** On a genuinely empty/fresh database only, `alembic upgrade 0001_baseline` creates them for real. |
| `0002_multi_tenant_schema` | Purely additive: creates `organizations`, `teams`, `team_memberships`, `organization_memberships`, `membership_roles`, `api_keys`, `organization_config`; adds nullable `organization_id`, `machine_id`, `max_devices` columns to `license_keys`. Does not alter, rename, or drop anything existing. | `alembic upgrade head` (after `0001` has been stamped) on every environment — this is the only revision that executes real DDL against an existing database. |
| `0003_oauth_clients` | Phase 2 PR1: purely additive, creates `oauth_clients` (OAuth 2.1 client_credentials grant registrations). No relationship to `api_keys` or any other existing table beyond FKs into `organizations`/`users`. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0002_multi_tenant_schema`. |
| `0004_org_sso_schema` | Phase 2 PR2: creates `organization_sso_configs` (per-org OIDC IdP registration, unused until Phase 2 PR3/PR4); adds nullable `organization_sso_config_id` to `oauth_accounts` and widens its unique constraint from `(provider, provider_user_id)` to `(provider, provider_user_id, organization_sso_config_id)`. Every existing row has the new column NULL and still satisfies the widened constraint unchanged -- no existing row's value changes. The constraint drop+add happens inside one `batch_alter_table` transactional step, not as separate manual commands. | `alembic upgrade head` on every environment already at `0003_oauth_clients`. |
| `0005_org_sso_operational_fields` | Phase 2 PR3: purely additive, adds nullable `last_verified_at`/`verification_error` to `organization_sso_configs` for future enterprise troubleshooting. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0004_org_sso_schema`. |
| `0006_sso_enforcement_override` | Phase 2 PR5: purely additive, adds nullable `sso_override_at`/`sso_override_reason`/`sso_override_by_user_id` to `organization_sso_configs` -- the break-glass bypass for `enforced`. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0005_org_sso_operational_fields`. |
| `0007_refresh_token_rotation` | Phase 3 PR0.2: purely additive, adds nullable `family_id`/`rotated_at` to `refresh_tokens` so `/auth/refresh` can rotate on every use and detect replay of an already-rotated token. Every existing row gets NULL for both and is treated as a single-member family the first time it's used post-migration. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0006_sso_enforcement_override`. |
| `0008_org_status_tracking` | Phase 3 PR2: purely additive, adds nullable `status_changed_at`/`status_changed_reason`/`status_changed_by_user_id` to `organizations` -- who/why/when for a platform admin's suspend/reactivate action, mirroring `0006`'s SSO override columns. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0007_refresh_token_rotation`. |
| `0009_user_directory_fields` | Phase 3 PR3A: purely additive, adds nullable `created_at` and `status_changed_at`/`status_changed_reason`/`status_changed_by_user_id` to `users` -- the platform-admin user directory's "Created" column plus the same suspend/reactivate tracking `0008` added for organizations. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0008_org_status_tracking`. |
| `0010_role_description` | Phase 3 PR3B: purely additive, adds nullable `description` to `roles` for the new platform-admin/org-scoped role management UI's RoleSummary response. Does not alter, rename, or drop anything existing. | `alembic upgrade head` on every environment already at `0009_user_directory_fields`. |

## Why `stamp`, not `upgrade`, for the baseline

Every environment this service currently runs in already has these 10 tables
(created historically by `create_all()`). Running `alembic upgrade 0001_baseline`
against such a database would attempt `CREATE TABLE users` and fail with a
duplicate-table error. `alembic stamp 0001_baseline` instead just writes a row
into Alembic's own `alembic_version` bookkeeping table, asserting "this
database is already at this revision" without touching any of the 10 tables.
`0002` then applies normally on top via `alembic upgrade head`.

A fresh environment (a new dev sandbox, a CI database, a from-scratch
install) has no existing tables, so `alembic upgrade head` there runs both
`0001` and `0002` for real, from empty — this is also how `tests/test_migrations.py`
exercises the full migration path.

## Required verification before production use

**`0001_baseline` must be diffed against a real restored production/staging
snapshot before this revision is stamped or applied anywhere that matters.**
It was hand-written from this dev environment's live schema (`omnibioai`
database on the local MySQL container) at the time of writing, cross-checked
column-by-column via `DESCRIBE`/`SHOW CREATE TABLE`, and further validated by
running a real `alembic upgrade head` against a throwaway MySQL database (see
`tests/test_migrations.py`, MySQL variant). That is strong evidence for *this*
environment but is **not** a substitute for verifying against production
directly — dev and production schemas can silently diverge. Before any real
deployment:

1. Restore the most recent production backup to a scratch MySQL instance.
2. Run `alembic stamp 0001_baseline` against it.
3. Run `python scripts/verify_schema.py --expect-revision 0001_baseline` (see
   below) to confirm Alembic's bookkeeping and the actual table/column set
   agree.
4. Only then proceed to `alembic upgrade head` for `0002` against that same
   scratch instance, followed by the same verification script with
   `--expect-revision head`, before ever running either step against the
   real production database.

## Backup procedure

Always take a full logical backup immediately before running any Alembic
command against a database that holds real data:

```bash
mysqldump -h <host> -u <user> -p \
  --single-transaction --routines --triggers \
  <database> > backup_$(date +%Y%m%d_%H%M%S).sql
```

`--single-transaction` avoids locking InnoDB tables for the duration of the
dump. Keep the backup off the same disk/volume as the database itself.

## Common commands

```bash
# Check current revision recorded in the database
alembic current

# See full history
alembic history --verbose

# Stamp an existing database at the baseline (no DDL executed)
alembic stamp 0001_baseline

# Apply everything after the stamped baseline
alembic upgrade head

# Reverse the multi-tenant schema migration only (drops the 7 new tables +
# 3 new license_keys columns; never touches the original 10 tables)
alembic downgrade 0001_baseline
```

`alembic downgrade base` (reversing past `0001_baseline`) drops the original
10 tables and must never be run against an environment with real data — it
exists only so `tests/test_migrations.py` can exercise a full upgrade/downgrade
cycle against a throwaway database.

## Connection configuration

`alembic/env.py` does not hardcode a database URL in `alembic.ini` (avoids
committing credentials/hosts to version control). It reuses
`app.core.config.settings.DATABASE_URL` — the exact same connection string
the running FastAPI app uses — so migrations always target the same database
the app itself would connect to, driven by the same `DB_HOST`/`DB_USER`/
`DB_PASSWORD`/`DB_NAME` environment variables.
