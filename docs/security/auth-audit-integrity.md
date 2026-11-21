# Auth audit record integrity

New rows in `audit_events` use canonicalization version 1 and HMAC-SHA-256.
The canonical record covers event type, actor and target IDs, organization
ID, resource type and ID, before/after state, metadata, and creation
timestamp. The field set is fixed and each field is
always represented; JSON object keys are sorted recursively, arrays retain
order, NULL remains distinct from an empty string/object, and timestamps
use a fixed microsecond ISO representation. The HMAC key is not stored in
the database.

Runtime configuration must provide `AUTH_AUDIT_INTEGRITY_KEY` as at least
64 hexadecimal characters representing at least 32 random bytes. Generate
it using an operating-system CSPRNG and provide it from the deployment's
protected secret mechanism. It must be independent from JWT, session,
OAuth, database, Redis, interaction-worker, and shared Security Audit
credentials. There is no default or key derivation. Missing or malformed
key material makes audit signing fail closed. Tests set an explicit
test-only key in `tests/conftest.py`.

`verify_record` returns `valid`, `invalid`, `legacy_unsigned`, or
`unsupported_version`. Rows whose integrity columns are all NULL are
legacy unsigned records; the additive migration does not rewrite or sign
historical data. A partial metadata tuple is not considered legacy.

Migration `0028_auth_audit_integrity` adds only nullable integrity columns
and database triggers rejecting UPDATE and DELETE on `audit_events` for
SQLite and MySQL. INSERT and SELECT remain available. This is storage-level
append-only protection; database administrators with trigger/schema
privileges remain outside the application-level boundary and must be
controlled separately.

On MySQL the migration creates `auth_audit_events_no_update` and
`auth_audit_events_no_delete` without a `DEFINER` clause, so their definer
is the account that runs `alembic upgrade` (`CURRENT_USER()`), not a fixed
account. Requirements:

- Run the migration as the account that should own the triggers (the
  schema-migration account, not the application runtime account). It needs
  the `TRIGGER` privilege on the schema.
- With binary logging on (the MySQL 8 default), MySQL rejects
  `CREATE TRIGGER` from an account without `SUPER` (error 1419) unless the
  server sets `log_bin_trust_function_creators=1`. Set that on the server
  rather than running the migration as an administrative account.
- That account must keep existing: MySQL refuses to fire a trigger whose
  definer account has been dropped, and the guarded UPDATE/DELETE then
  fails with a definer error instead of the append-only message.
- A logical dump (`mysqldump`) records each trigger's definer. When
  restoring onto a server where that account does not exist, restore as
  the intended owner account and recreate the two triggers there, or edit
  the `DEFINER=` clauses in the dump before loading it.
- Check after a migration or restore:

  ```sql
  SELECT TRIGGER_NAME, DEFINER FROM information_schema.TRIGGERS
  WHERE TRIGGER_SCHEMA = DATABASE() AND EVENT_OBJECT_TABLE = 'audit_events';
  ```

`tests/test_migrations.py::test_mysql_auth_audit_integrity_triggers_block_mutation`
asserts that both triggers' definer equals the migrating connection's
`CURRENT_USER()`.

This implementation does not provision a production credential or apply
the migration to production. Production activation requires separately
provisioning the independent key through protected deployment configuration
and applying the reviewed migration.
