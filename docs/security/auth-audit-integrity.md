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

This implementation does not provision a production credential or apply
the migration to production. Production activation requires separately
provisioning the independent key through protected deployment configuration
and applying the reviewed migration.
