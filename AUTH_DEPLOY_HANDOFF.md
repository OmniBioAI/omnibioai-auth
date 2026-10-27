# Auth HEAD deployment handoff

Date: 2026-10-27  
Target project: `omnibioai-studio`  
Target Auth commit/image: `b9819e0b57f4` / `obai-auth-v62:b9819e0b57f4`

## Current decision: NO-GO

Do not deploy until all of these are resolved:

1. `/mnt/wdpro26tb` is not mounted. The required off-volume backup cannot be
   created at `/mnt/wdpro26tb/omnibioai/backups/`.
2. The running Auth service does not use the `mysql` service shown in the base
   Compose file. `docker-compose.override.yml` points it at
   `omnibioai-full-mac-dev-v1`, database `omnibioai`.
3. That actual database already records Alembic head
   `0035_organization_invitations`; it is not in the stated first-rollout
   state. Its `alembic_version` table was created on 2026-10-14, and the
   0032--0035 objects were created on 2026-10-19. The historical pre-stamp
   revision can no longer be established from the current live database.
4. HEAD `scripts/verify_schema.py --expect-revision head` fails at 0035. Its
   revision/table manifest stops at 0010 and must be updated and reviewed
   before it can serve as the mandatory deployment gate.
5. A from-empty rehearsal with a database-scoped migration user stops at 0028:
   MySQL binary logging rejects `CREATE TRIGGER` with error 1419. Do not grant
   a schema migration principal global `SUPER`; establish and review the
   approved trigger-creation mechanism separately if a full empty replay is
   still required.

## Pre-flight and maintenance window

Auth is a dependency of Studio, Control Center, API Gateway, TES, Workbench,
LIMS SSO, ToolServer, and other IAM clients. Announce a maintenance window and
pause writes/login traffic before any restore or schema migration. One
designated deployment owner must perform the whole sequence; do not run another
`obai-deploy` or Auth migration concurrently.

```bash
set -euo pipefail
export MACHINE_DIR=/home/manish/Desktop/omnibioai-ecosystem
export AUTH_REPO="$MACHINE_DIR/omnibioai-auth"
export STUDIO_DIR="$MACHINE_DIR/omnibioai-studio"
export AUTH_IMAGE=obai-auth-v62:b9819e0b57f4
export MYSQL_CONTAINER=omnibioai-full-mac-dev-v1
export MYSQL_NETWORK=omnibioai-full-mac-dev-v1-net
export AUTH_DB=omnibioai
export EXPECTED_REVISION=0035_organization_invitations

cd "$STUDIO_DIR"
obai-deploy check
obai-deploy status

# Abort if another deploy owns the lock.
flock -n "${XDG_RUNTIME_DIR:-$HOME/.cache}/obai-deploy.lock" true

# The backup volume must be a real mount, not the root filesystem directory.
findmnt --mountpoint /mnt/wdpro26tb
test "$(findmnt -n -o TARGET /mnt/wdpro26tb)" = /mnt/wdpro26tb
install -d -m 700 /mnt/wdpro26tb/omnibioai/backups
export BACKUP_PATH="/mnt/wdpro26tb/omnibioai/backups/omnibioai_auth_predeploy_$(date -u +%Y%m%dT%H%M%SZ).sql"

# Root secret remains inside the DB container and is passed through MYSQL_PWD,
# never as a mysql/mysqldump command-line password.
docker exec "$MYSQL_CONTAINER" sh -lc \
  'MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysqldump -uroot --single-transaction --routines --triggers omnibioai' \
  > "$BACKUP_PATH"
chmod 600 "$BACKUP_PATH"
test -s "$BACKUP_PATH"
tail -n 1 "$BACKUP_PATH"

# Reconfirm the actual target and recorded revision immediately before work.
docker exec "$MYSQL_CONTAINER" sh -lc \
  'MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysql -uroot --batch --skip-column-names -e \
  "SELECT version_num FROM omnibioai.alembic_version"'
```

The observed database is already at `0035_organization_invitations`, so no
stamp or upgrade is currently justified. If the query does not return exactly
that one row, stop and repeat snapshot analysis; do not guess a stamp.

For a separately verified restored snapshot that has Auth schema through 0030
but no Alembic bookkeeping, the intended first-rollout value is
`0030_user_timezone`; 0031--0035 contain guards for their known `create_all()`
pre-creation cases. This conditional value must not be applied to the current
live database merely to recreate the old plan.

## Short-lived migration principal and migration gate

Run this only after the verifier supports every revision through 0035 and a
fresh rehearsal passes. The principal is scoped to `omnibioai` and receives
DDL plus the DML Alembic migrations use. It receives no global privileges.

```bash
set -euo pipefail
MIGRATION_USER=obai_auth_migration_20261027
MIGRATION_PASSWORD="$(openssl rand -hex 32)"
MIGRATION_ENV="$(mktemp /tmp/obai-auth-migration.XXXXXX.env)"
chmod 600 "$MIGRATION_ENV"
trap 'rm -f "$MIGRATION_ENV"; unset MIGRATION_PASSWORD' EXIT

docker exec -e MIGRATION_USER="$MIGRATION_USER" \
  -e MIGRATION_PASSWORD="$MIGRATION_PASSWORD" \
  "$MYSQL_CONTAINER" sh -lc '
    MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysql -uroot -e "
      CREATE USER IF NOT EXISTS '\''${MIGRATION_USER}'\''@'\''%'\'' IDENTIFIED BY '\''${MIGRATION_PASSWORD}'\'';
      GRANT ALTER, CREATE, DROP, INDEX, REFERENCES, SELECT, INSERT, UPDATE, DELETE,
            CREATE VIEW, SHOW VIEW, TRIGGER
        ON omnibioai.* TO '\''${MIGRATION_USER}'\''@'\''%'\'';
      FLUSH PRIVILEGES;"'

printf 'MIGRATION_DATABASE_URL=mysql+pymysql://%s:%s@%s:3306/%s\nDB_HOST=%s\nDB_PORT=3306\nDB_NAME=%s\nDB_USER=%s\nDB_PASSWORD=%s\n' \
  "$MIGRATION_USER" "$MIGRATION_PASSWORD" "$MYSQL_CONTAINER" "$AUTH_DB" \
  "$MYSQL_CONTAINER" "$AUTH_DB" "$MIGRATION_USER" "$MIGRATION_PASSWORD" \
  > "$MIGRATION_ENV"

# Current observed state: stamp is redundant and upgrade is a no-op. Keep the
# explicit revision so an unexpected target cannot silently be labeled head.
docker run --rm --network "$MYSQL_NETWORK" --env-file "$MIGRATION_ENV" \
  "$AUTH_IMAGE" alembic stamp "$EXPECTED_REVISION"
docker run --rm --network "$MYSQL_NETWORK" --env-file "$MIGRATION_ENV" \
  "$AUTH_IMAGE" alembic upgrade head

# After scripts/verify_schema.py is fixed, run the mandatory read-only gate:
docker run --rm --network "$MYSQL_NETWORK" --env-file "$MIGRATION_ENV" \
  "$AUTH_IMAGE" python scripts/verify_schema.py --expect-revision head

docker exec -e MIGRATION_USER="$MIGRATION_USER" "$MYSQL_CONTAINER" sh -lc '
  MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysql -uroot -e "
    DROP USER IF EXISTS '\''${MIGRATION_USER}'\''@'\''%'\'';
    FLUSH PRIVILEGES;"'
rm -f "$MIGRATION_ENV"
unset MIGRATION_PASSWORD
trap - EXIT
```

If working from a newly verified pre-rollout snapshot instead, replace only
the stamp argument with its evidence-backed revision (expected 0030 for the
original scenario), then upgrade. Never run `upgrade head` from base against a
database whose baseline tables already exist.

## Required Compose environment diff (do not apply from this handoff)

Startup itself defaults safely to production/validate, and an unset email OTP
pepper does not crash while email MFA is disabled. Explicitly pin the startup
policy, and configure manual-license issuance because the requested smoke test
includes issuing a license:

```diff
 services:
   auth-service:
     environment:
+      APP_ENV: production
+      AUTH_STARTUP_SCHEMA_MODE: validate
+      ADMIN_BOOTSTRAP_EMAIL: ${AUTH_ADMIN_BOOTSTRAP_EMAIL:?set to the verified email for users.id=1}
+      LICENSE_KEY_PEPPER_FILE: /run/secrets/license_key_pepper
+      LICENSE_ALLOWED_VALIDITY_DAYS: ${LICENSE_ALLOWED_VALIDITY_DAYS:?set approved values, e.g. 30,90,365}
+    volumes:
+      - ${AUTH_LICENSE_KEY_PEPPER_FILE:?set a mode-0400/0600 secret file}:/run/secrets/license_key_pepper:ro
```

Set `AUTH_ADMIN_BOOTSTRAP_EMAIL` to the exact email returned by the approved
read-only lookup for `users.id=1`; do not infer it from the operator's login.
That live lookup was not available from this Docker-restricted session, so the
value remains deliberately required and unresolved here. Confirm it maps to
ID 1 before applying this diff.

Do not add email-MFA or invitation delivery variables unless those features are
being enabled in this release. If enabled, review and supply the independent
`EMAIL_MFA_OTP_PEPPER` (or file), email service URL/token/from address, and the
invitation enable flag plus public acceptance URL.

## Pin and deploy Auth only

Do not use `deploy-all`. Do not deploy any retired license-server proxy branch.

```bash
cd "$STUDIO_DIR"
obai-deploy check
obai-deploy pin auth-service "$AUTH_IMAGE"
obai-deploy deploy auth-service
obai-deploy status
```

## Smoke tests

Use an interactive password prompt so the admin password never enters shell
history or process arguments. Keep response/token files mode 0600 and remove
them afterward.

```bash
set -euo pipefail
AUTH_BASE=https://webstudio.omnibioai.org/_svc/auth
ADMIN_EMAIL=manish@omnibioai.org
read -rsp 'Admin password: ' ADMIN_PASSWORD; printf '\n'
LOGIN_JSON="$(mktemp /tmp/obai-auth-login.XXXXXX.json)"
TOKEN_FILE="$(mktemp /tmp/obai-auth-token.XXXXXX)"
chmod 600 "$LOGIN_JSON" "$TOKEN_FILE"
trap 'rm -f "$LOGIN_JSON" "$TOKEN_FILE"; unset ADMIN_PASSWORD' EXIT

jq -n --arg email "$ADMIN_EMAIL" --arg password "$ADMIN_PASSWORD" \
  '{email:$email,password:$password}' |
  curl --fail-with-body -sS -H 'Content-Type: application/json' \
    --data-binary @- "$AUTH_BASE/auth/login" > "$LOGIN_JSON"

# If mfa_required=true, complete /mfa/challenge with the enrolled factor and
# write its access_token instead. Never log the challenge, code, or token.
jq -er '.access_token' "$LOGIN_JSON" > "$TOKEN_FILE"
unset ADMIN_PASSWORD

curl --fail-with-body -sS -H "Authorization: Bearer $(<"$TOKEN_FILE")" \
  "$AUTH_BASE/platform/licenses/policy" | jq -e '.issuance_enabled == true'
curl --fail-with-body -sS -H "Authorization: Bearer $(<"$TOKEN_FILE")" \
  "$AUTH_BASE/platform/licenses" | jq -e '.items | type == "array"'

# Issue one controlled smoke license. Choose an existing active identity and
# organization membership; reuse this idempotency key on retry.
SMOKE_IDEMPOTENCY="auth-deploy-20261027-$(openssl rand -hex 12)"
jq -n --arg name 'Auth deploy smoke' --arg email "$ADMIN_EMAIL" \
  --argjson organization_id "$SMOKE_ORG_ID" \
  '{full_name:$name,email:$email,persona:"developer",validity_days:30,
    organization_id:$organization_id,confirm_role_change:true,
    confirm_replace_existing:true}' |
  curl --fail-with-body -sS -H "Authorization: Bearer $(<"$TOKEN_FILE")" \
    -H 'Content-Type: application/json' \
    -H "Idempotency-Key: $SMOKE_IDEMPOTENCY" --data-binary @- \
    "$AUTH_BASE/platform/licenses" > /tmp/obai-auth-issued-license.json
chmod 600 /tmp/obai-auth-issued-license.json
SMOKE_LICENSE_ID="$(jq -er '.license.id' /tmp/obai-auth-issued-license.json)"
curl --fail-with-body -sS -H "Authorization: Bearer $(<"$TOKEN_FILE")" \
  "$AUTH_BASE/platform/licenses/$SMOKE_LICENSE_ID" | jq -e '.id == '"$SMOKE_LICENSE_ID"

# Gateway service token -> TES. Supply the approved client credentials through
# protected files/environment; do not put the secret in argv or logs.
curl --fail-with-body -sS -u "$TES_SMOKE_CLIENT_ID:$TES_SMOKE_CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode scope=tes.submit \
  "$AUTH_BASE/oauth/token" > /tmp/obai-tes-service-token.json
chmod 600 /tmp/obai-tes-service-token.json
curl --fail-with-body -sS \
  -H "Authorization: Bearer $(jq -er .access_token /tmp/obai-tes-service-token.json)" \
  https://webstudio.omnibioai.org/_svc/tes/health

# LIMS SSO: in a private browser session, start at the LIMS login page, choose
# OmniBioAI SSO, authenticate as manish@omnibioai.org, confirm the callback
# returns to https://lims.omnibioai.org/sso/callback and the LIMS session loads.

rm -f "$LOGIN_JSON" "$TOKEN_FILE" /tmp/obai-auth-issued-license.json \
  /tmp/obai-tes-service-token.json
trap - EXIT
```

Also load Control Center License Management and confirm policy, registry list,
issue, detail/history, revoke, and refresh behavior. A protected 401/403 proves
only route existence; the authenticated checks above must return 200.

## Rollback

Application rollback (schema remains at head):

```bash
cd "$STUDIO_DIR"
obai-deploy rollback auth-service
obai-deploy status
```

The old `b3cc6d97a15d` image has not been re-qualified against the current
upgraded schema in this audit because the mandatory verifier failed first.
Treat application rollback compatibility as unproven until that rehearsal
passes.

If a migration itself fails, stop. Do not hand-edit or fix forward. Because
`omnibioai` is shared, keep every dependent service in maintenance, preserve
the failed database for diagnosis if capacity allows, and restore the exact
pre-migration dump:

```bash
test -f "$BACKUP_PATH"
test "$(stat -c %a "$BACKUP_PATH")" = 600
read -rp "Type RESTORE-omnibioai to replace the shared DB: " CONFIRM
test "$CONFIRM" = RESTORE-omnibioai

docker exec "$MYSQL_CONTAINER" sh -lc \
  'MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysql -uroot -e \
  "DROP DATABASE omnibioai; CREATE DATABASE omnibioai CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci"'
docker exec -i "$MYSQL_CONTAINER" sh -lc \
  'MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysql -uroot omnibioai' \
  < "$BACKUP_PATH"
```

Re-run revision/schema verification against the restored DB before reopening
traffic. Do not delete the backup until post-deploy retention requirements are
met.

## Cleanup

After evidence has been retained and no investigation needs the scratch DBs:

```bash
docker exec "$MYSQL_CONTAINER" sh -lc \
  'MYSQL_PWD="$(cat /run/secrets/mysql-root-password)" exec mysql -uroot -e "
    DROP DATABASE IF EXISTS omnibioai_auth_rehearsal_live;
    DROP DATABASE IF EXISTS omnibioai_auth_rehearsal_empty;
    DROP USER IF EXISTS '\''obai_auth_migr_rehearsal'\''@'\''%'\'';
    DROP USER IF EXISTS '\''obai_auth_runtime_rehearsal'\''@'\''%'\'';
    FLUSH PRIVILEGES;"'

# This leftover lives on the Compose mysql container, not the active Auth DB.
docker exec omnibioai-studio-mysql-1 sh -lc \
  'exec mysql -uroot -p"$MYSQL_ROOT_PASSWORD" -e \
  "DROP DATABASE IF EXISTS omnibioai_auth_migration_test_bf3be845;
   DROP DATABASE IF EXISTS omnibioai_auth_rehearsal_live;
   DROP DATABASE IF EXISTS omnibioai_auth_rehearsal_empty;
   DROP USER IF EXISTS '\''obai_auth_migr_live'\''@'\''%'\'';
   DROP USER IF EXISTS '\''obai_auth_migr_empty'\''@'\''%'\'';
   DROP USER IF EXISTS '\''obai_auth_runtime_reh'\''@'\''%'\'';
   FLUSH PRIVILEGES;"'

find /tmp -maxdepth 1 -type f \
  \( -name 'obai-auth-*.env' -o -name 'obai-auth-*-env-path*' \) -delete
```

## License issuance configuration details

`LICENSE_ALLOWED_VALIDITY_DAYS` accepts a comma-separated list of positive
base-10 whole day counts, for example `30,90,365`. Whitespace around entries
is ignored; duplicates are removed and values are sorted. Empty or unset means
manual license issuance is disabled. Empty entries, signs, zero, non-decimal
values, and semicolon-separated values fail startup configuration parsing.
The current parser is `app/core/config.py::parse_license_allowed_validity_days`.

`LICENSE_KEY_PEPPER` and `LICENSE_KEY_PEPPER_FILE` are mutually exclusive.
The file setting names a UTF-8 text file; surrounding whitespace/newlines are
stripped. A configured value must contain at least 32 UTF-8 bytes. The loader
permits both sources to be empty, but new license issuance then fails closed
when it needs to compute a key digest. Supply a high-entropy secret of at least
32 bytes through a protected file. Keep it stable across restarts and backups:
new keys are stored as a digest derived with this pepper, so changing the
pepper makes existing digest-only keys unusable.

Add this diff to the Studio Compose deployment only after review; it is not
applied by this handoff. Create the secret file on the host with mode `0600`,
owned by the deployment operator, and configure its absolute path in the
protected Compose environment file. The container mount is read-only.

```diff
 services:
   auth-service:
     environment:
       APP_ENV: production
       AUTH_STARTUP_SCHEMA_MODE: validate
+      LICENSE_KEY_PEPPER_FILE: /run/secrets/license_key_pepper
+      ADMIN_BOOTSTRAP_EMAIL: ${AUTH_ADMIN_BOOTSTRAP_EMAIL:?set to the verified email for users.id=1}
+      LICENSE_ALLOWED_VALIDITY_DAYS: ${LICENSE_ALLOWED_VALIDITY_DAYS:?set approved positive day counts: 30,90,365}
+    volumes:
+      - ${AUTH_LICENSE_KEY_PEPPER_FILE:?set path to a mode-0600 secret file}:/run/secrets/license_key_pepper:ro
```

Before enabling manual issuance, verify that the host secret exists, is a
regular file with permissions exactly `0600`, and is readable by the container
user. Do not put the pepper inline in Compose or print it in deployment logs.
