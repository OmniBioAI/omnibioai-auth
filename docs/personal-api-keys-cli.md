# Personal API Keys for the CLI (design note)

Status: proposal, 2026-11-11, owner decisions recorded (see
[Decisions](#decisions)). No code yet. Context: omnibioai-cli #3.

The CLI stores the 15-minute IAM access token (`ACCESS_TOKEN_EXPIRE_MINUTES`),
so it goes stale almost at once. The agreed direction is long-lived personal
`omni_sk_` API keys:

- any member can create one for themselves;
- a key is limited to the member's own permissions;
- keys expire after 90 days by default, and 365 days at most;
- members list and revoke their keys on the Studio Developer page;
- members are warned before a key expires.

Most of this already exists. This note lists what is there, verified on
`origin/main` 75d3c83, and the gaps.

## Decisions

Owner, 2026-11-11:

1. **Scopes:** one key for both upload and run is acceptable for now.
   Separate storage scopes (`storage.read` / `storage.write`) are on the
   [1.0 list](#10-list).
2. **Expiry:** default 90 days, maximum 365 days for personal keys.
3. **Existing keys with no expiry:** each gets an expiry 90 days after
   rollout. The Developer page shows a warning banner from rollout day.
4. **Expiry warnings:** on the Developer page, in `omnibioai auth status`,
   and by email 14 and 3 days before expiry, through the existing
   transactional email service (Resend).

## What already exists

| Requirement | Current behaviour | Where |
|---|---|---|
| Members create their own key | `/me/api-keys` (list, create, rename, revoke): any active member of the session's organisation; at most 10 active keys; blocked when the organisation has no active plan; an API key's own token cannot manage keys | `app/api/routes_apikeys.py` (self-service section) |
| Limited to own permissions | At creation, scopes must be a subset of the caller's membership permissions. At **every** exchange, the token gets `key scopes ∩ current membership permissions`, and the creator must still be an active user and member. A key loses whatever its owner loses. | `apikey_service.create_api_key`, `exchange_api_key` |
| Listed and revocable | The Developer page lists keys (created, last used, expires) and revokes with a confirmation step | Studio `src/ui/pages/Developer.jsx`, `src/ui/lib/apiKeysApi.js` |
| Revocation takes effect at once | `DELETE` publishes the key hash on `policy:invalidate`; the Gateway drops its cached exchange | `_publish_key_revoked` |
| Key never leaves the Gateway | The Gateway exchanges `omni_sk_…` for a 5-minute JWT (`auth_method=api_key`, `api_key_id`, no global roles) and forwards only that JWT downstream | Gateway `app/middleware/auth.py` |
| Storage and audit | Only the sha256 hash is stored, and the plaintext is shown once. Create, rename and revoke are audited without key material. `last_used_at` is written at most once a minute. | `apikey_service` |
| Expiry enforced | `verify_api_key` rejects a key whose `expires_at` has passed | `apikey_service.verify_api_key` |
| Transactional email | `email_delivery_service` posts Resend-format messages (`from`, `to`, `subject`, `text`, `tags`) to `EMAIL_SERVICE_SEND_URL` with `EMAIL_SERVICE_TOKEN`. Failures raise `EmailDeliveryError` without provider details. | `app/services/email_delivery_service.py`, `app/core/config.py` |

## Gaps and design

### G1. Scopes for the CLI (blocking)

Self-service keys can only carry `literature:read` (`dataset.read`) and
`usage:read` (`usage.read`). The Gateway gates the CLI's paths as follows
(`SERVICE_PERMISSION_MAP`, `V1_SERVICE_MAP`):

| CLI call | Gateway service | Required permission |
|---|---|---|
| `/v1/storage/*` (usage, artifacts, upload, download) | workbench | `workflow.execute` (temporary coarse gate) |
| `/tes/api/runs/{id}`, `/results` | tes | `workflow.execute` |
| `/auth/verify` | (identity only) | none |

A personal key cannot use any CLI command today except `auth status`.

**Design.** Add two public scopes to `PUBLIC_SCOPE_TO_PERMISSION`:

| Public scope | Internal permission | Who holds it today |
|---|---|---|
| `workflows:execute` | `workflow.execute` | scientist, org admin |
| `runs:read` | `runs.read` | scientist, org admin |

- The existing subset check still applies, so a viewer cannot create a
  `workflows:execute` key. They get a 400, `Cannot grant scopes you don't hold`.
- The default for a create with no scopes stays `["literature:read"]`.
- **Accepted for now (decision 1):** a key that can upload can also
  submit TES runs, because both ride on `workflow.execute`. That is no more
  than the member can already do, and the 90-day default expiry bounds a
  leak. Storage-only scopes are on the [1.0 list](#10-list).
- **Test keys** (`omni_sk_test_`): the Gateway serves canned responses only
  for literature. A test key with `workflows:execute` would make real
  uploads and runs. Self-service creation therefore rejects `test: true`
  together with `workflows:execute` or `runs:read`.

### G2. Default and maximum expiry

Today `ApiKeyCreate.expires_at` is optional and `None` means never. The
Developer page sends a name only, so every self-service key made there
never expires.

**Design, for `/me/api-keys` only.** The org-admin `/orgs/{id}/api-keys`
routes are unchanged.

- Omitted `expires_at` becomes `now + SELF_SERVICE_API_KEY_DEFAULT_DAYS` (90).
- `expires_at` later than `now + SELF_SERVICE_API_KEY_MAX_DAYS` (365) is
  rejected with a 400. There is no "never" option.
- Both settings live in `app/core/config.py` and are read from the
  environment, like the other TTLs there.
- **New column** `api_keys.expiry_source`, `String(16)`, nullable:
  - `"creator"`: the caller chose the date;
  - `"default"`: the 90-day default applied;
  - `"backfill"`: set by G3;
  - `NULL`: key created before this change through the admin route.

  It drives the banner (G4) and email wording (G6), and is never shown as
  a secret.
- `expires_at` and `expiry_source` go into the `API_KEY_CREATED` audit
  `after_state`.

### G2a. Key kind: personal or integration

There is no column today that says what a key is for, so a backfill rule
can't tell a member's personal key from one an unattended integration
depends on. Every new key will say which it is.

**New columns on `api_keys`:**

| Column | Type | Rule |
|---|---|---|
| `key_kind` | `String(16)`, NOT NULL, `'personal'` or `'integration'` | `/me/api-keys` always writes `personal`, and the client cannot choose. Only the org-admin `/orgs/{id}/api-keys` route can create `integration`, and it must say so explicitly (`key_kind` in the body, no default). |
| `integration_owner_user_id` | FK `users.id`, nullable | Required for `integration`, NULL for `personal`. Names the accountable person. Must be an active member of the key's organisation with `manage_api_keys`. |
| `integration_note` | `String(500)`, nullable | Required for `integration`, NULL for `personal`. Says what uses the key, for example "nightly LIMS sync on dgx cron". Shown to org admins, never put in tokens. |

**Rules by kind:**

| | `personal` | `integration` |
|---|---|---|
| Created by | the member, on `/me/api-keys` | an org admin, on `/orgs/{id}/api-keys` |
| Expiry | default 90 days, maximum 365, never "no expiry" (G2) | optional; may have no expiry |
| Scopes | capped by the creator's permissions (unchanged) | same cap |
| Stops working when | the creator leaves or is downgraded (unchanged) | same. Reassigning the owner does not change this; a departing creator's integration keys must be re-issued. |
| Expiry emails (G6) | to the creator | to the `integration_owner_user_id`, only if the key has an expiry |
| Listed on | the member's Developer page | the org-admin key list, with kind, owner and note |

- `key_kind`, owner and note are written in the `API_KEY_CREATED` audit
  `after_state`.
- Changing the owner or note is an audited `API_KEY_OWNER_CHANGED` event.
  Changing the kind is not allowed; re-issue the key instead.
- The org-admin route keeps creating keys exactly as today, except that it
  now requires `key_kind`, plus the owner and note for `integration`.
  Callers that omit `key_kind` get a 400 naming the field, not a silent
  default.
- **Integrations should prefer OAuth clients** (client credentials; 13
  rows in `oauth_clients` on live). An `integration` API key is for tools
  that can only send a static bearer. The note field should say why.

### G3. Backfill existing keys (decision 3)

**Migration, run as part of the rollout deploy:**
- For every key with `status = 'active'` and `expires_at IS NULL`, set
  `expires_at = <rollout time> + 90 days` and `expiry_source = 'backfill'`.
- Write one `API_KEY_EXPIRY_SET` audit event per key: before `null`, after
  the new date, `reason = "rollout_backfill"`. No key material.
- Reversible by its downgrade, which clears exactly the rows with
  `expiry_source = 'backfill'`.
- The rollout time is recorded as the migration's run time. The
  `<rollout time>` used is written to the deploy record.

**Which keys.** The migration adds `key_kind` (G2a) and classifies every
existing row from an explicit, reviewed list, never by guessing:

- A key on the list as `integration` gets its owner and note and keeps no
  expiry. It is not backfilled.
- **Every other key becomes `personal`** and gets the 90-day backfill.
- The list ships with the migration as data (key ids only, no key
  material). The migration refuses to run if the list names a key id that
  doesn't exist or isn't active.

#### Inventory of keys with no expiry (live, 2026-11-11)

- **Query:** read-only, run against the live auth database (`omnibioai` on
  `omnibioai-studio-mysql-1`) from the auth container's own connection, in
  a `READ ONLY` transaction that was rolled back. No hashes or key
  material were selected.
- **Result:** the `api_keys` table has **0 rows** in any state. The audit
  log has no `api_key_*` events, so no key has ever been created on live.
  For scale: 8 users, 2 organisations, 13 OAuth clients.

| id | name | prefix | creator user | org | created | last used | scopes | proposal |
|---|---|---|---|---|---|---|---|---|
| — | *(no keys)* | | | | | | | |

**Proposal:** nothing needs an integration exception today, so the
reviewed list starts empty. Because keys can be created on live at any
time before rollout, the inventory is re-run as the first rollout step
(below). For each key it finds, the proposal is:

- **`personal`, 90-day backfill** if it was created by a member for their
  own use. This is the default.
- **`integration`, no expiry** only if the owner names an accountable
  person and what uses the key. The org admin confirms it, and the key id
  is added to the list before the migration runs.
- **Revoke instead** if no one claims it and `last_used_at` is NULL or
  more than 90 days old. That needs the owner's approval; the migration
  never revokes.

Re-check query (read-only, run through the auth container's own
connection, prints no secrets):

```sql
SET SESSION TRANSACTION READ ONLY;
SELECT k.id, k.name, k.key_prefix, k.created_by_user_id, k.organization_id,
       o.name AS org, k.created_at, k.last_used_at, k.scopes, k.status
FROM api_keys k LEFT JOIN organizations o ON o.id = k.organization_id
WHERE k.expires_at IS NULL AND k.status = 'active'
ORDER BY k.id;
```

`key_prefix` holds only the type prefix plus the first 4 random
characters, which the Developer page already shows. `key_hash` is never
selected.

### G4. Developer page (Studio)

The page can already list, copy once and revoke keys. It needs:

- **Create form:**
  - a name;
  - scope checkboxes: Literature, Usage, and "Workflows and storage (CLI)"
    (`workflows:execute` + `runs:read`);
  - an expiry choice of 30 / **90 (default)** / 180 / 365 days.

  Only scopes the member holds are enabled, from a new
  `GET /me/api-keys/scopes` that returns the scopes this member may grant.
- **List:** a scopes column (the API already returns public scopes) and an
  expiry cell showing "expires in N days" or "Expired". The cell is
  highlighted when 14 days or fewer remain.
- **Backfill banner (decision 3):**
  - Shown from rollout day while the member has any active key with
    `expiry_source = 'backfill'`.
  - Text: "Keys created before <date> now expire on <date>. Create a
    replacement before then; expired keys stop working."
  - The member can dismiss it for the session. It comes back on the next
    visit until those keys are revoked or replaced.
- **Expiry banner (decision 4):** shown while any active key expires
  within 14 days. It names the keys and links to create a replacement.
- **Snippet:** `omnibioai auth login --api-key` next to the existing curl
  example. A placeholder only; the key is never pre-filled.

### G5. Downstream acceptance (to verify before the CLI change)

Key-minted tokens differ from session tokens: `auth_method=api_key`,
`roles=[]`, `mfa_verified=false`, an `org_id` fixed to the key's
organisation, and a 5-minute lifetime. Each item below needs a test or a
live check with a test-tenant key:

1. Workbench `jwt_auth.validated_claims` requires
   `iss/sub/aud/exp/type`. Confirm the minted token's `iss`/`aud` match
   Workbench's `JWT_ISSUER`/`JWT_AUDIENCE` (`type=access` is set).
2. Personal storage (`UserStorageAccount`, quota, ownership) resolves from
   `sub`, not from session-only claims. No storage route may require
   `mfa_verified` or a role.
3. TES run reads authorise on `sub`/org and accept `auth_method=api_key`.
4. The Policy Engine allows `workflow.execute` for an `api_key` identity
   (`token_type` is `api_key` in the Gateway identity).
5. Billing and metering attribute storage and run usage to the key's
   organisation, as for literature calls today.

### G6. Expiry emails (decision 4)

**What is sent:** one email to the key creator's address, 14 days and
again 3 days before `expires_at`.
- Revoked keys, already-expired keys and inactive users get nothing.
- Content: the key name, its prefix (`omni_sk_live_ab12…`, never more),
  the organisation, the expiry date and a link to the Developer page. It
  contains no key material and no scopes.
- A backfilled key says its expiry was set at rollout.

**How it is sent:**
- **Transport:** add `send_api_key_expiry_notice(...)` to
  `email_delivery_service`. It uses the same `EMAIL_SERVICE_SEND_URL` /
  `EMAIL_SERVICE_TOKEN` / `EMAIL_FROM_ADDRESS` and the same
  `EmailDeliveryError` handling as the existing senders, with tag
  `message_type=api_key_expiry`.
- **Once only:**
  - New nullable columns `api_keys.expiry_notice_14d_sent_at` and
    `api_keys.expiry_notice_3d_sent_at`.
  - The job selects keys where `expires_at - now <= N days`, the matching
    column is `NULL`, and `status = 'active'`.
  - It sends, then sets the column in the same transaction as an
    `API_KEY_EXPIRY_NOTICE_SENT` audit event.
  - A send that fails leaves the column `NULL`, so the next run retries.
  - A key created with less than 14 (or 3) days left gets only the
    notices still ahead of it.
- **Schedule:** Auth has no scheduler.
  - Add an idempotent command, `python -m app.jobs.api_key_expiry_notices`.
    It exits 0 when there is nothing to send and prints counts only, no
    addresses.
  - Run it daily from the ecosystem `ops/crontab` with `docker exec` into
    the auth container, logged like the other ops jobs.
  - Because the job is idempotent, a missed or repeated run is harmless.
- **Off switch:** `API_KEY_EXPIRY_EMAILS_ENABLED` (default `false` until
  the rollout step turns it on). With email unconfigured, the job logs one
  line and exits 0, and the page and CLI warnings still work.
- **Backfill timing:** backfilled keys all expire on the same day, so
  their 14-day notices all go on one day. The job sends at most
  `API_KEY_EXPIRY_EMAIL_BATCH` (default 200) per run; the rest go on the
  next run, still before the 3-day window.

### G7. CLI (follow-up PR in omnibioai-cli, after G1–G5)

- `omnibioai auth login --api-key`: hidden prompt, or `OMNIBIOAI_API_KEY`.
  The value must start with `omni_sk_`. It is stored like today's token:
  keyring, else the mode-600 file. It is never echoed or logged.
- The CLI sends the key itself as the bearer. Nothing to refresh: the
  Gateway exchanges and caches.
- **`auth status` (decision 4):**
  - Shows the key prefix, scopes and expiry.
  - Prints a one-line warning when 14 days or fewer remain:
    `Warning: this API key expires in N days (<date>). Create a new one on the Developer page.`
  - Needs either `/auth/verify` to return `api_key_id`, `expires_at` and
    `expiry_source`, or a `GET /me/api-keys/current` that reads the key
    from the exchanged token's `api_key_id`.
- When the server says a key is revoked or expired, print one line:
  "This API key is no longer valid; create a new one on the Developer page."

## 1.0 list

These are not part of this rollout. They are required for 1.0:

- **Storage scopes `storage.read` / `storage.write`** (decision 1):
  - register them in the Permission Registry (`app/core/permission_names.py`)
    and grant both to scientist;
  - add exact Policy Engine mappings;
  - in the Gateway, select them per storage route and method instead of
    the `workflow.execute` coarse gate (Gateway README follow-up);
  - add public scopes `storage:read` / `storage:write` to self-service keys,
    so the CLI can request storage-only keys.

  After that, `workflows:execute` is needed only for run submission.

## Why not refresh tokens or device code

- **Refresh tokens** rotate once per use, and reuse revokes the whole
  family. Concurrent CLI processes (parallel uploads, two shells, cron)
  would race and sign the user out. Obtaining the first refresh token also
  needs a password login in the CLI, which SSO and MFA users cannot do.
- **Device code** is the right long-term flow for SSO/MFA, but Auth has
  none of it (endpoints, approval page, polling, throttling). It is the
  most work and still ends in a rotating refresh token.

## Security considerations

- A key is a long-lived bearer credential.
  - Mitigations: hash-only storage; scopes capped by the holder's
    permissions and re-checked on every exchange; immediate revocation;
    90-day default and 365-day maximum; at most 10 active keys.
  - After rollout, the only active keys without an expiry are
    `integration` keys. Each has an accountable owner and a note, and is
    visible to org admins.
- Expiry emails carry only the key name and prefix, and are sent only to
  the creator's own address. The job logs counts, not addresses.
- Removing a member or downgrading their role takes effect on the next
  exchange. That is at most one Gateway exchange-cache window, and is
  immediate after revocation.
- The CLI keeps the key in the keyring or a mode-600 file, and its tests
  can never write the real `~/.config/omnibioai` (CLI #3).

## Rollout order

Each step is its own PR. Deploys go through the deploy owner.

1. **Auth:**
   - G1 scopes, the test-key rule and `GET /me/api-keys/scopes`.
   - G2 default and maximum expiry, and the `expiry_source` column.
   - G2a `key_kind`, integration owner and note, and the admin-route
     validation.
   - G6 notice columns, sender and job, with emails disabled.
   - The G3 backfill migration.
   - Unit tests:
     - the subset check per role;
     - the default, the maximum, and test plus workflow rejected;
     - admin routes unchanged;
     - backfill and downgrade, including that keys on the integration list
       keep no expiry;
     - the migration refuses an unknown or inactive id on the list;
     - `key_kind` is forced on `/me`, required on the admin route, and
       owner and note are required for `integration`;
     - the email job's windows, once-only behaviour, failed-send retry,
       batch limit and no-op when unconfigured.
2. **G5 checks** with a test-tenant key against Workbench storage, TES run
   reads and Policy. Fix any service that rejects key tokens.
3. **Studio** Developer page (G4), deployed **with or before** step 1's
   deploy, so the backfill banner is visible from rollout day.
4. **Auth deploy:**
   - Re-run the G3 inventory query.
   - The owner classifies any keys it finds, and the reviewed integration
     list is finalised.
   - Run the migration (rollout day = backfill time).
   - Add the cron line.
   - Set `API_KEY_EXPIRY_EMAILS_ENABLED=true` after one dry run of the job
     against live data shows the expected counts.
5. **CLI** `--api-key` and the `auth status` warning (G7).

## Resolved: which keys the backfill covers

The earlier open question was whether org-admin keys would be backfilled.
`key_kind` (G2a) answers it, along with the reviewed integration list
(G3):

- Only keys explicitly listed as `integration`, each with a named owner
  and note, keep no expiry.
- Everything else is `personal` and gets the 90-day date.
- The live inventory on 2026-11-11 found no keys, so the list is currently
  empty. It is re-checked on rollout day.

## Effort (rough)

| Step | Estimate |
|---|---|
| Auth G1 + G2 + G2a + G3 + tests | 1.5–2 days |
| Auth G6 (sender, job, columns, tests) + ops cron line | 1 day |
| G5 verification and small fixes | 0.5–1 day (depends on what fails) |
| Studio G4 (form, list, two banners) | 1–1.5 days |
| CLI G7 | 0.5 day |
