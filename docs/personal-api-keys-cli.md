# Personal API Keys for the CLI (design note)

Status: proposal, 2026-11-11. No code yet. Context: omnibioai-cli #3.

The CLI stores the 15-minute IAM access token (`ACCESS_TOKEN_EXPIRE_MINUTES`),
so it goes stale almost at once. The agreed direction is long-lived personal
`omni_sk_` API keys:

- any member can create one for themselves;
- a key is limited to the member's own permissions;
- keys expire after 90 days by default;
- members list and revoke their keys on the Studio Developer page.

Most of this already exists. This note lists what is there, verified on
`origin/main` 75d3c83, and the gaps that stop the CLI from using it.

## What already exists

| Requirement | Current behaviour | Where |
|---|---|---|
| Members create their own key | `/me/api-keys` (list, create, rename, revoke): any active member of the session's organisation; at most 10 active keys; blocked when the organisation has no active plan; an API key's own token cannot manage keys | `app/api/routes_apikeys.py` (self-service section) |
| Limited to own permissions | At creation, scopes must be a subset of the caller's membership permissions. At **every** exchange, the token gets `key scopes ∩ current membership permissions`, and the creator must still be an active user and member. A key loses whatever its owner loses. | `apikey_service.create_api_key`, `exchange_api_key` |
| Listed and revocable | The Developer page lists keys (created, last used, expires) and revokes with a confirmation step | Studio `src/ui/pages/Developer.jsx`, `src/ui/lib/apiKeysApi.js` |
| Revocation takes effect at once | `DELETE` publishes the key hash on `policy:invalidate`; the Gateway drops its cached exchange | `_publish_key_revoked` |
| Key never leaves the Gateway | The Gateway exchanges `omni_sk_…` for a 5-minute JWT (`auth_method=api_key`, `api_key_id`, no global roles) and forwards only that JWT downstream | Gateway `app/middleware/auth.py` |
| Storage and audit | Only the sha256 hash is stored, and the plaintext is shown once. Create, rename and revoke are audited without key material. `last_used_at` is written at most once a minute. | `apikey_service` |

## Gaps

### G1. No scope covers what the CLI calls (blocking)

Self-service keys can only carry `literature:read` (`dataset.read`) and
`usage:read` (`usage.read`). The Gateway, however, gates the CLI's
paths as follows (`SERVICE_PERMISSION_MAP`, `V1_SERVICE_MAP`):

| CLI call | Gateway service | Required permission |
|---|---|---|
| `/v1/storage/*` (usage, artifacts, upload, download) | workbench | `workflow.execute` (temporary coarse gate; Gateway README follow-up: `storage.read`/`storage.write`) |
| `/tes/api/runs/{id}`, `/results` | tes | `workflow.execute` |
| `/auth/verify` | (identity only) | none |

A personal key cannot use any CLI command today except `auth status`.

**Proposal.** Add two public scopes to `PUBLIC_SCOPE_TO_PERMISSION`:

| Public scope | Internal permission | Who holds it today |
|---|---|---|
| `workflows:execute` | `workflow.execute` | scientist, org admin |
| `runs:read` | `runs.read` | scientist, org admin |

- The existing subset check still applies, so a viewer cannot create a
  `workflows:execute` key. They get a 400, `Cannot grant scopes you don't hold`.
- The default for a create with no scopes stays `["literature:read"]`, so
  today's Developer page flow does not change.
- **Trade-off (owner decision):** until `storage.read`/`storage.write`
  exist, a key that can upload also can submit TES runs, because both ride
  on `workflow.execute`. That is no more than the member can already do,
  but a leaked key is worth more. The 90-day expiry (G2) bounds that.
  - Follow-up: register `storage.read`/`storage.write` in the Permission
    Registry, grant them to scientist, map them in the Policy Engine and
    per Gateway storage route, then add public `storage:read`/`storage:write`
    scopes. The CLI can then request storage-only keys.
- **Test keys** (`omni_sk_test_`): the Gateway serves canned responses only
  for literature. A test key with `workflows:execute` would make real
  uploads and runs, so self-service creation should reject `test: true`
  together with `workflows:execute` or `runs:read`.

### G2. Keys never expire by default

`ApiKeyCreate.expires_at` is optional and `None` means never. The Developer
page creates keys with a name only, so every self-service key made there
never expires.

**Proposal, for `/me/api-keys` only.** The org-admin
`/orgs/{id}/api-keys` routes are unchanged.

- Omitted `expires_at` becomes `now + SELF_SERVICE_API_KEY_DEFAULT_DAYS`
  (default **90**).
- Reject `expires_at` beyond `SELF_SERVICE_API_KEY_MAX_DAYS` (proposed
  365), with a 400. There is no "never" option for self-service keys.
- Both settings live in `app/core/config.py` and are read from the
  environment, like the other TTLs there.
- Record `expires_at` in the `API_KEY_CREATED` audit `after_state`.
- **Existing keys with no expiry** are left alone, and the page shows them
  as "Never" with a warning. Back-filling an expiry is an owner decision
  (see the open questions).
- No migration is needed, because `expires_at` already exists and
  `verify_api_key` already enforces it.

### G3. Developer page

The page can already list, copy once and revoke keys. It needs:

- **Create form:** a name; scope checkboxes (Literature, Usage, and
  "Workflows and storage (CLI)" = `workflows:execute` + `runs:read`); and
  expiry choices 30 / **90 (default)** / 180 / 365 days. Only scopes the
  member holds are enabled, from a new `GET /me/api-keys/scopes` that
  returns the scopes this member may grant.
- **List:** a scopes column (the API already returns public scopes) and an
  "expires in N days" / "Expired" state, highlighted within 14 days.
  Revocation is unchanged.
- **Snippet:** `omnibioai auth login --api-key` next to the existing curl
  example. A placeholder only; the key is never pre-filled.

### G4. Downstream acceptance (to verify before the CLI change)

Key-minted tokens differ from session tokens: `auth_method=api_key`,
`roles=[]`, `mfa_verified=false`, an `org_id` fixed to the key's
organisation, and a 5-minute lifetime. Each item below needs a test or a
live check with a test key:

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

### G5. CLI (follow-up PR in omnibioai-cli, after G1–G4)

- `omnibioai auth login --api-key`: hidden prompt, or `OMNIBIOAI_API_KEY`.
  The value must start with `omni_sk_`. It is stored like today's token:
  keyring, else the mode-600 file. It is never echoed or logged.
- The CLI sends the key itself as the bearer. Nothing to refresh: the
  Gateway exchanges and caches.
- `auth status` shows the key prefix, scopes and expiry.
  - Needs either `/auth/verify` to return `api_key_id`/`expires_at`, or a
    `GET /me/api-keys/current`.
  - Warns within 14 days of expiry.
- When the server says a key is revoked or expired, print one line:
  "This API key is no longer valid; create a new one on the Developer page."

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
    default 90-day and maximum 365-day expiry; at most 10 active keys.
  - The CLI keeps the key in the keyring or a mode-600 file, and its tests
    can never write the real `~/.config/omnibioai` (CLI #3).
- Removing a member or downgrading their role takes effect on the next
  exchange. That is at most one Gateway exchange-cache window, and is
  immediate after revocation.
- Keys stay bound to one organisation (the session's), matching how
  usage is billed.

## Rollout order

1. **Auth:**
   - G1 scopes, the test-key rule and `GET /me/api-keys/scopes`.
   - G2 default and maximum expiry, and `expires_at` in the audit record.
   - Unit tests: the subset check per role, defaults, the maximum, test
     plus workflow rejected, admin routes unchanged.
2. **G4 checks** with a test-tenant key against Workbench storage, TES run
   reads and Policy. Fix any service that rejects key tokens.
3. **Studio** Developer page (G3).
4. **CLI** `--api-key` (G5).

Each step is its own PR. Deploys go through the deploy owner.

## Open questions for the owner

1. Is `workflows:execute` acceptable as the CLI scope before
   `storage.read`/`storage.write` exist, or should storage scopes come
   first?
2. Maximum lifetime: 365 days?
3. Existing self-service keys with no expiry: leave them, warn on the
   page, or back-fill `created_at + 90 days`, with notice?
4. Should keys warn by email before expiry, or only on the page and in
   the CLI?

## Effort (rough)

| Step | Estimate |
|---|---|
| Auth G1 + G2 + tests | 0.5–1 day |
| G4 verification and small fixes | 0.5–1 day (depends on what fails) |
| Studio G3 | 1 day |
| CLI G5 | 0.5 day |
