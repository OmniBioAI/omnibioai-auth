# PR11.5.1 — Enterprise MFA Database Foundation: Discovery

Schema/model-only foundation, discovery performed before writing any
migration or model code, per this PR's own instructions. Verified
directly against `omnibioai-auth` source in this session — no field
or convention below is assumed from naming.

This PR builds on, and does not repeat, PR11.5's own broader
discovery (`docs/pr11-security-foundation-discovery.md`, in
`omnibioai-control-center`), which already established that **zero**
MFA-related columns, tables, services, or routes exist anywhere in
this codebase today (confirmed there by an exhaustive
`grep -rniE "mfa|totp|webauthn|fido|2fa|otp_secret|backup_code|
recovery_code"` across all of `app/`, re-confirmed here). That
document's §7 roadmap names this PR "PR11.5.1 — MFA database
foundation" and scopes it to schema only; this discovery expands that
one paragraph into the concrete design below.

---

## 1. Current `User` schema

`app/db/models.py:43-77`, read in full:

```python
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))
    status = Column(String(50), default="active")

    created_at = Column(DateTime, nullable=True, default=datetime.utcnow)
    status_changed_at = Column(DateTime, nullable=True)
    status_changed_reason = Column(String(500), nullable=True)
    status_changed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    last_login_at = Column(DateTime, nullable=True)
    authentication_method = Column(String(20), nullable=True)

    roles = relationship("Role", secondary=user_roles, back_populates="users")
```

Every addition to this table so far (`created_at`/`status_changed_*`
in Phase 3 PR3A, `last_login_at`/`authentication_method` in PR11.1)
has followed the same two conventions, both re-used by this PR:

1. **New columns are always nullable with no backfill** — existing
   rows have no history to invent, and a fabricated non-null default
   for a historical fact would be dishonest. `mfa_enabled` is the one
   deliberate exception (see §2) because it is a live *current-state*
   flag, not a historical fact — the correct value for every existing
   row is unambiguous (`false`, since MFA doesn't exist yet), so it
   gets a real `NOT NULL DEFAULT false` instead.
2. **A short code comment above the new columns names the PR and
   explains why nullable/non-null was chosen for each field** — the
   comments in §2 below follow this exactly.

## 2. Where MFA fields should live

### 2.1 `User` table: MFA *status* metadata only, not secrets

Small, non-secret, frequently-read fields belong directly on `User`
(the row `get_current_user`/permission checks already load) — mirrors
`authentication_method`/`last_login_at`'s own placement, which are the
closest existing precedent (per-login-flow metadata baked onto the
user row rather than into a side table).

| Field | Type | Nullability | Rationale |
|---|---|---|---|
| `mfa_enabled` | `Boolean` | `NOT NULL DEFAULT false` | Live current-state flag, not a historical fact — every pre-existing row is unambiguously `false` today (§1's exception) |
| `mfa_status` | `String(20)` | `NOT NULL DEFAULT "disabled"` | `"disabled" \| "pending" \| "enabled"` — a string, not a DB-level enum, for the same reason `status`/`authentication_method` are plain strings elsewhere in this file: SQLite (used in every test run, per `tests/conftest.py:17`) has no native enum type, and this codebase has never used one (confirmed: zero `sa.Enum` usage anywhere in `alembic/versions/`) |
| `mfa_primary_method` | `String(20)` | `NULL` | `"totp" \| "webauthn"`, historical/pointer field — `NULL` until a device is actually enrolled, matching `authentication_method`'s own nullable pattern |
| `mfa_enabled_at` | `DateTime` | `NULL` | Historical fact, no backfill — same convention as `last_login_at` |
| `mfa_last_verified_at` | `DateTime` | `NULL` | Historical fact, no backfill |

**Not stored on `User`:** any secret material. `mfa_primary_method`
is a plain method-name string (`"totp"`), never a pointer into secret
data — the secret itself lives only in `MFADevice.encrypted_secret`
(§2.2). This mirrors how `OrganizationSSOConfig` keeps `client_id`
(non-secret, inline) separate from `client_secret_encrypted`
(secret, still inline but named/handled distinctly) — except MFA
secrets go a step further into their own table because, unlike a
single per-org SSO client secret, a user may have **multiple** devices
(§2.2, explicitly required by this PR: "support multiple devices in
future").

### 2.2 New table: `mfa_devices`

A separate table, not more columns on `User`, because:
- **Multiplicity**: this PR explicitly requires supporting multiple
  devices per user in the future (a user might enroll both a TOTP app
  and a WebAuthn key) — a 1:N relationship cannot live as columns on
  `User` itself.
- **Precedent**: this codebase already separates "the secret-bearing
  thing" from "the identity it belongs to" whenever there can be more
  than one — `ApiKey`/`OAuthClient` are both separate tables scoped by
  `organization_id`, not columns on `Organization`. `MFADevice` follows
  that exact shape, scoped by `user_id` instead.

```python
class MFADevice(Base):
    """PR11.5.1: a single enrolled MFA factor. Separate from `User`
    (see docs/pr11-mfa-database-foundation-discovery.md §2.2) because a
    user may enroll more than one factor -- mirrors ApiKey/OAuthClient's
    own "secret-bearing row, separate from its owning identity, FK +
    indexed by owner" shape exactly.

    No enrollment/verification logic is added by this PR -- schema
    only. `verified_at` distinguishes a device that has completed its
    enrollment challenge (not yet possible -- no such challenge exists
    yet) from one that was only ever created; every row this PR's own
    code can produce (none) would leave it NULL, same as every other
    field below.
    """
    __tablename__ = "mfa_devices"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    device_type = Column(String(20), nullable=False)  # "totp" | "webauthn"
    label = Column(String(255), nullable=True)  # user-chosen display name, e.g. "iPhone"

    # Fernet, same CONFIG_ENCRYPTION_KEY / app/core/crypto.py as
    # OrganizationSSOConfig.client_secret_encrypted and
    # OrganizationConfig.llm_api_key_encrypted -- see §3.
    encrypted_secret = Column(String(1000), nullable=False)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    disabled_at = Column(DateTime, nullable=True)
```

`user_id` is indexed (`index=True`) per this PR's own requirement —
mirrors `ApiKey.organization_id`'s (implicit FK) and, more directly,
`RefreshToken.user_id`'s pattern of an indexed owner column on a
per-owner-multiplicity table.

**Why `encrypted_secret` is `nullable=False`**: unlike `User`'s new
columns (§2.1, historical/no-backfill), `MFADevice` is a brand-new
table with zero existing rows — there is nothing to migrate, so there
is no reason to allow a null secret on a row whose entire purpose is
to hold one. Not nullable, matching `OrganizationSSOConfig.
client_secret_encrypted`'s own `nullable=False`.

### 2.3 New table: `mfa_recovery_codes`

```python
class MFARecoveryCode(Base):
    """PR11.5.1: one-time-use recovery codes, hashed at rest -- never
    the plaintext code (see §3: same "store a hash, never the
    plaintext" convention as ApiKey.key_hash / OAuthClient.
    client_secret_hash, not the Fernet-reversible pattern MFADevice's
    TOTP/WebAuthn secret uses, because a recovery code only needs to be
    *checked*, never redisplayed or decrypted for reuse). No generation
    logic is added by this PR -- schema only.
    """
    __tablename__ = "mfa_recovery_codes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)  # sha256 hex, same shape as OAuthClient.client_secret_hash
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    used_at = Column(DateTime, nullable=True)  # NULL = unused; one-time-use enforced by future consumption logic, not this PR
```

`code_hash` is **not** declared `unique=True`: unlike `ApiKey.key_hash`
(globally unique because a key must resolve to exactly one owner on
lookup) or `OAuthClient.client_secret_hash`, a recovery code is always
looked up scoped to a known `user_id` (the user is already mid-login,
just missing their second factor) — so a global uniqueness constraint
would only add a (vanishingly unlikely, SHA-256) collision-across-
unrelated-users failure mode with no benefit. Left as a plain indexed
FK column instead, consistent with `MFADevice.user_id`.

---

## 3. Encryption / storage approach

Two distinct patterns already exist in this codebase for two distinct
needs — this PR uses both, matching the right one to each new table
rather than inventing a third:

| Pattern | Existing precedent | Used by this PR for |
|---|---|---|
| **Reversible encryption** (Fernet, `app/core/crypto.py`, `CONFIG_ENCRYPTION_KEY`) — the plaintext must be recoverable to actually *use* it | `OrganizationSSOConfig.client_secret_encrypted`, `OrganizationConfig.llm_api_key_encrypted`, `GlobalConfig.llm_api_key_encrypted`/`cloud_credentials_encrypted` | `MFADevice.encrypted_secret` — a TOTP shared secret must be decrypted to compute the expected code at verification time; a WebAuthn public key similarly needs to be read back intact. There is no way to verify a TOTP code from a one-way hash. |
| **One-way hash** (SHA-256 hex, `hashlib.sha256(...).hexdigest()`) — only ever *compared*, never read back | `ApiKey.key_hash`, `OAuthClient.client_secret_hash` | `MFARecoveryCode.code_hash` — a recovery code is checked by hashing the presented value and comparing, exactly like an API key or OAuth client secret; the plaintext is shown to the user exactly once at generation time and never needs to be recovered afterward |

**`app/core/crypto.py` read in full** — `encrypt()`/`decrypt()` wrap a
single module-level `Fernet` instance keyed by `CONFIG_ENCRYPTION_KEY`
(already required in every environment that uses `OrganizationSSOConfig`
or `OrganizationConfig`, so no new environment variable is needed).
`encrypt()` raises loudly if the key isn't configured rather than
silently storing plaintext — `MFADevice.encrypted_secret` inherits
this guarantee automatically by using the same helper, with zero new
code in this PR (no enrollment logic exists yet to call it — see
scope note below).

**This PR does not call `crypto.encrypt`/`decrypt` or any hashing
function anywhere** — no enrollment, verification, or recovery-code
generation code is being added (explicitly out of scope, per this
PR's own instructions: "No generation logic yet"). §3 documents the
approach the *next* PR (PR11.5.2, TOTP enrollment) will use, so the
column types chosen here (`String(1000)` for the Fernet-encrypted
blob, matching `client_secret_encrypted`'s own width; `String(64)` for
the SHA-256 hex hash, matching `OAuthClient.client_secret_hash`
exactly) are already correctly sized for it without a follow-up
migration.

---

## 4. Migration strategy

Continues the existing single linear Alembic history
(`alembic/versions/0001_baseline.py` through `0012_user_login_metadata.py`)
with one new revision, `0013_mfa_foundation`, `down_revision =
"0012_user_login_metadata"`.

- **`users` table**: `op.batch_alter_table("users")`, adding 5 columns
  — matches `0012`'s own `batch_alter_table` usage exactly (needed
  for SQLite's limited native `ALTER TABLE`, which every test run
  exercises via `tests/conftest.py`'s SQLite `test.db`).
- **`mfa_devices` / `mfa_recovery_codes`**: `op.create_table(...)`,
  matching `0011_audit_events.py`'s shape (a brand-new table needs no
  `batch_alter_table` wrapper — that's only for altering an existing
  table on SQLite).
- **Revision id length**: kept at 20 characters
  (`"0013_mfa_foundation"`), well under this project's established
  32-character ceiling (MySQL's `alembic_version.version_num` column
  is `VARCHAR(32)` — every existing revision id, e.g.
  `"0012_user_login_metadata"` at 24 chars, already respects this).
- **`downgrade()`**: drops the two new tables and the 5 new `users`
  columns, in reverse order — matches every existing migration's own
  reversibility contract (`tests/test_migrations.py`'s
  `test_sqlite_downgrade_base_reverses_cleanly` walks the *entire*
  history down to `base` and asserts no tables survive; this PR's new
  tables/columns must not break that).

## 5. Backward compatibility considerations

- **Zero existing call sites reference any new field** — this PR adds
  no service function, no route, no schema (Pydantic) change. The ORM
  classes and migration are purely additive; nothing in
  `auth_service.py`, `routes_auth.py`, or any other existing file is
  touched.
- **Existing users authenticate exactly as before**: `mfa_enabled`
  defaults to `false` for every row (both pre-existing, via the
  migration's `server_default`, and any newly-registered user, via the
  ORM column's Python-level `default=False`) — with no login-flow code
  reading this column yet (that's PR11.5.3, per the roadmap in
  `docs/pr11-security-foundation-discovery.md` §7), its value cannot
  affect any request today regardless of what it's set to.
- **`test_migrations.py`'s existing assertions need two small,
  additive updates** (not behavioral changes to any existing
  migration): `ALL_TABLES` gains `MFA_TABLES = {"mfa_devices",
  "mfa_recovery_codes"}`, and
  `test_sqlite_stamp_then_upgrade_matches_real_deployment_procedure`'s
  final `recorded == "..."` assertion advances to the new head
  revision id — the same one-line update every prior migration PR in
  this history has made to that test (e.g. PR11.1 advancing it from
  `"0011_audit_events"` to `"0012_user_login_metadata"`).
- **No `alembic_version` branch is created** — this is a strictly
  linear `down_revision` chain continuation, so `alembic upgrade head`
  behaves identically to every prior migration for any environment
  currently at `0012_user_login_metadata`.

---

## 6. Future audit events (documented only, not implemented)

Per this PR's own instructions, no audit call sites are added — the
following event-type names are recorded here so the AuditEventType
class (`app/services/audit_service.py:32-56`) has a settled naming
scheme ready for the PR that actually implements MFA enrollment/
verification/reset, following the exact `SCREAMING_SNAKE_CASE` Python
constant / `snake_case` string-value convention every existing entry
already uses (e.g. `SSO_OVERRIDE_CREATED = "sso_override_created"`):

| Constant | String value | Emitted when (future) |
|---|---|---|
| `MFA_ENABLED` | `"mfa_enabled"` | A user completes MFA setup (first device verified) |
| `MFA_DISABLED` | `"mfa_disabled"` | A user or admin turns MFA off entirely |
| `MFA_DEVICE_ADDED` | `"mfa_device_added"` | A new `MFADevice` row is verified |
| `MFA_DEVICE_REMOVED` | `"mfa_device_removed"` | An `MFADevice` row is disabled/deleted |
| `MFA_RECOVERY_USED` | `"mfa_recovery_used"` | A recovery code is consumed to bypass a lost device |
| `MFA_RESET_BY_ADMIN` | `"mfa_reset_by_admin"` | An admin force-clears a user's MFA (break-glass, mirroring `SSO_OVERRIDE_CREATED`'s own break-glass shape) |

No code in this PR references `AuditEventType` or `log_event` — this
table is documentation for the next PR, not a schema decision (audit
events have no foreign schema dependency on `MFADevice`/
`MFARecoveryCode` beyond the existing generic `resource_type`/
`resource_id` string columns `AuditEvent` already has).

---

## 7. Verification method

- Full read of `app/db/models.py` (all classes, not just `User`) to
  confirm the exact shape/naming conventions this PR must match.
- Full read of `alembic/versions/0012_user_login_metadata.py` (most
  recent migration) and `alembic/versions/0011_audit_events.py`
  (most recent new-table migration) as direct templates.
- Full read of `app/core/crypto.py` (the only encryption helper in
  the codebase) and grep-confirmed it is the sole `Fernet` usage
  (`grep -rn "Fernet" app/` → only `crypto.py` and the two call sites
  already noted in `models.py`'s own comments).
- Full read of `app/services/audit_service.py` (existing
  `AuditEventType`/`log_event`/`list_events` — confirms §6's naming
  scheme fits the existing convention without needing any code
  change here).
- Full read of `tests/test_migrations.py` and `tests/conftest.py` to
  confirm the exact test structure/fixtures this PR's own migration
  tests must follow (§5's two required updates to existing
  assertions, and the new tests added in this PR's own test file).
- Re-confirmed (grep) that this codebase has zero MFA-related code of
  any kind prior to this PR, consistent with
  `docs/pr11-security-foundation-discovery.md`'s own finding in
  `omnibioai-control-center`.
