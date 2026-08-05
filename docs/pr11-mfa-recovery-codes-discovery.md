# PR11.5.4 — Enterprise MFA Recovery Codes + Admin Reset: Discovery

Discovery performed before coding, per this PR's own instructions.
Completes the user/admin recovery path on top of PR11.5.1 (schema),
PR11.5.2 (TOTP enrollment), PR11.5.3 (login challenge) — this PR does
not redesign any of that, only extends it. Verified directly against
current source in this session.

## 1. `MFARecoveryCode` — already exists, unchanged shape (PR11.5.1)

`app/db/models.py:467-488`, read in full:

```python
class MFARecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)  # sha256 hex
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    used_at = Column(DateTime, nullable=True)  # NULL = unused
```

**No migration is needed for this PR** — every requirement below is
satisfiable with these five columns exactly as PR11.5.1 shipped them.
In particular, there is no `disabled_at` column (unlike `MFADevice`) —
only `used_at`. This PR deliberately reuses `used_at` as a general
"no longer redeemable" marker, not only "consumed via a successful
login": both a genuine login-time consumption (§5) and an
administrative invalidation (regenerate, §3; admin reset, §6) set the
same column to the same effect — "this code can never be presented
again." The two situations remain distinguishable after the fact via
`AuditEvent` (a `MFA_RECOVERY_CODE_USED` row for genuine use vs.
`MFA_RECOVERY_CODES_REGENERATED`/`MFA_RESET_BY_ADMIN` for
invalidation), not via the row itself — the row only ever needs to
answer "is this code still valid," which `used_at IS NULL` already
answers correctly regardless of *why* it became non-null. Confirmed
this is sufficient by re-reading every requirement in this PR's own
spec: nothing asks for a per-code invalidation *reason* to be
queryable later, only that invalidated codes stop working and that the
*event* of invalidating them is audited (which `AuditEvent` already
covers independently of this table).

`code_hash` is `String(64)` — sized exactly for a SHA-256 hex digest
(64 hex chars), already correctly sized by PR11.5.1 for this PR's own
"Use: hashlib... Store only: SHA256(code)" requirement, with zero
schema change needed.

## 2. `MFADevice` — reused unchanged (PR11.5.1/11.5.2)

`app/db/models.py:437-465`. This PR's admin reset (§6) disables every
device the same way PR11.5.2's own `remove_device` already does —
`disabled_at = now()`, never a SQL delete, same "soft-remove,
resource_id keeps a resolvable audit history" reasoning that function's
own docstring already gives. No change to this model.

## 3. Existing MFA challenge flow (PR11.5.3)

`app/services/mfa_service.py::verify_mfa_challenge` (read in full)
does, today:

1. Decode + validate `challenge_token` (type/reuse/user-active/
   `mfa_enabled` checks) — raises `MFAChallengeError` (401) on any
   problem with the token itself.
2. Loads every verified, non-disabled `MFADevice` for the user; tries
   `verify_totp_code` against each.
3. No match → `MFA_VERIFICATION_FAILED` audit event, raises
   `ValueError` (400).
4. Match → marks the challenge `jti` used (`RevokedToken` insert),
   updates `device.last_used_at`/`user.mfa_last_verified_at`, emits
   `MFA_VERIFIED`, calls the existing, unchanged `generate_tokens` to
   finish the login.

**This PR's integration point is exactly step 3** — before giving up
and raising `ValueError`, try the same `code` value as a recovery code
(§5). No separate endpoint, no separate request field: the *shape* of
`code` (6 digits vs. `AAAA-BBBB-CCCC`) is what disambiguates, matching
this PR's own architecture diagram ("MFA Challenge → TOTP verification
→ Recovery code verification", both under the same challenge). Steps
1, 2, and 4's TOTP-specific mechanics are **completely untouched** —
every existing PR11.5.3 test still exercises the exact same code path
it always did, TOTP is tried first and unchanged.

**`generate_tokens` and `generate_tokens_or_mfa_challenge` are not
modified at all** by this PR, confirmed by design: a successful
recovery-code match reaches the *same* "mark jti used, call
`generate_tokens`" tail a successful TOTP match already reaches — this
PR factors that shared tail into one small private helper inside
`mfa_service.py` (§5) rather than duplicating it, but touches zero
lines in `auth_service.py`.

## 4. Existing audit event pattern (PR11.5.2/PR11.5.3)

`app/services/audit_service.py::AuditEventType` — confirmed the
existing `SCREAMING_SNAKE_CASE` / `"snake_case"` string convention,
and the existing "audit inside the service layer, at the point of the
actual mutation/decision, never in the route handler" rule (every
PR11.x call site so far). This PR's four new events follow both
exactly:

```python
MFA_RECOVERY_CODES_GENERATED = "mfa_recovery_codes_generated"
MFA_RECOVERY_CODES_REGENERATED = "mfa_recovery_codes_regenerated"
MFA_RECOVERY_CODE_USED = "mfa_recovery_code_used"
MFA_RESET_BY_ADMIN = "mfa_reset_by_admin"
```

(`MFA_RESET_BY_ADMIN` was already named, unimplemented, in PR11.5.1's
own §6 roadmap table — this PR is the one that finally adds it.)

**Where each is emitted**, decided by the same reasoning PR11.5.3
already established (audit lives at the point of the actual
login-flow/administrative decision, not inside a lower-level
primitive):

| Event | Emitted from | Not from |
|---|---|---|
| `MFA_RECOVERY_CODES_GENERATED` | `mfa_service.generate_recovery_codes` (a thin wrapper over a shared `_issue_recovery_codes` helper, §5) | — |
| `MFA_RECOVERY_CODES_REGENERATED` | `mfa_service.regenerate_recovery_codes` (same shared helper, different event) | — |
| `MFA_RECOVERY_CODE_USED` | `mfa_service.verify_mfa_challenge`, at the point a recovery-code match succeeds | **Not** `consume_recovery_code` itself — that function's signature is literally just `consume_recovery_code(code_id)` per this PR's own spec, with no `auth_method`/organization context to attribute a meaningful event to; keeping it a small, audit-free primitive mirrors how `verify_totp_code` (PR11.5.2) is also audit-free, with its caller (`verify_mfa_challenge`) owning the actual audit call |
| `MFA_RESET_BY_ADMIN` | `mfa_service.reset_user_mfa` | — |

`invalidate_recovery_codes` (§5) is likewise audit-free by design — a
small composable primitive called from both `_issue_recovery_codes`
(regenerate path) and `reset_user_mfa` (admin path), each of which
already emits its own, more specific event that already captures *why*
the invalidation happened; a third, generic "codes invalidated" event
from inside the primitive itself would be redundant noise on every
regenerate/reset, not new information.

## 5. Recovery code generation, storage, and verification design

**Generation** — `secrets.choice` over a fixed alphabet, never
`random()`/`uuid`, per this PR's own explicit requirement (re-grepped
this codebase's existing secret-generation call sites —
`apikey_service._generate_key`, PR11.5.2's `generate_totp_secret` —
both already use `secrets`, confirming this is the established
convention, not a new one for this PR to introduce):

```python
_RECOVERY_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ"  # no I/O -- avoid 1/0 confusion
_RECOVERY_CODE_GROUP_LEN = 4
_RECOVERY_CODE_GROUPS = 3     # "AAAA-BBBB-CCCC"
_RECOVERY_CODE_COUNT = 10
```

24-letter alphabet (26 minus `I`/`O`, which are easily confused with
`1`/`0` when hand-typed from a printed sheet — a deliberate,
usability-motivated narrowing, not a security one; entropy is still
`24^12 ≈ 3.2×10^16` per code, ~55 bits, far more than the "one
guessable code among 10, single-use, no online brute-force
amplification path this PR adds" threat model needs). Matches this
PR's own literal example format (`ABCD-EFGH-IJKL`) exactly.

**Storage** — `hashlib.sha256(code.strip().upper().encode()).hexdigest()`,
stored in the existing `code_hash` column, **never the plaintext**.
Same "store a hash, never the plaintext, checked by re-hashing and
comparing" shape `ApiKey.key_hash`/`OAuthClient.client_secret_hash`
already use (re-confirmed by re-reading `apikey_service.py`'s
`_hash_key` this session) — not a new pattern. Normalizes case/
whitespace before hashing (a user re-typing a code from a printed
sheet may vary casing/spacing; the hyphens themselves are part of the
canonical displayed format and are hashed as-is, matching exactly what
was generated and shown).

**Why plain hash-equality lookup, not `hmac.compare_digest`, for
recovery-code verification** — unlike PR11.5.2's TOTP comparison
(explicitly required "constant-time... where applicable" because a
6-digit code is short and guessable digit-by-digit, so a timing
side-channel on the comparison itself would leak partial-match
information), a recovery code's *hash* is what gets compared via a SQL
`WHERE code_hash = :hash` lookup — the value being matched is already
an irreversible 256-bit digest, not the secret itself, so there is no
analogous "how many characters did the attacker get right" timing
signal to protect against. This PR does not add `hmac.compare_digest`
here, and documents why rather than silently omitting it.

**One live batch at a time** — `generate_recovery_codes`/
`regenerate_recovery_codes` both invalidate any existing unused codes
first (via `invalidate_recovery_codes`) before issuing a fresh 10, so
a user can never accumulate two overlapping valid batches (which would
be a confusing, silently-doubled attack surface — an old, forgotten
batch remaining valid alongside a new one). This makes
`generate_recovery_codes` safe to call unconditionally, including a
second time for a user who already has an unused batch.

## 6. Admin reset — permission model

**Reuses `manage_all_orgs` (`MANAGE_ALL_ORGS`), no new permission.**
Re-read `app/api/routes_platform_users.py` in full — every existing
platform-admin route there (`GET /platform/users`, `GET
/platform/users/{id}`, `PATCH /platform/users/{id}`) is gated by the
exact same `_require_platform_admin = require_permission(MANAGE_ALL_ORGS)`
module-level binding, with the same "deliberately not a new, narrower
permission... platform_admin is treated here as one general
cross-tenant capability" reasoning its own comment already states.
This PR's new `POST /platform/users/{user_id}/mfa/reset` is added to
this **same router**, reusing `_require_platform_admin` verbatim — not
a new file, not a new permission, not a new pattern. `caller["sub"]`
(the admin's own id) becomes `actor_user_id`, `user_id` (the path
param) becomes `target_user_id` — the identical shape
`update_platform_user_status` (the existing `PATCH` route immediately
above it) already establishes for `user_admin_service.set_user_status`.

**What "preserve login history, audit history" means concretely**:
`reset_user_mfa` never touches `User.status`, `User.last_login_at`,
`User.authentication_method`, or any `AuditEvent` row — only the five
`mfa_*` columns on `User`, every non-disabled `MFADevice` row's
`disabled_at`, and every unused `MFARecoveryCode` row's `used_at`.
The user's account itself, and every prior audit trail entry
(including this reset's own new `MFA_RESET_BY_ADMIN` row), remain
exactly as they were.

## 7. Security considerations carried forward from prior PRs

- **No rate limiting** on any new endpoint — this codebase still has
  zero rate limiting anywhere
  (`docs/pr11-security-foundation-discovery.md`, Critical risk R2,
  omnibioai-control-center). `/users/me/mfa/challenge`'s
  recovery-code fallback inherits the same pre-existing gap
  `/totp/verify` and the TOTP challenge path already have, explicitly
  out of scope per this PR's own DO NOT list ("separate security PR").
- **Own-resource-only enforcement**, same convention as every prior
  `routes_mfa.py` endpoint: `generate_recovery_codes`/
  `regenerate_recovery_codes`/the status endpoint all derive `user_id`
  from the caller's own JWT `sub` claim (`get_current_user`), never a
  request parameter — there is no way for one user's request to
  target another user's recovery codes through these three endpoints.
- **Cross-user isolation for verification is structural**, same
  reasoning PR11.5.3 already established for TOTP: `verify_recovery_code`
  is always scoped by the `user_id` embedded in the *challenge token*
  itself (§3), never a request parameter — there is no way to express
  "verify this code as a different user."
- **No secrets in logs or audit metadata**: no `logger.*` call
  anywhere in this PR's new code references a plaintext code or its
  hash; every `log_event` call's `metadata`/`before_state`/
  `after_state` is a small, explicit, hand-built dict (code counts,
  booleans) — never a raw code, hash, or `code_hash` column value.
  Verified by construction and re-verified by this PR's own tests.

## 8. Verification method

- Full read of `app/db/models.py`'s `MFARecoveryCode`/`MFADevice`/
  `User` sections (unchanged by this PR, confirming no migration is
  needed).
- Full read of `app/services/mfa_service.py` (current state, PR11.5.2 +
  PR11.5.3 combined) and `app/api/routes_mfa.py` (current state) to
  confirm the exact integration point in `verify_mfa_challenge` and the
  exact existing endpoint/router shape this PR extends.
- Full read of `app/api/routes_platform_users.py` to confirm the exact
  `_require_platform_admin`/`MANAGE_ALL_ORGS` pattern and
  `update_platform_user_status`'s actor/target shape, both reused
  verbatim for the new admin reset route.
- Full read of `app/services/audit_service.py` (`AuditEventType`,
  `log_event`) and `app/services/apikey_service.py` (`_hash_key`, the
  existing "hash, never plaintext" precedent) to confirm naming/
  storage conventions this PR's new code follows.
- Grepped this codebase's existing secret-generation call sites
  (`apikey_service._generate_key`, `mfa_service.generate_totp_secret`)
  to confirm `secrets` (not `random`/`uuid`) is already the
  established convention here, not a new constraint introduced by this
  PR.
- Confirmed (grep) `test_route_authorization_coverage.py`'s automated
  scan is scoped to `/orgs/{org_id}/...` paths only — the new
  `/platform/users/{user_id}/mfa/reset` route falls outside that
  scan's scope, same as every existing `/platform/users/*` route
  already does.
