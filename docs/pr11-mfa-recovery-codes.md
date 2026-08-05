# PR11.5.4 — Enterprise MFA Recovery Codes + Admin Reset

Reference documentation for the recovery-code and admin-reset
capabilities this PR adds on top of PR11.5.1 (MFA database
foundation), PR11.5.2 (TOTP enrollment), and PR11.5.3 (MFA login
challenge). See `docs/pr11-mfa-recovery-codes-discovery.md` for the
pre-implementation discovery this doc's design follows.

## Architecture

```
                    ┌─────────────────────────────┐
                    │  User (self-service, "me")   │
                    └───────────────┬───────────────┘
                                    │
        ┌───────────────────────────┼───────────────────────────┐
        ▼                           ▼                           ▼
POST /users/me/mfa/         GET /users/me/mfa/         POST /users/me/mfa/
   recovery-codes              recovery-codes           recovery-codes/regenerate
        │                           │                           │
        ▼                           ▼                           ▼
mfa_service.                mfa_service.               mfa_service.
generate_recovery_codes     recovery_codes_remaining    regenerate_recovery_codes
        │                                                        │
        └──────────────────────┬─────────────────────────────────┘
                                ▼
                    mfa_service._issue_recovery_codes
                    (invalidate old unused -> generate 10 new ->
                     hash + store -> audit -> return plaintext once)
                                │
                                ▼
                    MFARecoveryCode rows (code_hash only)


                    ┌─────────────────────────────┐
                    │   Mid-login (challenge_token) │
                    └───────────────┬───────────────┘
                                    │
                    POST /users/me/mfa/challenge
                    {challenge_token, code}
                                    │
                                    ▼
                    mfa_service.verify_mfa_challenge
                                    │
                    ┌───────────────┴───────────────┐
                    ▼                                ▼
              TOTP match?                    recovery code match?
           (unchanged, PR11.5.2/3)          verify_recovery_code (new)
                    │                                │
                    └───────────────┬────────────────┘
                                    ▼
                    consume + audit + generate_tokens()
                    (existing, unchanged function -- PR11.5.1's
                     original token-issuance choke point)


                    ┌─────────────────────────────┐
                    │  Platform admin (break-glass) │
                    └───────────────┬───────────────┘
                                    │
                POST /platform/users/{user_id}/mfa/reset
                    (manage_all_orgs, existing permission)
                                    │
                                    ▼
                    mfa_service.reset_user_mfa
                    (disable devices, invalidate codes,
                     clear User.mfa_* -- preserves account,
                     login history, audit history)
```

## Recovery code lifecycle

1. **Issue** — `POST /users/me/mfa/recovery-codes` (first time) or
   `POST /users/me/mfa/recovery-codes/regenerate` (replace an existing
   batch). Both funnel through the same internal
   `mfa_service._issue_recovery_codes`, which:
   - invalidates any currently-unused codes for the user first (so a
     user never holds two live batches at once — see
     `invalidate_recovery_codes`)
   - generates 10 codes in `AAAA-BBBB-CCCC` format via `secrets.choice`
     over a 24-letter alphabet (`A-Z` minus `I`/`O`, to avoid
     hand-typing confusion with `1`/`0`)
   - hashes each with SHA-256 and stores only the hash
     (`MFARecoveryCode.code_hash`)
   - emits `MFA_RECOVERY_CODES_GENERATED` or
     `MFA_RECOVERY_CODES_REGENERATED`
   - returns the 10 plaintext codes in the HTTP response — **the only
     time they are ever visible again**
2. **Check remaining** — `GET /users/me/mfa/recovery-codes` returns
   `{"remaining": N}`, a count only. No endpoint ever returns codes
   after step 1.
3. **Consume** — during an MFA login challenge
   (`POST /users/me/mfa/challenge`), if the presented `code` doesn't
   match any verified TOTP device, it's tried as a recovery code
   (`verify_recovery_code`, scoped to the challenge token's own
   embedded user). A match is consumed (`consume_recovery_code` —
   marks `used_at`), the login completes via the existing
   `generate_tokens`, and `MFA_RECOVERY_CODE_USED` is audited.
   **One-time use**: a consumed code's `used_at` is no longer `NULL`,
   so it never matches `verify_recovery_code`'s own `used_at IS NULL`
   filter again.
4. **Regenerate** — same as step 1's second form; invalidates the
   entire previous batch (even codes never used) before issuing a
   fresh 10.
5. **Admin reset** — invalidates every remaining unused code
   unconditionally, as part of a full MFA reset (see below).

## Storage security

- **`MFARecoveryCode.code_hash`**: SHA-256 hex digest (64 chars) of
  the code, normalized (`.strip().upper()`) before hashing so casing/
  whitespace variance in re-typing doesn't cause a false mismatch.
  **The plaintext code is never persisted anywhere** — not in this
  table, not in any log line, not in any audit event's `metadata`/
  `before_state`/`after_state`.
- Same "store a hash, never the plaintext, verify by re-hashing and
  comparing" pattern already used by `ApiKey.key_hash` and
  `OAuthClient.client_secret_hash` — not a new convention introduced
  by this PR.
- Verification is a direct SQL hash-equality lookup
  (`WHERE code_hash = :hash`), not `hmac.compare_digest` — the
  compared value is already an irreversible digest, not a short,
  guessable secret like a 6-digit TOTP code, so there's no analogous
  timing side-channel to defend against with a constant-time compare.
- No schema change / no migration in this PR — `MFARecoveryCode`
  (PR11.5.1) already had exactly the columns needed. `used_at` is
  reused as a general "no longer redeemable" marker for both genuine
  login-time consumption and administrative invalidation
  (regenerate/reset) — the two cases remain distinguishable via
  `AuditEvent`, not via the row itself.

## Admin reset flow

`POST /platform/users/{user_id}/mfa/reset` — platform-admin only,
reusing the existing `manage_all_orgs` permission (no new permission
added), the same `_require_platform_admin` binding every other
`/platform/users/*` route in `routes_platform_users.py` already uses.

`mfa_service.reset_user_mfa(db, target_user_id, actor_user_id)`:

| Action | Detail |
|---|---|
| Disable every device | Every non-disabled `MFADevice` for the user gets `disabled_at = now()` — soft-remove, same as `remove_device` (PR11.5.2) |
| Invalidate every recovery code | Every unused `MFARecoveryCode` gets `used_at = now()` via `invalidate_recovery_codes` |
| Clear `User.mfa_*` | `mfa_enabled=False`, `mfa_status="disabled"`, `mfa_primary_method=None`, `mfa_enabled_at=None`, `mfa_last_verified_at=None` |
| **Preserved, untouched** | `User.status`, `User.last_login_at`, `User.authentication_method`, every existing `AuditEvent` row |

The user can freely re-enroll from scratch afterward via the normal
PR11.5.2 enrollment flow (`POST /users/me/mfa/totp/enroll`). A
challenge token issued *before* the reset is rejected the moment it's
presented — `verify_mfa_challenge`'s existing `user.mfa_enabled`
re-check (added in PR11.5.3 for the "user disables their own MFA
mid-flight" case) applies identically here, with zero new code needed
for that specific guarantee.

## Audit model

| Event | Actor | Target | Emitted from |
|---|---|---|---|
| `mfa_recovery_codes_generated` | user | same user | `generate_recovery_codes` |
| `mfa_recovery_codes_regenerated` | user | same user | `regenerate_recovery_codes` |
| `mfa_recovery_code_used` | user | same user | `verify_mfa_challenge` (recovery-code success branch) |
| `mfa_reset_by_admin` | admin | target user | `reset_user_mfa` |

Metadata is always a small, explicit, hand-built dict — `codes_issued`/
`codes_invalidated` counts, `authentication_method` string,
`devices_disabled`/`recovery_codes_invalidated` counts. **Never**: a
plaintext recovery code, a `code_hash` value, a TOTP secret, or the
challenge token. Verified both by construction (no call site
references those values) and by this PR's own tests
(`tests/test_mfa_recovery_codes.py`'s `_assert_no_secret_leakage`
checks on every audit-emitting test).

## Limitations

Explicitly out of scope for this PR, per its own instructions:

- No Admin Console UI (backend-only PR; `omnibioai-control-center` is
  untouched).
- No organization-level MFA policy.
- No WebAuthn support.
- No rate limiting on any endpoint in this PR (including the
  recovery-code fallback inside `/users/me/mfa/challenge`) — this
  codebase still has zero rate limiting anywhere
  (`docs/pr11-security-foundation-discovery.md`, Critical risk R2,
  omnibioai-control-center); a known, pre-existing, still-open gap,
  not newly introduced or newly closed here.
- No session-management changes.
- No password-policy changes.
- No permission-model redesign — `manage_all_orgs` is reused as-is.
- No email-based recovery path (recovery codes only).
- Recovery codes are not individually labeled/trackable beyond "used
  or not" — there is no way for a user to see *which* of their 10
  codes was consumed, only the remaining count. Acceptable for a
  one-time-use, all-equivalent batch; would need a schema change
  (e.g. a per-code label) to improve, out of scope here.
