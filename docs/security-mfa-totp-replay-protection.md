# TOTP Replay / Consumed-Time-Step Protection (HIPAA Phase 3b)

Closes a gap in `POST /users/me/mfa/challenge`'s TOTP verification: the
same valid 6-digit code, correct by construction for up to ~90 seconds
(the `+-1` step clock-skew window), could be redeemed more than once --
each redemption completing a *separate*, independently-issued MFA
challenge and minting its own new session. HIPAA Phase 3
(`docs/security-mfa-challenge-throttling.md`) closed the brute-force
(wrong-guess) gap; this closes a different one -- a single *correct*
code being usable more than once.

This is a security control implementation, **not a HIPAA certification
claim**.

## Discovery summary

Traced the complete verification path
(`app/services/mfa_service.py::verify_mfa_challenge`) before making any
change:

- **TOTP secret verification**: `verify_totp_code` checks a submitted
  code against 3 candidate steps (`for_time-30s`, `for_time`,
  `for_time+30s`) via `hmac.compare_digest`, returning a bare boolean.
  Nothing recorded *which* step matched, and nothing prevented the same
  code from matching again on a later call.
- **`challenge_token` consumption**: `_consume_challenge_jti` inserts the
  token's `jti` into `revoked_tokens` (`UNIQUE(token_jti)`) *only on a
  successful* TOTP or recovery-code match -- a **failed** attempt leaves
  the same `challenge_token` fully valid for the rest of its 5-minute
  TTL. This is not itself the gap (a wrong guess still doesn't grant
  access), but it means jti consumption alone cannot be read as "TOTP
  replay is already solved" -- it only stops one *specific*
  `challenge_token` from being completed twice, not the same *code* from
  completing two *different* `challenge_token`s (e.g. two separate
  logins) within its validity window.
- **`MFADevice` schema**: only `last_used_at` (a timestamp) exists --
  confirmed via `app/db/models.py`, no `last_used_step`/counter column,
  and `last_used_at` was never read back or compared against anything;
  purely informational.
- **Concurrent verification**: no locking of any kind around the
  device-matching loop. Two concurrent requests each presenting a valid
  code (whether the same `challenge_token` or two different ones) both
  ran the full match-and-succeed path independently.
- **Recovery-code verification**: entirely separate mechanism
  (`MFARecoveryCode.used_at`, checked via `verify_recovery_code` then set
  via `consume_recovery_code`) -- correctly single-use in the
  single-request case, but (see "Recovery-code concurrency finding"
  below) not atomic against a genuine concurrent double-request on its
  own.
- **Enrollment confirmation** (`POST /users/me/mfa/totp/verify`): uses
  the same `verify_totp_code`, but has no replay exposure of its own --
  `MFADevice.verified_at`/`disabled_at` already make a second
  confirmation attempt a no-op (`ValueError("This device is already
  verified")`), independent of the code itself. Out of this PR's scope
  for that reason, not an oversight.
- **Multi-instance/distributed behavior**: this service has no existing
  Redis-backed replay-prevention primitive to reuse for this concern
  (HIPAA Phase 3's `app/core/rate_limit.py` is for *counting* failed
  attempts, not for *single-use claiming* a value) -- see "Design choice"
  below for why the fix uses the database instead.
- **Interaction with HIPAA Phase 3 throttling**: `record_success` (HIPAA
  Phase 3) *clears* the account/pair failure counters on every successful
  verification -- so replaying a captured, valid code was not only
  unthrottled, each successful replay actively reset whatever throttle
  state existed. Confirms this is a real gap independent of, not
  mitigated by, the existing throttle.

**Conclusion: the replay gap was real and exploitable.** A code
obtained by an attacker (phishing/real-time relay proxy, shoulder-
surfing, a compromised client at the moment of display, or a race
between a legitimate user's own retried requests) could be redeemed for
more than one independent authenticated session within its ~90s
validity window, without tripping HIPAA Phase 3's throttle at all (each
success actively reset it).

## Threat model

**Attacker prerequisites**: possession of one valid TOTP code for a
target's device, valid for its current ~90s window (via any of the
vectors above), *and* the ability to complete a primary-factor login for
that account (a valid password, or a hijacked primary-auth session) to
obtain a `challenge_token` to present it against.

**Replay window**: up to ~90 seconds (the existing `+-1` step tolerance,
unchanged by this fix) -- the interval during which the *same* code
remains cryptographically valid and could previously be redeemed
repeatedly.

**Exploitability**: single-instance and distributed identically -- the
gap was in application logic (no state tracked which codes had been
used), not in anything instance-local, so it was exploitable regardless
of deployment topology.

**Relationship to HIPAA Phase 3's rate limiting**: throttling reduces
exposure to *guessing* wrong codes; it does not, and structurally cannot,
address a *correct* code being reused, since `record_success` clears
throttle state on every successful verification by design (a legitimate
user who gets their code right shouldn't stay throttled). The two
controls are complementary, not overlapping -- HIPAA Phase 3 stops "try
many codes," this fix stops "reuse one correct code."

**Impact**: without this fix, a single leaked/intercepted valid code
could mint more than one independent session -- a materially stronger
outcome for an attacker than a single compromised session, and contrary
to the security assumption TOTP is normally relied on to provide (that a
second factor, once spent, is spent).

**Where the fix belongs**: in `mfa_service.py`'s TOTP-verification path
specifically (challenge-token handling itself -- `_consume_challenge_jti`
-- was already correctly single-use *for the token*; the gap was one
layer down, in what the token's *code* was allowed to do).

## Design choice: database, not Redis

HIPAA Phase 3's throttle uses Redis (`app/core/rate_limit.py`) for
*counting*, with a documented, deliberate fail-soft-on-Redis-error
policy. This fix does **not** reuse that pattern, and does not introduce
a second Redis-backed subsystem, for two reasons:

1. **The task explicitly requires avoiding fail-open replay protection.**
   Redis is, by this codebase's own established and correct policy,
   allowed to degrade (fail-soft, tighter fallback thresholds) for
   *counting* controls, because an availability tradeoff there is
   acceptable. For *single-use claiming*, degrading to "maybe allow
   reuse" is not an acceptable tradeoff to design around at all.
2. **The database is not a component this service treats as
   degradable.** If the database is unreachable, authentication does not
   work regardless -- there is no existing fallback path for that
   anywhere in this codebase (confirmed: no in-process fallback exists
   for any DB write in `app/services/`). Using the database for this
   claim sidesteps the entire fail-open/fail-closed design question
   Redis would have raised, and reuses a pattern this codebase already
   trusts for exactly this shape of guarantee: `RevokedToken.token_jti`
   (`UNIQUE`, insert-and-catch-conflict) is the existing precedent for
   "prove this identifier hasn't been used before," reused here for the
   identical shape of problem.

`MFAUsedTOTPStep` (new table, `app/db/models.py`,
`alembic/versions/0024_mfa_totp_replay_protection.py`):
`UNIQUE(device_id, time_step)`. `time_step` is TOTP's own RFC 6238
counter (`unix_time // 30`), not a timestamp -- two different valid codes
naturally produce two different rows; the *same* code presented again
always maps to the same `time_step` and is rejected by the constraint at
insert time.

## Remediation

- `app/services/mfa_service.py::_totp_matched_step` -- same window/
  candidate-generation/constant-time-comparison logic as the existing
  `verify_totp_code`, but returns the matched RFC 6238 counter instead of
  a bare boolean. `verify_totp_code` itself is untouched and still used,
  unmodified, by TOTP enrollment.
- `app/services/mfa_service.py::_try_claim_totp_step` -- attempts to
  insert `(device_id, time_step)` and commit; returns `True` only for
  the caller whose commit actually lands. **Fails closed**: any outcome
  other than a clean, confirmed insert (a genuine conflict, or any other
  error) is treated as "cannot confirm this is fresh, therefore reject."
- `verify_mfa_challenge`'s device-matching loop now requires *both* a
  cryptographic match *and* a successful claim before treating a device
  as matched. A code that's right but whose step was already claimed
  falls through exactly like a wrong code -- same `400
  {"detail": "Invalid verification code"}` response, no distinguishing
  oracle between "wrong code" and "correct code, already used."
- **Concurrency hardening**: `_consume_challenge_jti` (the challenge
  token's own single-use enforcement) previously let a genuine
  `IntegrityError` on its `RevokedToken` insert propagate as an unhandled
  500. Now caught and re-raised as the existing `MFAChallengeError`
  (`-> 401`, the same shape an already-consumed token gets via the reuse
  check earlier in the function) -- closing a race the recovery-code path
  can still reach (see "Recovery-code concurrency finding" below), since
  the TOTP path's own race is now made effectively unreachable by
  `_try_claim_totp_step` itself (only one concurrent request can ever
  claim a given step). The rollback this triggers also cleanly discards
  the caller's other not-yet-committed changes for that request
  (`device.last_used_at`/`user.mfa_last_verified_at`) -- no partial state
  survives for the losing request.

**Preserved, unchanged**:

- Clock-skew tolerance (`+-1` step, ~90s) -- identical candidate
  generation, identical comparison, for both first-use and any later,
  different, legitimate step.
- Enrollment confirmation (`verify_totp_enrollment`) -- unmodified,
  still uses `verify_totp_code`, never touches `MFAUsedTOTPStep`.
- Recovery-code single-use semantics (`used_at`) -- unmodified.
- HIPAA Phase 3 throttling -- unmodified; a replay rejection still flows
  through the existing terminal failure branch and is still counted by
  `mfa_throttle_service.record_failure` exactly once, same as any other
  wrong code.
- Identity/keying -- no new client-supplied identifier is trusted
  anywhere; `device_id` comes from the already-verified `MFADevice` row
  looked up via the challenge token's own server-verified `user_id`,
  exactly as before.

## Replay-state lifetime

No explicit expiration or cleanup job, deliberately: a row for a
`time_step` far in the past is never queried again (TOTP's own counter
only ever advances forward in real verification), so it's permanently
irrelevant the moment it's superseded by real time passing -- "expired"
is implicit in the RFC 6238 counter itself, not something this mechanism
needs to actively prune. Table growth is bounded by real *successful*
verification volume, never by attacker-controlled failed-guess volume: a
wrong code never reaches `_try_claim_totp_step` at all (the claim is
only ever attempted after `_totp_matched_step` already confirms a
cryptographic match). This mirrors the exact same unbounded-but-harmless
growth tradeoff `RevokedToken` already makes in this codebase, for the
identical reason -- not a new precedent, not an oversight.

## Concurrency / atomicity guarantees

Provided entirely by the database's own `UNIQUE(device_id, time_step)`
constraint enforcement at commit time -- correct across any number of
horizontally-scaled `omnibioai-auth` instances sharing one database,
without any Redis or in-process state, the same way `RevokedToken`'s
existing `UNIQUE(token_jti)` already is. Verified directly by
`test_try_claim_totp_step_atomicity_directly` (20 concurrent claims
against one step, exactly one succeeds) and end-to-end by
`test_concurrent_duplicate_submissions_result_in_exactly_one_success`
(8 concurrent HTTP challenge requests presenting the same code via 8
different `challenge_token`s, exactly one 200).

## Recovery-code concurrency finding (not fixed here)

Discovered, not remediated in this PR -- a genuinely separate mechanism
from TOTP time-step replay, and not required to close the gap this PR
targets. `verify_recovery_code` (a read: is there an unused row matching
this hash) and `consume_recovery_code` (a separate write: mark it used)
are not atomic with each other -- two truly concurrent requests
presenting the same recovery code could both read "unused" before either
writes.

**Status: closed by HIPAA Phase 5, see
[docs/security-mfa-recovery-code-atomicity.md](security-mfa-recovery-code-atomicity.md)
-- with one correction to this section's own original analysis.** This
section originally assessed the residual risk as *not* allowing two
sessions to be minted, reasoning that the challenge token's own `jti`
uniqueness backstops it. That reasoning holds only for two concurrent
requests racing the *same* `challenge_token` (one `jti`, one row in
`revoked_tokens`, `UNIQUE` rejects the second). It does **not** hold for
two concurrent requests using *different* challenge_tokens (e.g. two
separate logins) presenting the same still-unused recovery code -- each
gets its own distinct `jti`, so neither is ever rejected by that
constraint, and (verified by direct reproduction during HIPAA Phase 5's
own discovery, against this exact pre-fix code) **two independent
sessions could in fact be minted from one recovery code** in that
broader case. The original "no double-session risk" framing understated
the actual exposure; HIPAA Phase 5's `try_consume_recovery_code` closes
both variants with one fix (an atomic `UPDATE ... WHERE used_at IS NULL`
claim, checked by rows-affected), independent of which or how many
challenge_tokens are involved.

## Audit / secret-handling verification

No new audit event type -- a replay rejection is, from the caller's
perspective, indistinguishable from a wrong code, and already flows
through the existing `MFA_VERIFICATION_FAILED` event
(`app/services/mfa_service.py`) and HIPAA Phase 3's
`MFA_RATE_LIMIT_TRIGGERED` (if it crosses a threshold) -- no new event
type needed. Verified directly by
`test_replay_rejection_leaks_no_secret_code_or_token_in_audit`: neither
the TOTP secret, the submitted code, nor the (replayed) `challenge_token`
appears in any audit event generated by a replay attempt.

## Tests added

`tests/test_mfa_totp_replay_protection.py` (15 tests): first-use success,
immediate replay rejection (with a fresh `challenge_token`), replay
falling through to the recovery-code check with the existing generic
error message, concurrent-duplicate-submission atomicity (both via real
HTTP and directly against `_try_claim_totp_step`), replay rejection
across the full `+-1` step window, legitimate adjacent-step codes
remaining valid, first-use clock-skew tolerance unaffected, an old
unrelated consumed step not blocking a later one, same-`challenge_token`
double-completion (`401`, unchanged), cross-user isolation, recovery-code
single-use unchanged (and confirmed to never touch this new table),
audit secret-handling, and enrollment-confirmation unaffected.

## Limitations (intentionally unresolved in this PR)

1. **Recovery-code consumption is not itself atomic** -- see "Recovery-
   code concurrency finding" above. No double-session results (the
   challenge token's jti uniqueness backstops it), but the `used_at`
   write is not exactly-once. Flagged as a follow-up, not fixed here.
2. **The local-password login timing side channel remains unaddressed**
   -- explicitly out of scope for this task. **Status: closed by HIPAA
   Phase 4, see
   [docs/security-login-timing-side-channel.md](security-login-timing-side-channel.md).**
3. **`MFAUsedTOTPStep` has no active pruning job** -- deliberate, bounded,
   harmless growth; see "Replay-state lifetime" above.

## HIPAA Phase 3b mapping

Closes: **TOTP replay / consumed-time-step protection** for
`POST /users/me/mfa/challenge`. Verified by
`tests/test_mfa_totp_replay_protection.py` (15 tests) plus continued
passing of the full existing MFA/session/rate-limiting suite (185 tests
across `tests/test_mfa*.py`, `tests/test_login_rate_limiting.py`,
`tests/test_session_hardening.py`). Status: **Implemented**, with the
recovery-code concurrency finding tracked as an explicit, separate
follow-up, not silently folded into "done." This is a security control
implementation, **not a HIPAA certification** of this service or the
platform built on it.
