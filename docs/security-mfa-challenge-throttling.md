# MFA/TOTP Challenge Throttling (HIPAA Phase 3)

Brute-force protection for `POST /users/me/mfa/challenge` -- the endpoint
that completes an MFA-gated login by verifying a TOTP code (or recovery
code) against a `challenge_token` issued after primary authentication
(password/OAuth/SSO/license) already succeeded. Closes the gap explicitly
flagged, but deliberately left open, by HIPAA Phase 1 PR1's own
[docs/security-auth-rate-limiting.md](security-auth-rate-limiting.md)
("`POST /mfa/challenge` has no throttling ... arguably more urgent than
the local-password gap given a 6-digit TOTP keyspace").

This is a security control implementation, **not a HIPAA certification
claim**. It closes one identified authentication-abuse gap; it does not
by itself make this service, or the platform built on it, HIPAA compliant.

## Discovery summary

- **MFA route inventory**: two routes in `app/api/routes_mfa.py` accept a
  TOTP code: `POST /users/me/mfa/totp/verify` (self-enrollment
  confirmation, gated by `get_current_user` -- the caller already holds a
  real, valid access token) and `POST /users/me/mfa/challenge` (login
  completion, gated by nothing but the `challenge_token` in the request
  body itself -- the caller has no access token yet). No other route in
  this service verifies a TOTP code or a recovery code.
- **MFA architecture**: a challenge can only occur *after* primary
  authentication succeeds -- `auth_service.generate_tokens_or_mfa_challenge`
  is the single point every login flow (password/OAuth/SSO/license) calls,
  and it only ever issues a `challenge_token` once the caller has already
  proven a first factor. There is no "MFA before authentication" state in
  this service.
- **MFA scope**: user-level (`User.mfa_enabled`, `MFADevice`,
  `MFARecoveryCode`), with an *organization*-level policy layer
  (`OrganizationMFAPolicy`) that can require it but does not itself carry
  a per-org secret -- personal MFA enrollment/verification is identical
  regardless of which org (if any) required it. Not SSO-specific or
  local-password-specific: the same `verify_mfa_challenge` completes a
  challenge regardless of which primary-auth method produced the
  `challenge_token` (`auth_method` is just carried through in its
  payload).
- **Existing rate-limit infrastructure (HIPAA Phase 1 PR1)**:
  `app/core/rate_limit.py` is already generic over key names and
  Redis-path thresholds -- reused here as-is, with one small additive
  change (optional `fallback_window_seconds`/`fallback_max_attempts`
  overrides on `record_attempt`, see "Redis failure behavior" below) so
  this control's in-process fallback doesn't have to silently inherit the
  login control's own fallback thresholds.

## Threat model

Addressed:

- **TOTP brute force against one account** from a single IP, or
  distributed across many IPs (changing IP alone must not reset the
  account's own counter) -- the attacker already has (or has guessed) a
  valid first factor and is now guessing the second.
- **Distributed MFA-challenge abuse** -- one source hitting many
  different accounts' challenges (secondary/IP dimension only, per this
  control's explicit design -- never relied on alone).
- **The common single-attacker-single-target case** -- caught fastest by
  the (account, IP) pair dimension.
- **Resubmission of one still-valid challenge_token** -- a failed
  verification does *not* consume the token's `jti` (only a *successful*
  one does, via `mfa_service._consume_challenge_jti`), so a single
  `challenge_token` can otherwise be resubmitted with different codes for
  its full 5-minute lifetime. The throttle's keys are the same regardless
  of whether an attacker reuses one token or re-authenticates for a fresh
  one each time.

Explicitly not addressed by this PR (see Limitations):

- `POST /users/me/mfa/totp/verify` (self-enrollment confirmation) -- a
  fundamentally different threat model (the caller already holds a valid
  access token; brute-forcing their own new device's code grants no
  access they don't already have), out of this PR's explicit scope.
- TOTP replay beyond what already exists -- see "Replay findings" below.
- The local-password login timing side channel (HIPAA Phase 1 PR1's own
  documented, still-open limitation) -- untouched by this PR.
- Any change to JWT architecture, refresh-token rotation, session timeout
  policy, password policy, SAML/SSO behavior, or org/team authorization.

## Strategy: three layered dimensions

Same shape as the login control
([docs/security-auth-rate-limiting.md](security-auth-rate-limiting.md)),
reused not duplicated (`app/core/rate_limit.py`), but with its own
namespace (`mfaratelimit:*`, never `ratelimit:*`) and its own
independently-tunable policy (`MFA_RATE_LIMIT_*`, never `RATE_LIMIT_*`).
Deliberately **not** the same thresholds as login: a TOTP code is a
6-digit value (10^6 space, only ~3 valid values at once given the ±1 step
verification window) checked against a token that isn't single-use on
failure -- see "Threat model" above -- which calls for tighter windows
and lower attempt counts than local-password login gets.

| Dimension | Key | Defends against | Default threshold | Default lockout |
|---|---|---|---|---|
| account | the challenge token's own (signature-verified) `user_id` | attacker varying source IP against one account | 5 failures / 5 min | 5 min (progressive, see below) |
| IP | source IP (`request.client.host`) | one source hammering many accounts' challenges -- secondary control only | 20 failures / 5 min | 5 min |
| (account, IP) pair | hash of `ip:user_id` | the common case -- fast circuit breaker | 3 failures / 5 min | 5 min |

Account-based protection is primary (an attacker can rotate IP, not the
account they're trying to get past MFA for); IP is secondary/abuse-control
only, never relied on alone, per this control's explicit design
requirement.

**Progressive escalation** (account dimension only): identical mechanism
to the login control -- `MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS *
(MFA_RATE_LIMIT_PROGRESSIVE_MULTIPLIER ** (strikes - 1))`, capped at
`MFA_RATE_LIMIT_MAX_LOCKOUT_SECONDS` (default 1800s/30min -- deliberately
lower than login's 3600s/1h cap: recovery codes remain a legitimate way
for a genuinely locked-out user to finish signing in during an escalated
lockout, so an overly long cap buys little extra security while making a
false-positive lockout more painful than necessary).

## Identity / keying

The throttle keys off the `challenge_token`'s own `user_id` claim,
extracted *only after* the token's signature has been verified
(`app.core.jwt.decode_token`) -- this endpoint reads no
`X-Organization-Id`/`X-User-Id` header at all, so there is nothing for a
spoofed header to influence even in principle. Verified directly by
`test_spoofed_organization_header_does_not_influence_throttle` and
`test_spoofed_user_id_header_cannot_reset_or_redirect_the_counter` in
`tests/test_mfa_challenge_throttling.py`: a forged `X-User-Id` naming a
*different*, real, MFA-enabled account neither resets the real account's
counter nor causes the forged account to accumulate one.

No plaintext password, TOTP secret, recovery code, or access/refresh
token is ever used as a key or ever logged. Unlike the login control's
account key (a truncated SHA-256 of the submitted email -- an email
address is meaningful PII to avoid retaining in plaintext), this
control's account key is the bare integer `user_id` -- not hashed,
because a `user_id` is already used unhashed as a plain identifier
everywhere else in this service (`AuditEvent.target_user_id`, URL path
params, etc.) and carries none of an email address's own privacy
sensitivity.

**Enumeration resistance**: `POST /users/me/mfa/challenge` cannot reveal
anything about account existence beyond what it already did before this
PR -- a `challenge_token` is, by construction, already scoped to exactly
one real user (issued only after that user's primary authentication
succeeded); there is no "does this email exist" question at this
endpoint the way there is at `/auth/login`. Once an account is throttled,
*every* request against it (right code, wrong code, or an otherwise-
malformed token) returns the same generic `429`, mirroring the login
control's own "an already-locked account rejects even the correct
credential" behavior.

## Challenge semantics / ordering

`create_mfa_challenge_token` issues a distinct, short-lived (5 min)
per-login challenge token (`type: "mfa_challenge"`, own `jti`) -- this PR
does not add a new challenge/session concept, it throttles verification
attempts *against* the existing one. The throttle check
(`mfa_throttle_service.check_throttled`) runs inside
`mfa_service.verify_mfa_challenge` as early as possible: right after the
token's signature is verified and its `user_id` extracted, but *before*
the `RevokedToken` (single-use) check, the user-active/`mfa_enabled`
checks, the device query, any TOTP secret decryption, or any recovery-code
lookup. A locked account therefore short-circuits before any of that
DB/crypto work runs, and gets a uniform `429` regardless of whether the
underlying token/code would otherwise have separately failed with `401`
or `400`.

## Failed attempts

Exactly one `record_failure` call per HTTP request, on the single
terminal failure branch of `verify_mfa_challenge` -- reached only after
*both* the TOTP-device loop and the recovery-code check found no match.
Never per-device (a user with multiple enrolled devices doesn't get
double- or triple-counted for one request), and never for a request
rejected before that point (malformed/expired/reused/wrong-type token, or
a user no longer active/no longer MFA-enabled) -- those are a different
failure class, not a TOTP-guessing attempt against a resolvable account,
matching this PR's own "don't count unrelated authentication failures"
requirement.

Malformed input (empty string, non-digit, wrong length, pathological
length) and an unexpected exception while checking a device's TOTP secret
or a recovery code (e.g. a corrupted `encrypted_secret`) are both treated
as "this candidate doesn't match" rather than allowed to skip the counter
or 500 the request -- verified by
`test_malformed_code_is_throttled_and_cannot_bypass_counter` and
`test_exception_during_verification_cannot_bypass_throttle`.

## Successful MFA

A successful TOTP or recovery-code verification calls
`mfa_throttle_service.record_success`, which clears the account and
(account, IP) pair counters/locks/strikes for that user -- mirroring the
login control's own `record_success`. Deliberately does **not** clear the
IP-wide counter, for the identical reason: other accounts may still be
under active attack from the same (possibly shared) IP. This runs
*before* `generate_tokens` issues the new session, so no stale lockout
state can carry into or interfere with the now-authenticated session, and
existing session/token semantics (`_consume_challenge_jti`, cookie
issuance, `mfa_verified` claim) are completely unchanged.

## Lockout response

`429` with `Retry-After` (seconds until the longest-remaining active
lockout across the three dimensions expires) and a generic body --
`{"error": "too_many_attempts", "message": "Too many MFA verification
attempts. Try again later."}` -- the same shape
`docs/security-auth-rate-limiting.md` documents for `/auth/login`'s own
throttle response, reused rather than inventing a second convention.
Never reveals the current attempt count or the configured threshold.

## Redis failure behavior

Re-evaluated for MFA specifically, not copied blindly from the login
control. The same two extremes were considered and rejected for the
identical reasons `docs/security-auth-rate-limiting.md` already gives for
login:

- **Fail-open** (disable throttling on Redis error) would silently remove
  the one control this PR exists to add, exactly when sustained attack
  traffic might itself be straining shared infrastructure.
- **Fail-closed** (reject every MFA verification while Redis is down) was
  evaluated and rejected here too -- it would turn a Redis outage into a
  total authentication outage for every MFA-enabled user (not just
  degrade one control), which is a worse failure mode than the control
  being temporarily weaker.

**Actual behavior**: the same hybrid as login -- on any Redis error,
`app/core/rate_limit.py` falls back to a small, bounded, in-process
counter -- but with its own, tighter thresholds
(`MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS`/`MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS`,
defaults 2 attempts / 5 min, vs. login's 5 attempts / 5 min). This
required one small, additive change to the shared
`_InProcessFallback.record_attempt` (and the module-level
`record_attempt` that wraps it): optional `fallback_window_seconds`/
`fallback_max_attempts` parameters, defaulting to `None` (which preserves
`RATE_LIMIT_FALLBACK_*` exactly, so the login control is completely
unaffected) -- `mfa_throttle_service.py` passes its own
`MFA_RATE_LIMIT_FALLBACK_*` values instead of silently inheriting
login's.

This fallback:

- is **not** shared across service instances -- same per-replica
  degradation tradeoff login's fallback already documents, applying
  equally here.
- shares `RATE_LIMIT_FALLBACK_MAX_KEYS` (default 10,000) -- the single
  cardinality cap on the one in-process counter dict
  (`app/core/rate_limit.py::_fallback`) both this control and login's
  populate. **Known, deliberate cross-feature interaction, not an
  oversight**: a large burst of fallback activity from one control could
  in principle evict the other's in-flight fallback state during a
  Redis outage. Not given a second, separate cap -- the existing one
  already bounds total process memory, which is the property that
  matters; a second cap wouldn't change the shared dict's actual size,
  only how the one budget is split.
- increments the existing `auth_rate_limit_backend_degraded_total`
  Prometheus counter (shared with login -- both controls hit the exact
  same Redis-unreachable code path in `app/core/rate_limit.py`, so one
  "was Redis reachable" signal is correct for both, not a gap).
- is exercised directly by
  `test_redis_unavailable_falls_back_and_still_throttles`,
  `test_redis_unavailable_does_not_block_a_correct_verification`, and
  `test_redis_fallback_in_process_state_is_bounded`.

## Atomicity / concurrency

Every increment-and-maybe-lock operation is the same atomic Redis Lua
script login already uses (`_INCR_AND_LOCK_SCRIPT` in
`app/core/rate_limit.py`) -- correct across any number of horizontally-
scaled `omnibioai-auth` instances sharing one Redis, for the identical
reason documented in `docs/security-auth-rate-limiting.md`'s own
"Distributed deployment" section. `test_concurrent_attempts_cannot_bypass_atomic_counter`
fires a concurrent burst of real HTTP challenge requests against one
(account, IP) pair and confirms exactly one lockout-triggered audit
event, regardless of how the burst interleaved -- the underlying script
itself is already covered directly by
`test_concurrent_failures_are_atomic_no_overshoot` in
`tests/test_login_rate_limiting.py`.

## Audit events

New event type: `AuditEventType.MFA_RATE_LIMIT_TRIGGERED =
"mfa_rate_limit_triggered"`, written through the existing
`audit_service.log_event` -- no second audit system. Same "once per
dimension, only on the request that newly crosses that dimension's
threshold" convention as `AUTH_RATE_LIMIT_TRIGGERED`, avoiding audit-log
amplification during a sustained attack.

Metadata recorded: `ip`, `dimension` (`"account"`/`"ip"`/`"pair"`),
`lockout_seconds`. `actor_user_id`/`target_user_id` are the throttled
user's own id (a normal `AuditEvent` field, not new metadata);
`organization_id` is populated when the user has a resolvable primary org
membership, `None` otherwise -- same optional-population convention every
other MFA event in this service already uses. Never: TOTP codes, TOTP
secrets, recovery codes, passwords, access/refresh tokens, or
`challenge_token` values -- verified by
`test_audit_events_never_contain_secrets_codes_or_tokens`, which checks
both `mfa_rate_limit_triggered` and the existing `mfa_verification_failed`
events for every secret/code/token used in that test.

## Secret-handling verification

Explicitly checked, end to end:

- The plaintext TOTP secret exists only inside `verify_totp_code`'s own
  call frame during verification -- never passed to, or held by, any
  throttle function (`check_throttled`/`record_failure`/`record_success`
  take only `user_id`/`ip`/`organization_id`).
- The submitted `code` (right or wrong) is never passed to any throttle
  function either -- only whether it matched is used to decide
  success/failure.
- `challenge_token` itself never appears in a throttle-related audit
  event (only `user_id`, already the resource being described).
- No log statement anywhere in the new code paths logs a code, secret,
  token, or password -- `mfa_throttle_service.py` has no `logging` calls
  at all beyond what `audit_service.log_event`'s own metadata already
  redacts by construction.

## Replay findings

Not expanded into a TOTP redesign, per this PR's explicit scope
boundary. Findings from discovery, recorded here rather than silently
acted on:

- **Single-use challenge_token, but only on success.** Already existing,
  unchanged by this PR: `_consume_challenge_jti` runs only on a
  successful TOTP or recovery-code match; a failed attempt leaves the
  token fully valid for the remainder of its 5-minute TTL. This is the
  primary reason this control exists at all -- see "Threat model" above
  -- and is now bounded by the throttle rather than left open.
- **No per-device "last consumed time-step" tracking.** RFC 6238
  recommends rejecting a TOTP code already accepted once for the same
  time step, independent of any wrapping token's own single-use
  enforcement. This service has no such tracking -- a user (or an
  attacker who has captured one still-valid code) could, in principle,
  present the same correct code against two different challenge attempts
  within the same ~30s step and have both succeed. **Recorded as a
  separate, pre-existing finding, not fixed by this PR**: implementing it
  is a TOTP-verification-layer change (`mfa_service.verify_totp_code`/
  `MFADevice`, likely a new `last_used_step` column), not a throttling
  change, and the throttle this PR adds does not depend on it to be
  effective against the guessing threat model in scope here.
- **±1 step clock-skew window is unchanged.** `_VERIFY_WINDOW = 1` (≈90s
  total tolerance) predates this PR and is untouched -- it modestly
  widens the instantaneous "valid code" set from 1 to 3 values, already
  accounted for in this control's own threshold choices (see "Strategy"
  above), not a new consideration this PR introduces.

## Configuration

All in `app/core/config.py`, `MFA_RATE_LIMIT_*` prefix, every value an
`os.getenv` override:

| Setting | Default | Meaning |
|---|---|---|
| `MFA_RATE_LIMIT_ENABLED` | `true` | Master on/off switch |
| `MFA_RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS` | 5 | Failures before account lockout |
| `MFA_RATE_LIMIT_ACCOUNT_WINDOW_SECONDS` | 300 | Account counting window |
| `MFA_RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS` | 300 | Base account lockout duration |
| `MFA_RATE_LIMIT_IP_MAX_ATTEMPTS` | 20 | Failures before IP lockout |
| `MFA_RATE_LIMIT_IP_WINDOW_SECONDS` | 300 | IP counting window |
| `MFA_RATE_LIMIT_IP_LOCKOUT_SECONDS` | 300 | IP lockout duration |
| `MFA_RATE_LIMIT_PAIR_MAX_ATTEMPTS` | 3 | Failures before pair lockout |
| `MFA_RATE_LIMIT_PAIR_WINDOW_SECONDS` | 300 | Pair counting window |
| `MFA_RATE_LIMIT_PAIR_LOCKOUT_SECONDS` | 300 | Pair lockout duration |
| `MFA_RATE_LIMIT_PROGRESSIVE_MULTIPLIER` | 2 | Account lockout escalation factor per repeat offense |
| `MFA_RATE_LIMIT_MAX_LOCKOUT_SECONDS` | 1800 | Cap on escalated account lockout |
| `MFA_RATE_LIMIT_STRIKE_TTL_SECONDS` | 3600 | How long repeat offenses keep escalating |
| `MFA_RATE_LIMIT_FALLBACK_MAX_ATTEMPTS` | 2 | Threshold used only while Redis is unreachable |
| `MFA_RATE_LIMIT_FALLBACK_WINDOW_SECONDS` | 300 | Window for the above |

`RATE_LIMIT_FALLBACK_MAX_KEYS` (login's own setting) also bounds this
control's in-process fallback -- see "Redis failure behavior" above; not
duplicated as a second, MFA-specific cap.

Not exposed to ordinary application users -- process environment
variables, not application config surfaced through any API, same as the
login control.

## API behavior

`POST /users/me/mfa/challenge` gains exactly one new response shape: a
throttled request returns `429` with the body/headers described in
"Lockout response" above. The existing `401`
(`MFAChallengeError` -- bad/expired/reused/wrong-type token, inactive
user, MFA no longer enabled) and `400` (`ValueError` -- token fine, code
wrong) responses are unchanged in shape and unchanged in when they fire,
except that they no longer fire *at all* for a request against an
already-throttled account (which now gets `429` instead, before the
token/code is even evaluated -- see "Challenge semantics / ordering").
No other endpoint's contract changes.

## Observability

- `auth_mfa_rate_limit_dimension_triggered_total{dimension=...}` -- new
  lockout count, bounded 3-value label, mirroring
  `auth_rate_limit_dimension_triggered_total`.
- `auth_rate_limit_backend_degraded_total` -- reused, not duplicated (see
  "Redis failure behavior").

## Limitations (intentionally unresolved in this PR)

1. **`POST /users/me/mfa/totp/verify` (self-enrollment) is not
   throttled** -- deliberate scope boundary, see "Threat model" above and
   `test_totp_enrollment_verify_endpoint_not_covered_by_this_throttle`.
   Different threat model (already-authenticated caller); a future PR
   could still add a lighter-weight account-only throttle there if
   product/security decides the defense-in-depth is worth it.
2. **No per-device consumed-time-step replay tracking** -- see "Replay
   findings" above. Pre-existing, not introduced or worsened by this PR.
3. **In-process Redis-outage fallback is per-instance and shares its
   cardinality cap with the login control** -- see "Redis failure
   behavior" above.
4. **The local-password login timing side channel remains unaddressed**
   -- HIPAA Phase 1 PR1's own documented, still-open limitation,
   untouched by this PR.

## HIPAA Phase 3 mapping

Closes: **MFA/TOTP challenge brute-force protection** -- the gap HIPAA
Phase 1 PR1 explicitly identified but left out of its own scope. Verified
by `tests/test_mfa_challenge_throttling.py` (26 tests: first/repeated
failures, account/IP/pair throttling, successful-verification reset,
Retry-After/429 shape, malformed-input and exception-during-verification
resistance, Redis-failure behavior and fallback boundedness, expiry/
recovery, audit correctness and secret-handling, spoofed-header
resistance, concurrency/atomicity, config disable, and the explicit
enrollment-verify scope boundary). Status: **Implemented**, with the
limitations above tracked as separate, explicit follow-up items, not
silently folded into "done." This is a security control implementation,
**not a HIPAA certification** of this service or the platform built on
it.
