# Authentication Abuse Protection (HIPAA Phase 1 PR1)

Login rate limiting and brute-force protection for local-password
authentication (`POST /auth/login`). Implements the primary gap identified
in the Phase 1 security review: this service's existing authentication
foundation (JWT validation, refresh-token rotation/replay detection,
session tracking, server-side revocation, org/team authorization,
privileged-operation auditing, login success/failure audit events) had no
throttling, lockout, or brute-force protection on local-password login
itself.

## Threat model

Addressed:

- **Credential guessing against one account** from a single IP, or
  distributed across many IPs (changing IP alone must not reset the
  account's own counter).
- **Credential stuffing / spraying** — many different accounts attacked
  from one IP or small IP range (changing the target account alone must
  not reset the attacking IP's own counter).
- **The common single-attacker-single-target case** — caught fastest by
  the (account, IP) pair dimension, well before either broader counter
  would trip on its own.

Explicitly not addressed by this PR (see Limitations):

- The unknown-user-returns-before-bcrypt timing side channel identified in
  the Phase 1 gap assessment.
- Brute-forcing the TOTP code at `POST /mfa/challenge` — a real, separate
  gap found during this PR's discovery (no throttling exists there
  either), but MFA is out of this PR's scope.
- Anything upstream of this service: nginx's existing
  `limit_req_zone $binary_remote_addr zone=auth_limit rate=10r/m` (see
  `omnibioai-studio/docker/nginx-router.conf`) already rate-limits all
  `/auth/*` traffic per source IP at the reverse-proxy layer. That's
  complementary defense-in-depth, not a substitute for this control: it's
  IP-only, applies uniformly to every `/auth/*` route (not
  login-failures specifically), is local to each nginx instance, and
  produces no audit trail. This PR doesn't modify it.
- SAML/OAuth/OIDC login — see "SSO/SAML/OAuth users" below.

## Strategy: three layered dimensions

All three are evaluated on every `POST /auth/login` call to the local-
password path (`app.services.auth_service.authenticate_user`, the only
caller of `verify_password`), keyed on values available before any
credential verification runs:

| Dimension | Key | Defends against | Default threshold | Default lockout |
|---|---|---|---|---|
| account | truncated SHA-256 of submitted email | attacker varying source IP against one account | 10 failures / 15 min | 15 min (progressive, see below) |
| IP | source IP (`request.client.host`) | attacker varying target account from one IP | 30 failures / 15 min | 15 min |
| (account, IP) pair | hash of `ip:email` | the common case — fast circuit breaker | 5 failures / 5 min | 5 min |

Changing only the email, or only the IP, does not reset the dimension the
attacker *didn't* change — that's what makes this layered rather than a
single counter. The pair dimension's tighter threshold means it's usually
what actually stops a real attack first; the account and IP dimensions
exist for the cases where an attacker deliberately keeps the pair fresh
(rotating IP *and* varying nothing else, or vice versa).

**Progressive escalation** (account dimension only): each time the same
account's lockout retriggers before its "strike" window
(`RATE_LIMIT_STRIKE_TTL_SECONDS`, default 24h) expires, the lockout
duration actually applied is
`RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS * (RATE_LIMIT_PROGRESSIVE_MULTIPLIER ** (strikes - 1))`,
capped at `RATE_LIMIT_MAX_LOCKOUT_SECONDS` (default 1h). A single lockout
cycle is unaffected; only an account still under repeated attack across
multiple cycles sees escalating lockouts.

## Recovery behavior

- Every counter and lock key carries its own Redis TTL — recovery is
  automatic, no administrator action or database mutation required for
  ordinary temporary throttling.
- A successful login resets the account and (account, IP) pair counters
  for that account/IP — **not** the IP-wide counter, since other accounts
  may still be under active attack from a shared/NAT'd IP that one user's
  successful login says nothing about.
- No permanent account lockout exists anywhere in this design. There is no
  new "admin unlock" endpoint — none of the lockouts this PR introduces
  can outlast `RATE_LIMIT_MAX_LOCKOUT_SECONDS` (1h default), so the
  existing account-management surface doesn't need one.

## Enumeration resistance

`POST /auth/login` continues to return an identical `401 {"detail":
"Invalid credentials"}` for an unknown email, a password-less OAuth-only
account, and a genuinely wrong password — unchanged from before this PR.
Throttling is keyed off a hash of whatever email string was *submitted*,
independent of whether that account exists, so a `429` is returned
identically for a real account under attack and for a nonexistent one
(verified in `tests/test_login_rate_limiting.py::
test_throttled_response_identical_for_real_and_fake_accounts`).

**Known, deliberately unresolved gap**: the Phase 1 assessment identified
that an unknown-email request returns *faster* than a real-account wrong-
password request, because the latter also runs bcrypt verification. This
PR does not add timing equalization — doing so well (constant-time dummy
hash comparison for unknown users) is a real, separable piece of work,
and folding it into this PR would have expanded scope past "add rate
limiting" into "redesign login timing behavior." **Recorded here as a
follow-up finding, not silently expanded into.**

## Redis behavior

This is the one place this PR deliberately does **not** reuse an existing
pattern in this codebase. `token_revocation.py`'s access-token blacklist
check fails *open* on Redis error (documented in that module: an
unreachable Redis must not 500 every authenticated request in the
service). Copying that here would silently disable brute-force protection
exactly when it matters most — during sustained attack traffic that might
itself be straining shared infrastructure. Failing fully *closed*
instead (reject all logins on Redis error) was also rejected: that turns
a Redis outage into a total login outage, which is a worse failure mode
than a degraded control.

**Actual behavior**: hybrid. `app/core/rate_limit.py` wraps every Redis
call; on any exception it falls back to a small, bounded, in-process
counter (`RATE_LIMIT_FALLBACK_MAX_ATTEMPTS` / `RATE_LIMIT_FALLBACK_WINDOW_SECONDS`,
defaults 5 attempts / 5 min — deliberately tighter than the normal
Redis-backed thresholds). This fallback:

- is **not** shared across service instances — a multi-replica deployment
  gets weaker (per-instance) protection during a Redis outage, not zero
  protection; this is a deliberate, bounded degradation, documented here
  rather than assumed away
- is capped at `RATE_LIMIT_FALLBACK_MAX_KEYS` (default 10,000) distinct
  keys, clearing entirely if exceeded, to bound memory during a
  prolonged outage under attack traffic
- is exercised by dedicated tests
  (`test_redis_unavailable_falls_back_and_still_throttles`,
  `test_redis_unavailable_does_not_break_normal_login`,
  `test_redis_recovery_uses_normal_thresholds_again`), not left
  unverified
- increments the `auth_rate_limit_backend_degraded_total` Prometheus
  counter every time it activates, so an operator can see Redis
  connectivity problems in this specific subsystem, not just infer them

## Distributed deployment

Every increment-and-maybe-lock operation runs as one atomic Redis Lua
script (`_INCR_AND_LOCK_SCRIPT` in `app/core/rate_limit.py`) — a single
round trip that reads the current count, increments it, and sets the lock
if the threshold is newly crossed, all inside Redis's own single-threaded
execution. This avoids the classic read-increment-write race: concurrent
requests against the same key are serialized by Redis itself, not by
anything in this service's own process, so it's correct across any number
of horizontally-scaled `omnibioai-auth` instances sharing one Redis.
Verified directly in
`test_concurrent_failures_are_atomic_no_overshoot` (25 concurrent calls
against one key pair, exactly one observes the threshold-crossing
transition) and `test_concurrent_requests_do_not_double_trigger_audit` (a
concurrent burst of real HTTP login attempts against the auto-generated
lockout still produces exactly one audit event).

## Audit events

New event type: `AuditEventType.AUTH_RATE_LIMIT_TRIGGERED =
"auth_rate_limit_triggered"` (`app/services/audit_service.py`), written
through the existing `audit_service.log_event` — no second audit system.
Emitted once per dimension, only on the request that newly crosses that
dimension's threshold (not on every subsequent throttled attempt while a
lockout is already active — that would amplify the audit log during a
sustained attack for no investigative benefit; a lockout's own presence
and duration is already recoverable from Redis/metrics while active).

Metadata recorded: `email` (the submitted email — consistent with the
existing `login_failure` event, which already records this in plaintext),
`ip`, `dimension` (`"account"` / `"ip"` / `"pair"`), `lockout_seconds`.
Never: passwords, access/refresh tokens, or full request bodies — verified
by `test_audit_events_never_contain_password_or_tokens`.

## Configuration

All in `app/core/config.py`, `RATE_LIMIT_*` prefix, every value an
`os.getenv` override (no code change or redeploy needed to retune):

| Setting | Default | Meaning |
|---|---|---|
| `RATE_LIMIT_ENABLED` | `true` | Master on/off switch |
| `RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS` | 10 | Failures before account lockout |
| `RATE_LIMIT_ACCOUNT_WINDOW_SECONDS` | 900 | Account counting window |
| `RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS` | 900 | Base account lockout duration |
| `RATE_LIMIT_IP_MAX_ATTEMPTS` | 30 | Failures before IP lockout |
| `RATE_LIMIT_IP_WINDOW_SECONDS` | 900 | IP counting window |
| `RATE_LIMIT_IP_LOCKOUT_SECONDS` | 900 | IP lockout duration |
| `RATE_LIMIT_PAIR_MAX_ATTEMPTS` | 5 | Failures before pair lockout |
| `RATE_LIMIT_PAIR_WINDOW_SECONDS` | 300 | Pair counting window |
| `RATE_LIMIT_PAIR_LOCKOUT_SECONDS` | 300 | Pair lockout duration |
| `RATE_LIMIT_PROGRESSIVE_MULTIPLIER` | 2 | Account lockout escalation factor per repeat offense |
| `RATE_LIMIT_MAX_LOCKOUT_SECONDS` | 3600 | Cap on escalated account lockout |
| `RATE_LIMIT_STRIKE_TTL_SECONDS` | 86400 | How long repeat offenses keep escalating |
| `RATE_LIMIT_FALLBACK_MAX_ATTEMPTS` | 5 | Threshold used only while Redis is unreachable |
| `RATE_LIMIT_FALLBACK_WINDOW_SECONDS` | 300 | Window for the above |
| `RATE_LIMIT_FALLBACK_MAX_KEYS` | 10000 | Bounds in-process fallback memory |

Not exposed to ordinary application users — these are process
environment variables, not application config surfaced through any API.

## API behavior

`POST /auth/login` gains exactly one new response shape: a throttled
request returns `429` with `{"error": "too_many_attempts", "message":
"Too many failed login attempts. Try again later."}` and a `Retry-After`
header (seconds until the longest-remaining active lockout across the
three dimensions expires). The existing `401 {"detail": "Invalid
credentials"}` for bad credentials is unchanged. No other endpoint's
contract changes; no frontend changes are required (a client that doesn't
special-case 429 today simply sees a failed login, same as any other
error).

## Observability

- `jwt_auth_total{endpoint="/auth/login", result="throttled"}` — reuses
  the existing `JWT_AUTH_TOTAL` counter already tracking
  success/failure/mfa_required for this endpoint, rather than inventing a
  parallel metric for the same measurement.
- `auth_rate_limit_dimension_triggered_total{dimension=...}` — new lockout
  count, bounded 3-value label (never email/IP/user id).
- `auth_rate_limit_backend_degraded_total` — Redis-fallback activations,
  no labels.

## SSO/SAML/OAuth users

`find_enforced_org_for_email` (checked first in `routes_auth.py::login`,
unchanged position) short-circuits to `403 sso_required` before
`authenticate_user` — and therefore before this control — ever runs for
an SSO-enforced org's email. Verified end-to-end in
`test_sso_enforced_login_bypasses_password_throttle_entirely`: repeated
attempts against an SSO-enforced email never trigger a lockout and never
see a `429`. Brute-force protection for those logins is delegated to the
organization's own enterprise IdP — duplicating IdP-side controls here
would be redundant and out of this PR's scope.

## Privacy

- The account and pair dimensions key on a truncated (16 hex char)
  SHA-256 of the email, not the raw address — consistent with this
  service's existing `_hash_refresh_token`/`_hash_key` convention. This is
  a lighter measure than full anonymization (a known email can still be
  hashed and looked up by anyone with Redis access) and is documented as
  such, not oversold.
- Every rate-limit key (Redis or in-process fallback) carries an explicit
  TTL — nothing persists past its counting window or lockout duration.
  No new permanent table of IP addresses or account identifiers is
  created.
- Audit events follow the existing `AuditEvent` retention model — no new
  retention policy introduced by this PR.

## Limitations (intentionally unresolved in this PR)

1. **Timing side channel** — see "Enumeration resistance" above.
2. **`POST /mfa/challenge` has no throttling** — discovered during this
   PR's work, arguably more urgent than the local-password gap given a
   6-digit TOTP keyspace, but MFA redesign is explicitly out of this PR's
   scope. Needs its own follow-up.
3. **In-process Redis-outage fallback is per-instance** — see "Redis
   behavior" above.
4. **The nginx `auth_limit` zone is untouched** — it's in a different
   repository (`omnibioai-studio`) and already provides IP-only,
   non-login-specific, per-instance defense-in-depth; this PR doesn't
   change it.

## HIPAA Phase 1 mapping

Closes: **Authentication abuse protection** — verified by
`tests/test_login_rate_limiting.py` (30 tests: normal auth, account/IP/pair
throttling, distributed/race atomicity, reset/recovery, Redis-failure
behavior, audit correctness, enumeration resistance, SSO exclusion, and
bypass/malformed-request handling — see that file for the full list).
Status: **Implemented**, with the limitations above tracked as separate
follow-up items, not silently folded into "done."
