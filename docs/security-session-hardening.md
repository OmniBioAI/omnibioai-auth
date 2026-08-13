# Session Lifecycle and Termination Controls (HIPAA Phase 1 PR3)

Idle timeout, absolute session lifetime, concurrent-session limits, and
explicit session revocation on account disable. Builds on
[PR1's authentication abuse protection](security-auth-rate-limiting.md)
and [PR2's password policy](security-password-policy.md) without
redesigning authentication.

## Security gap

The Phase 1 security review identified: *"Access token = 15 minutes.
Refresh/session lifetime = 7 days, but `expires_at` slides forward on
refresh, so a continuously used session can remain alive indefinitely."*
Verified live against the code before implementing (not assumed): every
call to `rotate_refresh_token` computed `new_expires_at =
utcnow() + 7 days` and wrote it to both the new `RefreshToken` row and
the session's own `expires_at` -- so a session refreshed at least once
a week never actually expired, no matter how long it had been running.

A related, more specific gap found during discovery: disabling a user
(`user_admin_service.set_user_status`) already blocked that user's
*next* request immediately (`assert_token_usable`/`rotate_refresh_token`
both live-check `User.status`), but never touched the underlying
`RefreshToken`/`UserSession` rows -- so **re-enabling the account
silently made their old refresh tokens valid again**. That function's
own docstring explicitly said "no new enforcement code is needed here,"
which was true for immediate blocking but not for permanence across a
disable/re-enable cycle.

## Session model

| Control | Anchor | Default | Enforced at |
|---|---|---|---|
| Idle timeout | `UserSession.last_activity_at` | 7 days | `POST /auth/refresh` |
| Absolute lifetime | `UserSession.created_at` | 30 days | `POST /auth/refresh` |
| Concurrent sessions | count of effectively-active sessions | 5 | `POST /auth/login` (and MFA-challenge completion, which funnels through the same `generate_tokens`) |

A session is valid only when **both** the idle and absolute checks pass
-- either one failing rejects the refresh. Absolute is checked first,
so a session violating both is attributed to the harder ceiling in its
`revoked_reason`.

**Idle timeout default (7 days) intentionally matches today's de facto
behavior** for a normally-used session (refreshed at least once a
week) -- existing users are not affected by this control specifically.
**Absolute timeout (30 days) is the actual new property**: before this
PR there was no ceiling at all; now even a daily user must fully
re-authenticate at least monthly.

**Access tokens are deliberately unchanged** -- still 15 minutes, still
validated by `assert_token_usable` doing only a JTI-blacklist/
`RevokedToken`/`User.status` check, with **no session lookup added to
that path**. Consequence, documented rather than fixed: a session that
crosses its idle/absolute deadline remains usable via its already-issued
access token for up to that token's remaining 15-minute life, until the
next refresh attempt is rejected. Adding a session-table read to every
authenticated request to close a bounded ≤15-minute window would trade
a real, direct performance cost (a DB read on the hot path of every API
call) for a small, already-bounded security improvement -- not a good
trade, and exactly the "expand into a complete token architecture
rewrite" this PR's own scope explicitly warns against.

## Concurrent sessions

Enforced in `generate_tokens` (the single choke point every login flow
-- password, OAuth, SSO, license, MFA-verified -- already funnels
through). On reaching the limit: **the oldest effectively-active session
is evicted** (revoked, not deleted -- see "Data minimization" below),
not a rejection of the new login. Revoked and idle/absolute-expired
sessions never count toward the limit, even if their persisted `status`
column still technically says `active` (nothing has written to that row
yet -- see "Read-time status" below).

**Race safety**: the user's own session rows are locked
(`SELECT ... FOR UPDATE`) for the duration of the login transaction, so
two concurrent logins for the same user can't both observe "room for
one more" and both proceed. New pattern for this codebase (no prior
row-locking precedent) but standard practice; a no-op on SQLite (used in
tests, which has no row-level locking) -- the real guarantee only
matters under concurrent load, which the production database
(MySQL/InnoDB) provides. The failure mode of a race here is bounded and
non-security-critical (occasionally one session over the limit, not an
authentication bypass), unlike PR1's login-rate-limit counters -- which
is why this uses ordinary transactional locking instead of PR1's
atomic-Redis-script approach: the two problems have different severity
profiles.

## Account disable / re-enable

`user_admin_service.set_user_status`, on the active→suspended
transition, now also calls `auth_service.revoke_all_sessions_for_user` --
every non-revoked session belonging to the user is explicitly revoked
(and its refresh-token family marked revoked), not just blocked by the
live status check. Uses the existing admin chokepoint; no parallel admin
pathway was added.

**Re-enable**: previously revoked sessions/tokens stay revoked -- a
disable/re-enable cycle does not resurrect them, since revocation is now
a real, persisted fact rather than a live check that a later status flip
silently undoes. The user must establish a fresh session (log in again).
Verified directly:
`test_reenable_does_not_resurrect_old_refresh_token`.

## Refresh-token rotation

Unchanged: rotation, family revocation, and reuse-detection/replay
protection are exactly as before this PR. The new idle/absolute checks
sit alongside the existing revoked/hard-expiry checks in
`rotate_refresh_token`, not instead of them -- verified by the full
existing `test_refresh_rotation.py`/`test_session_foundation.py` suites
passing unmodified.

## Database

**No migration.** `UserSession.created_at` and `last_activity_at`
already existed (Phase 4 PR-A) but were only ever used for display --
this PR is the first thing to check them against policy. No new
columns, no new tables. The two new read-time-only statuses
(`idle_expired`, `absolute_expired`) follow the exact same convention
`expired` already used: never persisted by a background sweep (no
scheduler exists in this repo), computed at read time in
`session_service.effective_status`. `UserSession.revoked_reason` is
already a free-text column (matching `ApiKey.revoked_reason`'s
established convention) -- the four new reason strings
(`idle_timeout`, `absolute_timeout`, `concurrent_session_limit`,
`account_disabled`) need no schema change.

## Redis

Untouched. This PR is pure DB/config logic -- no new Redis usage, no
change to the existing JTI-blacklist fail-open behavior
(`token_revocation.py`, PR1's own documented decision, unmodified here).

## Audit

**Zero session-lifecycle audit events existed before this PR** -- not
even for logout or manual self-service revocation. One new event type,
`AuditEventType.SESSION_REVOKED`, emitted from a single new helper
(`auth_service._log_session_revoked`) wired into every place a session
is revoked -- both the three pre-existing paths (logout, manual
self-revoke, reuse-detection) and the three new ones (idle timeout,
absolute timeout, concurrent-session eviction) plus account-disable.
One event type with `reason` in metadata, not a family of near-duplicate
event-type constants -- mirrors `LOGIN_FAILURE`'s own established
convention.

Metadata: `reason` only. No passwords, tokens, or token hashes --
verified directly (`test_audit_events_contain_no_secrets`).
`actor_user_id` defaults to the affected user (self-service logout/
revoke); account-disable passes the real admin actor.

## Performance

No new database write on every authenticated request -- the idle/
absolute checks run only inside `POST /auth/refresh`, which already
reads the session row (`session_service.get_by_family_id`, pre-existing)
before this PR; no *new* query was added to read it. The concurrent-
session check runs only inside `POST /auth/login`, not on every request
either. Verified with a query-count regression test
(`test_refresh_query_count_does_not_scale_with_other_sessions`): a
refresh for a user with 10 prior sessions issues no more SQL statements
than one for a user with 1.

## Backward compatibility

Every existing `UserSession` row already has real `created_at`/
`last_activity_at` values (both non-nullable, defaulted at creation
since Phase 4 PR-A) -- there is no legacy-row migration question. A
session created before this PR is evaluated against the same
`created_at`/`last_activity_at` it already had; nothing is
retroactively backdated or force-expired. No user is unexpectedly
logged out by this PR shipping.

## Session listing

`GET /sessions` (`routes_sessions.py`) required zero changes -- it
already serializes through `session_service.effective_status`, which
now additionally reports `idle_expired`/`absolute_expired` alongside
the pre-existing `active`/`revoked`/`expired`. Still never exposes a
raw refresh token, access token, or token hash (unchanged; no such field
exists on the underlying row to begin with).

## Configuration

All in `app/core/config.py`, env-overridable, seconds:

| Setting | Default | Meaning |
|---|---|---|
| `SESSION_IDLE_TIMEOUT_SECONDS` | 604800 (7 days) | Max time a session may go unused before rejection |
| `SESSION_ABSOLUTE_TIMEOUT_SECONDS` | 2592000 (30 days) | Hard ceiling from session creation; refresh never extends it |
| `SESSION_MAX_CONCURRENT` | 5 | Active sessions per user before oldest is evicted |

## Limitations (intentionally unresolved in this PR)

1. Access tokens remain valid for their full 15-minute life even after
   the underlying session crosses idle/absolute timeout -- see "Session
   model" above.
2. Concurrent-session-limit race safety uses ordinary row locking,
   untested under real MySQL/InnoDB concurrency in this PR (only
   SQLite, where it's a documented no-op) -- the logic is verified
   correct; the locking's *effectiveness* under production concurrency
   is not independently load-tested here.
3. No org-scoped or platform-admin session view (`GET
   /orgs/{org_id}/sessions`, `GET /platform/sessions`) -- self-service
   only, matching the existing Phase 4 PR-A scope this PR builds on.
4. The MFA-challenge throttling gap and the unknown-user timing side
   channel (both flagged in PR1/PR2) remain open, separate follow-ups.
   **Status: both since closed** -- MFA-challenge throttling by HIPAA
   Phase 3 (`docs/security-mfa-challenge-throttling.md`), the timing side
   channel by HIPAA Phase 4
   (`docs/security-login-timing-side-channel.md`).

## HIPAA Phase 1 mapping

Closes: **Session lifecycle and termination controls** -- verified by
`tests/test_session_hardening.py` (32 tests: idle timeout, absolute
timeout, combined/boundary conditions, concurrent-session limits
including race safety, manual revocation/logout regressions, account
disable/re-enable, audit correctness, refresh-token replay regression,
and a query-count performance regression). This PR does not, on its
own, establish full HIPAA compliance -- see "Limitations" above and
PR1/PR2's own equivalent sections for what remains.
