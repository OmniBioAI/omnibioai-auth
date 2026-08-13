# MFA Recovery-Code Consumption Atomicity (HIPAA Phase 5)

Closes the recovery-code concurrency gap HIPAA Phase 3b's own discovery
identified but explicitly deferred (see
[docs/security-mfa-totp-replay-protection.md](security-mfa-totp-replay-protection.md)'s
"Recovery-code concurrency finding"): `verify_recovery_code` (a read)
and the old `consume_recovery_code` (a separate, unconditional write)
were not atomic with each other, allowing a genuine race to transition
one recovery code from unused to used more than once.

This is a security control implementation, **not a HIPAA certification
claim**.

## Discovery summary

Traced the complete recovery-code flow before making any change:

- **Generation/storage**: `generate_recovery_codes`/`regenerate_recovery_codes`
  (`app/services/mfa_service.py`) issue 10 codes, storing only each
  one's SHA-256 hash (`MFARecoveryCode.code_hash`) -- the plaintext
  exists only for the single response that returns it, never persisted,
  never logged. Unchanged by this PR.
- **`verify_recovery_code`**: a plain, read-only lookup --
  `WHERE user_id = ? AND code_hash = ? AND used_at IS NULL`, returning
  the matching row or `None`. Unchanged by this PR -- still exactly this
  query, still read-only, still grants nothing on its own.
- **The old `consume_recovery_code`**: `SELECT` the row by id, set
  `row.used_at = datetime.utcnow()`, `commit()` -- **no precondition on
  the write at all**. Calling it twice, on the same row, in any order,
  both times "succeeded" (no exception, no rejection) -- the second call
  simply overwrote `used_at` with a slightly later timestamp.
- **MFA challenge verification** (`verify_mfa_challenge`): on a
  successful recovery-code match, calls (old) `consume_recovery_code`,
  then `_consume_challenge_jti`, then `generate_tokens` -- three
  separate steps, each with its own state-mutation, only the *token*
  step (`_consume_challenge_jti`) backed by a database constraint.
- **Challenge-token JTI consumption** (`_consume_challenge_jti`,
  hardened in HIPAA Phase 3b): inserts the `challenge_token`'s `jti`
  into `revoked_tokens`, whose `token_jti` column is `UNIQUE`
  (`app/db/models.py`) -- a real, database-enforced atomic single-winner
  check, but scoped to one specific `jti`. **This is the crux of the
  original finding's blind spot**: it only backstops two concurrent
  requests racing the exact same `challenge_token`. Two different
  challenge_tokens (two separate logins, two different jtis) racing the
  same recovery code are never touched by this constraint at all.
- **Database transaction/session behavior**: the old `consume_recovery_code`
  committed immediately, independently of the later `_consume_challenge_jti`
  commit -- two separate transactions, not one. Preserved by this fix
  (see "Transaction/session behavior" below).
- **Existing migration conventions**: `alembic/versions/0024_mfa_totp_replay_protection.py`
  (HIPAA Phase 3b) is the most recent precedent for adding a new
  single-use-consumption mechanism -- a new table with a `UNIQUE`
  constraint. **Not needed here**: `MFARecoveryCode.used_at` (added by
  the original PR11.5.1 migration, `0013_mfa_foundation.py`) already has
  every column this fix requires; only the *query pattern* used against
  it needed to change. Confirmed no migration necessary (see "Migration"
  below).
- **Existing concurrency/atomic-update patterns in this repo**:
  - `app/services/mfa_service.py::_try_claim_totp_step` (HIPAA Phase
    3b) -- `db.add(...)` + `commit()`, relying on a `UNIQUE` constraint
    and catching the conflict. Not directly reusable here (recovery
    codes have no natural insert-a-new-row-per-use shape the way a TOTP
    time-step claim does), but the same *atomic-claim, fail-closed-on-
    any-non-success* philosophy applies.
  - `app/services/auth_service.py::_revoke_family` -- the exact SQL
    shape this fix uses: `db.query(Model).filter(...).update({...})`,
    an UPDATE with a `WHERE` predicate compiled directly into the SQL
    statement, not a Python-level read-modify-write. That call site
    doesn't need the rows-affected count (it revokes "however many"
    tokens share a family); this fix is the first place in this
    codebase that both uses this UPDATE shape *and* checks its
    rows-affected result as the actual security decision.
  - `app/db/models.py::RevokedToken.token_jti` -- `UNIQUE` constraint,
    insert-and-catch-conflict. A different SQL mechanism (INSERT vs.
    UPDATE) for the same underlying idea: let the database's own
    constraint/predicate enforcement be the source of truth for "did
    this transition already happen," never a Python-level check.

## Deterministic reproduction (pre-fix)

Established the exact race before writing any fix, per this task's own
requirement -- not assumed:

1. Two independent DB sessions (`db_a`, `db_b`), each calling
   `verify_recovery_code` for the same user/code, in sequence but
   *before* either attempts a write. **Both returned the same row**,
   confirming the TOCTOU precondition: nothing prevents two concurrent
   readers from both observing "unused."
2. The old `consume_recovery_code`, called once from each session for
   that same row, **both calls succeeded** with no error -- confirming
   the write side had no guard against a second consumption.
3. End-to-end: two separate logins for the same MFA-enabled user (two
   distinct `challenge_token`s, confirmed distinct `jti`s), each session
   independently calling `verify_mfa_challenge` with the same recovery
   code, driven with explicit interleaving (both reads before either
   write) -- reproduced **two independently-minted sessions from one
   recovery code**, against unmodified pre-fix code.

This corrects a specific claim in HIPAA Phase 3b's own original
"Recovery-code concurrency finding," which assessed the risk as "does
**not** allow two sessions to be minted" because the challenge token's
own `jti` uniqueness was assumed to backstop it. That reasoning holds
only for the *same-challenge_token* race; the reproduction above used
*different* challenge_tokens specifically because that's the case the
`jti` constraint cannot reach. The original finding's residual-risk
assessment was too narrow; this PR closes both variants with one fix.

## Threat model

**Attacker prerequisites**: possession of one valid, still-unused
recovery code for a target account (via the same vectors any recovery
code could be exposed -- a compromised backup/password-manager entry,
social engineering, a captured printed sheet) **and** the ability to
complete primary authentication for that account twice, concurrently,
to obtain two independent `challenge_token`s (or to race one
`challenge_token` concurrently -- the fix closes both).

**Impact**: a single recovery code -- meant to be a single emergency
use of the second factor -- could mint more than one independent
session. Recovery codes are explicitly a *lower-friction, printed/
stored-offline* credential (10 issued at once, meant to survive device
loss); a mechanism that lets one leaked code be worth more than one
login materially weakens that credential's intended one-time-use
guarantee.

**Distributed exploitability**: identical single-instance and
multi-instance -- the gap was a missing database predicate, not
anything instance-local, so it was exploitable regardless of deployment
topology (in fact *more* practically exploitable in a real
multi-instance deployment, where two concurrent requests are more
likely to land on two different application processes with no shared
in-process state at all).

## Required security invariant

For every recovery code, at most one concurrent request may transition
it from unused to used. Enforced entirely by the database.

## Atomicity mechanism

`app/services/mfa_service.py::try_consume_recovery_code` replaces the
old `consume_recovery_code`:

```python
claimed = (
    db.query(MFARecoveryCode)
    .filter(MFARecoveryCode.id == code_id, MFARecoveryCode.used_at.is_(None))
    .update({"used_at": datetime.utcnow()})
)
db.commit()
return claimed == 1
```

One `UPDATE ... WHERE id = ? AND used_at IS NULL` statement, compiled
and sent to the database as a single atomic operation -- the
single-use precondition is part of the *predicate*, not a separate
read beforehand. `Query.update()`'s return value is the database's own
report of how many rows actually matched (and were updated) by that
statement; checking it `== 1` is the entire security decision. No
`SELECT`-then-`UPDATE`, no application-level lock, no Redis, no timing
assumption, no instance affinity of any kind.

`verify_mfa_challenge`'s call site:

```python
if recovery_match is not None and try_consume_recovery_code(db, recovery_match.id):
    ...  # success path, unchanged
```

`recovery_match` (from the unchanged `verify_recovery_code`) only
identifies a *candidate* row -- it grants nothing by itself. Only a
`True` return from `try_consume_recovery_code` -- the actual atomic
claim -- allows the success path to proceed. A code that's hash-correct
but whose claim is lost falls through to the exact same generic
terminal-failure branch a wrong code already used (`400
{"detail": "Invalid verification code"}`), with no distinguishing
oracle between "wrong code" and "correct code, already claimed by
someone else."

## Why this works across multiple application instances

The atomicity comes from the database engine's own row-level locking
during the `UPDATE`, not from anything this service's process holds.
In production (MySQL/InnoDB), two concurrent transactions attempting to
update the same row block on each other at the database level; the
loser's `UPDATE` re-evaluates its `WHERE` clause against the
already-committed state and matches zero rows once the winner commits.
In this test suite (SQLite), the same guarantee holds via SQLite's own
whole-database write-lock serialization. Neither depends on which
process, thread, or `omnibioai-auth` instance issued the query -- the
exact same guarantee `_try_claim_totp_step` (HIPAA Phase 3b) already
relies on for TOTP steps and `RevokedToken.token_jti`'s `UNIQUE`
constraint already relies on for challenge tokens, applied here via an
`UPDATE` predicate instead of an `INSERT` constraint (the natural shape
for "claim an existing row" vs. "claim a not-yet-existing key").

## Transaction/session behavior

`try_consume_recovery_code` commits immediately and independently, the
same separate-commit shape the old `consume_recovery_code` already had
-- **deliberately not bundled** into one transaction with the later
`_consume_challenge_jti` commit. A recovery code this call genuinely,
atomically claims is spent, permanently, regardless of what an
unrelated later step in the same request does. Considered and rejected:
rolling the claim back if a *different* single-use check
(`_consume_challenge_jti`) fails afterward for an unrelated reason
(e.g. a plain duplicated HTTP request racing on the same `challenge_token`)
would reopen exactly the kind of "is this code still valid" ambiguity
this fix exists to close, and changes what "consumed" means for a
credential explicitly designed to be precious and one-time -- this is a
product-semantics question, not a correctness one, and is deliberately
left as the existing, already-shipped behavior rather than decided
unilaterally here.

No partially-created authentication state can result from a *lost*
claim: `try_consume_recovery_code` returning `False` is checked in the
same `if` condition that gates the entire success branch
(`if recovery_match is not None and try_consume_recovery_code(...)`) --
a losing caller never reaches `_consume_challenge_jti`,
`mfa_throttle_service.record_success`, the `MFA_RECOVERY_CODE_USED`
audit event, or `generate_tokens`. Nothing about `user`/`matched_device`
is mutated on that path either (those mutations belong to the *TOTP*
success branch, structurally separate code).

## Migration

**None required.** `MFARecoveryCode.used_at` (nullable `DateTime`, NULL
= unused) already existed, unchanged, since the original PR11.5.1
migration (`0013_mfa_foundation.py`). This fix changes only *how* the
existing column is read and written (one atomic `UPDATE` with a
predicate, instead of a `SELECT` followed by an unconditional write) --
no new column, no new table, no new index, no constraint change. No
existing `MFARecoveryCode` row's data is touched by this change itself.

## Audit behavior

No new audit event type. `MFA_RECOVERY_CODE_USED` is still emitted from
exactly one place (`verify_mfa_challenge`'s recovery-code success
branch), now gated behind the same `if` condition as the atomic claim
itself -- a losing request never reaches the `audit_service.log_event`
call at all, so **exactly one `MFA_RECOVERY_CODE_USED` event can ever
be emitted per recovery code**, even under a genuine concurrent race.
Verified directly by
`test_audit_emits_exactly_one_success_event_under_concurrent_race`.
Never includes the recovery code, its hash, any challenge_token, or any
access/refresh token -- verified by
`test_no_secret_or_code_leakage_in_audit_under_race`.

## Security verification

- **Database-atomic**: yes -- one `UPDATE ... WHERE used_at IS NULL`
  statement, no read-then-write.
- **Exactly one concurrent claimant succeeds**: yes -- verified both by
  deterministic two-session interleaving
  (`test_atomicity_holds_across_separate_db_sessions_deterministic`)
  and by real concurrent HTTP requests
  (`test_concurrent_requests_different_challenge_tokens_same_code_exactly_one_success`,
  `test_concurrent_requests_same_challenge_token_same_code_exactly_one_success`).
- **No process-local lock required**: confirmed -- `try_consume_recovery_code`
  holds no lock object of any kind; correctness verified with 25
  concurrent callers each opening their own, fully independent DB
  session (`test_atomicity_does_not_depend_on_process_local_locking`).
- **No cross-instance race remains**: the mechanism is entirely
  database-enforced (see "Why this works across multiple application
  instances" above) -- there is no in-process state for a second
  instance to be unaware of.
- **Losing requests cannot create sessions**: verified directly --
  every losing response in the concurrency tests carries no
  `access_token`/`refresh_token`.
- **Challenge JTI protection intact**: unmodified logic, still
  `UNIQUE`-constraint-backed; verified by
  `test_challenge_jti_single_use_remains_intact_for_recovery_code_success`
  and the full, unchanged `tests/test_mfa_login_challenge.py`/
  `tests/test_mfa_totp_replay_protection.py` suites.
- **Recovery codes remain hashed/not exposed**: `_hash_recovery_code`/
  storage/generation logic entirely untouched by this PR.
- **No new client-controlled identity source**: `try_consume_recovery_code`
  takes only a `code_id` already resolved server-side from
  `verify_recovery_code`'s own `user_id`-scoped, server-verified query
  (itself keyed off the challenge token's own `user_id` claim, per
  HIPAA Phase 3's identity model) -- no header, no client-supplied
  identifier, anywhere in this change.
- **No MFA throttle regression**: `mfa_throttle_service.record_success`/
  `record_failure` call sites, arguments, and ordering are byte-identical
  to before this fix -- confirmed by the full, unchanged
  `tests/test_mfa_challenge_throttling.py` suite passing.
- **No TOTP replay-protection regression**: `_totp_matched_step`/
  `_try_claim_totp_step`/`MFAUsedTOTPStep` entirely untouched; confirmed
  by the full `tests/test_mfa_totp_replay_protection.py` suite passing
  (one test's own docstring/comments updated for accuracy, no assertion
  changed).
- **No login timing-side-channel regression**: this fix touches neither
  `app/core/security.py` nor `app/services/auth_service.py::authenticate_user`;
  confirmed by the full, unchanged `tests/test_login_timing_side_channel.py`
  suite passing.

## Residual limitations (intentionally unresolved in this PR)

1. **The recovery code's own `used_at` write is not bundled with the
   later challenge-token `jti` consumption in one transaction** -- a
   deliberate choice, not an oversight; see "Transaction/session
   behavior" above for why joining them is a product-semantics decision
   left out of this fix's scope.
2. **No change to recovery-code count, format, or hashing** -- 10 codes,
   `AAAA-BBBB-CCCC` format, SHA-256 hash, all unchanged; this fix is
   entirely internal to how the *existing* single-use check is
   performed.

## HIPAA Phase 5 mapping

Closes: **MFA recovery-code consumption atomicity** -- the gap HIPAA
Phase 3b identified but explicitly deferred (and, per the correction
above, initially underestimated). Verified by
`tests/test_mfa_recovery_code_atomicity.py` (11 tests: normal single-
request behavior unchanged, sequential reuse still rejected,
cross-challenge_token and same-challenge_token concurrent races both
yield exactly one success, a deterministic lock-free two-session proof,
process-local-locking independence, challenge-JTI protection intact,
cross-code independence, and audit/secret-handling under a race) plus
continued passing of the full existing MFA/throttle/replay/timing/
session suites. Status: **Implemented**. This is a security control
implementation, **not a HIPAA certification** of this service or the
platform built on it.
