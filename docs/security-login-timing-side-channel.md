# Login Authentication Timing Side-Channel (HIPAA Phase 4)

Closes the timing side-channel identified during HIPAA Phase 1 PR1's own
discovery but explicitly left open at the time (see
[docs/security-auth-rate-limiting.md](security-auth-rate-limiting.md)'s
"Enumeration resistance" section): `POST /auth/login` returned
measurably faster for an unknown email than for a real account with a
merely wrong password, because only the latter ran a full bcrypt
verification.

This is a security control implementation, **not a HIPAA certification
claim**.

## Discovery summary

Traced `POST /auth/login`'s complete failure-path logic
(`app/api/routes_auth.py::login` -> `app/services/auth_service.py::authenticate_user`
-> `app/core/security.py::verify_password`) before making any change:

- **Password authentication / account lookup**: `authenticate_user` does
  one `db.query(User).filter(User.email == email).first()`, then branches
  three ways, all returning `None` (-> the route's `401 {"detail":
  "Invalid credentials"}`, identical response shape for all three):
  1. `not user or user.status != "active"` (unknown email, or a real but
     disabled account)
  2. `not user.hashed_password` (a real, active, OAuth-only account with
     no local password)
  3. `not verify_password(password, user.hashed_password)` (a real,
     active, password-having account -- wrong password)
- **Password-hash verification timing**: only branch 3 called
  `verify_password` before this fix. Branches 1 and 2 returned
  immediately after one cheap indexed DB lookup -- no hashing work at
  all. `verify_password` wraps `pwd_context.verify` (bcrypt_sha256 by
  default, see `app/core/security.py`'s own `pwd_context` docstring),
  which is *deliberately* expensive (that's what makes bcrypt a good
  password hash) -- on this environment, empirically ~200ms per call.
- **MFA challenge generation**: unaffected by, and irrelevant to, this
  gap -- MFA challenge issuance only happens *after* a successful
  password verification (branch 3 *not* taken, i.e. the code falls
  through past all three failure branches). The timing question here is
  entirely about the three *failure* branches converging, not about
  success vs. failure being distinguishable (which is expected and
  unavoidable -- a successful login always returns something different
  from a failed one).
- **Rate limiting / lockout**: `login_throttle_service.check_throttled`
  is evaluated *before* `authenticate_user` is ever called
  (`routes_auth.py::login`, unchanged by this fix) -- a throttled request
  never reaches any password verification, real or dummy, so this fix
  introduces no new resource-exhaustion vector for an attacker hammering
  an already-locked account/IP. Confirmed directly by
  `test_rate_limited_login_never_invokes_password_verification`.
- **Session/token issuance**: entirely downstream of a *successful*
  branch 3, untouched by this fix.
- **SAML/SSO paths**: `find_enforced_org_for_email` (Phase 2 PR5) is
  checked even earlier than the throttle peek, before `authenticate_user`
  is reached at all, for any email matching an SSO-enforced org --
  confirmed via `grep` that `verify_password`/`authenticate_user` have
  exactly two call sites in this entire codebase (see "Scope" below);
  neither is in any SSO/SAML/OAuth callback file. This fix touches
  neither `app/api/routes_oauth.py` nor any `routes_*saml*.py`/
  `routes_org_sso.py` file. Confirmed unaffected by
  `test_sso_enforced_login_still_bypasses_password_verification_entirely`.

**Conclusion: the timing side-channel was real and empirically
confirmed**, not assumed. Measured directly against unmodified `main`
(15 samples per branch, local bcrypt_sha256 default cost factor):

| Branch | Avg. response time |
|---|---|
| Unknown email | ~25ms |
| Real account, wrong password | ~229ms |

**~9x slower** for the wrong-password branch -- a difference far larger
than ordinary network/scheduling jitter, and trivially distinguishable
by an attacker sampling repeatedly (which averages out jitter). After
this fix, on the same measurement: **~228ms vs. ~228ms (1.00x)**.

## Threat model

**Attacker prerequisites**: network access to `POST /auth/login` (no
authentication, no special privilege) and the ability to measure
response time, either directly or via repeated sampling to average out
network jitter -- a low bar, not a sophisticated attack.

**What it revealed**: which submitted email addresses correspond to
*real, password-protected accounts* on this platform, independent of
guessing any password. This is an account-enumeration oracle -- useful
to an attacker for building a target list before a credential-stuffing
or phishing campaign, or for confirming a specific individual has an
account here at all (a privacy concern independent of credentials ever
being compromised).

**What it did not reveal**: anything about the password itself (no
digit-by-digit or partial-match signal) -- `verify_password`'s own
`hmac`-based comparison inside passlib is already constant-time with
respect to the *hash comparison*; the side-channel here was about
*whether hashing ran at all*, a coarser, binary signal (branch 1/2 vs.
branch 3), not a fine-grained one.

**Relationship to HIPAA Phase 1 PR1's rate limiting**: complementary,
not overlapping. Throttling (`docs/security-auth-rate-limiting.md`)
bounds how many login *attempts* an attacker can make; it does nothing
to prevent a *single* well-timed request (or a handful, safely under any
threshold) from leaking account existence. This fix closes that
independent gap.

**Relationship to HIPAA Phase 3's MFA throttling**: no interaction --
MFA challenge verification (`docs/security-mfa-challenge-throttling.md`)
only begins after a *successful* password verification; this fix's
scope is entirely within the *failure* branches that precede it.

## Scope: exactly one vulnerable entry point, one already-out-of-scope finding

`verify_password` has exactly two call sites in this codebase (verified
by `grep`, not assumed):

1. **`app/services/auth_service.py::authenticate_user`** -- the gap this
   PR closes. Reachable with an arbitrary, attacker-chosen email on every
   `POST /auth/login` request; the branch it takes (and therefore the
   account-existence signal) is entirely attacker-observable.
2. **`app/api/routes_oauth.py::confirm_oauth_link`** (`POST
   /auth/{provider}/link/confirm`) -- a structurally different
   situation, **not modified by this PR**: the `user` here is already
   resolved from a signed `link_token` minted earlier in a real OAuth
   exchange (`oauth_service.find_user_by_email` already ran, against a
   *known* email, at token-mint time) -- there is no "submit an arbitrary
   candidate email and observe the branch" primitive here the way there
   is at `/auth/login`. The endpoint's own `404 "Account not found"`
   (token points at a user that no longer exists) vs. `401 "Incorrect
   password"` (wrong password) responses are already explicitly,
   visibly different via **status code**, independent of timing, and
   reaching either branch first requires a valid, signed `link_token` an
   attacker cannot forge. **Recorded here as a discovered, deliberately
   out-of-scope finding** (mirroring HIPAA Phase 3b's own "Recovery-code
   concurrency finding" precedent) -- not fixed in this PR, since it is
   not the "unknown username/email enumeration via `/auth/login`" gap
   this task targets, and applying the same dummy-hash technique there
   would be a legitimate but separate follow-up if ever prioritized.

## Remediation

`app/core/security.py`: new module-level constant `DUMMY_PASSWORD_HASH`
-- a real `pwd_context.hash(...)` of a fixed, arbitrary placeholder
string (never a real credential, never compared against anything
meaningful), computed **once, at import time**, using the exact same
scheme/cost factor (`bcrypt_sha256`, this context's current default) any
real registration hash uses. Not a hardcoded literal: computing it via
`pwd_context.hash(...)` means it always matches whatever this process's
actual default hashing cost is, including if that default is ever
changed later, with nothing else to remember to keep in sync.

`app/services/auth_service.py::authenticate_user`: the first two failure
branches (previously returning immediately) now call
`verify_password(password, DUMMY_PASSWORD_HASH)` before returning `None`
-- spending the same bcrypt-bound CPU time the third (real-hash) branch
already pays, before continuing to the identical audit/throttle/response
logic each branch already had. The dummy verification's boolean result
is always discarded (never assigned, never checked) -- it changes
nothing about which branch is taken or what response is returned, only
how much CPU time is spent getting there.

## Why this equalizes the relevant work

bcrypt's (and therefore bcrypt_sha256's) verification cost is a function
of the *target hash's own embedded cost parameter* (its `$2b$12$...`-style
work-factor prefix), not of the plaintext being checked or of whether the
two ultimately match. `DUMMY_PASSWORD_HASH` is produced by the exact same
`pwd_context.hash(...)` call (same default scheme, same default cost
factor) that produces every real user's password hash at registration --
so a dummy verification and a real verification against an
equally-recent real hash cost the same order of magnitude of CPU time by
construction, not by coincidence or careful tuning. This is the standard
mitigation for this class of vulnerability (compare against a fixed,
real hash of the correct scheme/cost rather than skip hashing entirely),
not a novel technique.

## Interaction with existing rate limiting and MFA

- **Rate limiting**: unaffected in both directions. The throttle check
  still runs *before* `authenticate_user` (unchanged ordering), so a
  throttled request still short-circuits before any password
  verification, real or dummy -- no new resource-exhaustion path.
  `login_throttle_service.record_failure`/`record_success` are still
  called from the exact same three/one places, with the exact same
  arguments, in the exact same order relative to everything else in each
  branch -- this fix adds one function call per branch, nothing else.
- **MFA**: entirely unaffected -- MFA challenge issuance
  (`generate_tokens_or_mfa_challenge`) is only reached after
  `authenticate_user` returns a real `user` (the success path, never
  touched by this fix).
- **Account lockout / audit logging**: every existing `_log_login_failure`
  call, its `reason` metadata value, and `login_throttle_service.record_failure`'s
  arguments are byte-identical to before this fix -- only one line (the
  dummy verification call) was added immediately before each, nothing
  reordered or removed.

## Residual limitations (intentionally unresolved in this PR)

1. **`POST /auth/{provider}/link/confirm` has its own, separate,
   lower-severity `verify_password` call site** -- see "Scope" above.
   Not an arbitrary-email enumeration oracle (requires a valid signed
   `link_token` first), not fixed here.
2. **Database query timing itself is not equalized.** An index lookup
   for an existing row vs. a miss can differ by a small, sub-millisecond-
   to-low-single-digit-millisecond amount depending on database engine,
   cache state, and index depth -- dwarfed by bcrypt's ~100-300ms cost
   (the dominant signal this PR closes), but not literally zero. This is
   an inherent property of essentially any indexed-lookup-backed
   authentication system, not specific to this codebase, and not
   practically exploitable at this codebase's data volumes; recorded as
   a known, accepted residual, not silently ignored.
3. **Network-level timing variance** (routing, TLS handshake reuse,
   server load) is entirely outside this service's control and
   unaffected by any change at this layer.
4. **`PasswordSizeError`'s early return** (an oversized, >4096-byte
   password) still short-circuits *inside* `verify_password` faster than
   a full hash -- but identically on both the dummy-hash and real-hash
   branches (the size check runs before any scheme-specific work,
   independent of which hash it's being compared against), so this
   introduces no *new* asymmetry between "unknown user" and "wrong
   password" -- both are equally fast for an oversized input, both are
   equally slow (bcrypt-cost) for a normal-length one. Verified by
   `test_oversized_password_against_unknown_user_still_invokes_verification`
   and its real-account counterpart.

## HIPAA Phase 4 mapping

Closes: **login authentication timing side-channel** -- the gap
identified but explicitly deferred by HIPAA Phase 1 PR1 (see that PR's
own `docs/security-auth-rate-limiting.md` "Enumeration resistance"
section). Verified by `tests/test_login_timing_side_channel.py` (14
tests: every failure branch invokes exactly one password-hash
verification against the expected hash -- deterministic call-count/
call-argument assertions, not wall-clock timing, per this task's own
guidance to avoid duration-based regression tests -- plus success/MFA/
throttled/malformed/concurrent/SSO/audit coverage) and empirical
before/after timing measurement during discovery (documented above,
~9x -> ~1.00x). Status: **Implemented**, with the `link/confirm`
finding tracked as a separate, explicit, lower-severity follow-up, not
silently folded into "done." This is a security control implementation,
**not a HIPAA certification** of this service or the platform built on
it.
