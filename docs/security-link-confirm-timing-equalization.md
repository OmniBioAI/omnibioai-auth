# `POST /auth/{provider}/link/confirm` Timing Equalization (HIPAA Phase 4 follow-up)

Closes the `verify_password` timing gap in `confirm_oauth_link`
(`app/api/routes_oauth.py`) that
[docs/security-login-timing-side-channel.md](security-login-timing-side-channel.md)
found during its own discovery but deliberately left open, recorded there
as residual limitation #1: "`POST /auth/{provider}/link/confirm` has its
own, separate, lower-severity `verify_password` call site... not fixed
here."

This is a security control implementation, **not a HIPAA certification
claim**.

## Discovery summary

Re-traced `confirm_oauth_link`'s complete failure-path logic before
making any change, confirming the gap HIPAA Phase 4 documented still
exists, byte-for-byte, on `main` (base commit `841beec`, containing
merged PRs #54-#58):

```python
try:
    payload = decode_token(body.link_token)
except Exception:
    raise HTTPException(400, "Invalid or expired link token")      # (1)
if payload.get("type") != "oauth_link":
    raise HTTPException(400, "Invalid link token")                 # (2)

user = oauth_service.find_user_by_email(db, payload["email"])
if not user or user.id != payload["user_id"]:
    raise HTTPException(404, "Account not found")                  # (3)

if not user.hashed_password:
    raise HTTPException(409, "This account has no password set...") # (4)

if not verify_password(body.password, user.hashed_password):        # (5)
    raise HTTPException(401, "Incorrect password")
```

Four branches ((1)-(4)) return before `verify_password` is ever called;
only branches (5) and the success path pay a real bcrypt-cost
verification. This is the same structural shape HIPAA Phase 4 closed in
`authenticate_user` -- some failure branches short-circuit on a cheap
check, one branch (and success) pays for a full hash comparison -- but
not every branch here is the same kind of gap, so this fix targets two
of the four, not all four (see "Scope" below).

## Threat model

**Attacker prerequisites**: a valid, signed `link_token` for some
account, obtained either legitimately (the attacker's own account, mid
link-flow) or illegitimately (a stolen/intercepted token). Unlike
`POST /auth/login`, there is no "submit an arbitrary candidate email and
observe the branch" primitive here: `payload["email"]`/`payload["user_id"]`
are baked into the token at mint time
(`oauth_service.issue_link_confirmation`, itself only reachable after
`find_user_by_email` already resolved a real, existing account during a
real OAuth exchange), not attacker-supplied at request time. This is
exactly why HIPAA Phase 4 rated this "lower severity" rather than "not a
gap" -- token-bound signals are a narrower attack surface than
open-ended email enumeration, not a nonexistent one.

**What each branch actually reveals, and to whom:**

- **(1) Invalid/expired token, (2) wrong token type**: reveal only "is
  this a validly-signed, current `oauth_link` token" -- already
  status-code-visible (400) independent of timing, and an attacker who
  doesn't already hold a validly-signed token learns nothing new from
  timing that the status code didn't already tell them. **Not
  equalized** -- see "Scope."
- **(3) Account not found**: the token's own `user_id`/`email` no longer
  resolve to a real row. Since the token is only mintable against a
  real, existing account, this branch is reachable only via a race (the
  account was deleted, or its email reassigned, between token-mint and
  confirm) -- not attacker-controlled input in the normal case. Still
  worth equalizing for defense-in-depth and internal consistency with
  `authenticate_user`'s identical-shaped branch.
- **(4) No password set**: the account existed and had
  `find_user_by_email`-resolvable state at mint time, but has no local
  password by confirm-time (e.g. it was always OAuth-only, or the
  password was removed in between). Same reasoning as (3).
- **(5) Wrong password / success**: the meaningful signal (does the
  submitted password match) is exactly what a real hash comparison is
  supposed to reveal -- not a gap, unchanged.

**Relationship to the original login oracle**: `POST /auth/login`, the
gap HIPAA Phase 4 closed, let an attacker probe *arbitrary* emails with
*zero* prerequisites to build an account-existence list. This route lets
an attacker who already holds one specific, non-forgeable, short-lived
(5 minute TTL, `create_link_token`) token distinguish two low-frequency
edge cases from a normal wrong-password attempt -- a materially smaller
population of both attackers (must already hold a valid token) and
victims (only accounts hitting one of these races within the token's
5-minute window). This is why it was correctly deferred, and why it
remains "lower severity" even now that it's closed: the fix closes an
inconsistency and a defense-in-depth gap, not an actively exploitable
account-enumeration oracle the way the original login fix was.

## Scope

Two of the four short-circuiting branches ((3) and (4)) are equalized,
mirroring `authenticate_user`'s exact pattern
(`app/services/auth_service.py`, `DUMMY_PASSWORD_HASH` from
`app/core/security.py`, discarded boolean result, same import already
used elsewhere in this codebase -- no new dummy-hash mechanism
introduced).

Branches (1) and (2) are **deliberately left unequalized**:

- They run *before* any user resolution (`decode_token` is a JWT/crypto
  operation, not a database lookup) -- there is no user-existence signal
  at this point to blur, only "is this token validly signed and of the
  expected type," which is already, and unavoidably, distinguished by
  status code (400) regardless of timing.
- `authenticate_user` has no analogous branch (login has no
  signed-token-decode step preceding its user lookup), so there is no
  established precedent shape to extend here, and inventing one for a
  signal that's already status-code-visible would add bcrypt-cost CPU
  work to every malformed/garbage request (a much larger population
  than the population of near-miss token holders (3)/(4) address) for
  no corresponding confidentiality gain.

## Remediation

`app/api/routes_oauth.py::confirm_oauth_link`: branches (3) and (4) now
call `verify_password(body.password, DUMMY_PASSWORD_HASH)` immediately
before their existing `raise HTTPException(...)`, spending the same
bcrypt-bound CPU time branch (5)'s real verification already pays. The
boolean result is discarded -- unchanged from `authenticate_user`'s own
convention, and for the identical reason: it must never influence which
branch is taken or what response is returned, only how much CPU time is
spent getting there.

No other line in this function changed. In particular, unchanged:

- **Link-token validation semantics**: `decode_token`, the `type`
  check, and the `user_id`/`email` cross-check are byte-identical.
- **Authorization behavior**: still requires a validly-signed token
  bound to the requesting account; no new bypass, no relaxed check.
- **Successful account linking**: `link_oauth_to_existing_user`,
  `jit_provision_membership`, and `_issue_tokens_or_challenge` are
  unchanged, unreached by any of this fix's two new lines (both are on
  branches that `raise` before reaching them).
- **MFA behavior**: `_issue_tokens_or_challenge`'s MFA-challenge
  decision point is downstream of branch (5)'s *successful* case only,
  never touched.
- **OAuth/SAML behavior**: `idp_org_id`-carrying tokens (enterprise
  SSO/SAML flows) run through the exact same four branches as the
  3-provider flow; no provider-specific branching exists in this
  function today, so no provider-specific behavior could have been
  introduced.
- **Rate limiting**: this route has no throttle check today (unlike
  `/auth/login`'s `login_throttle_service`) -- unaffected either way,
  nothing added or removed.
- **Audit events**: this route emits none today -- unaffected either
  way.
- **Response status/body semantics**: every `HTTPException` call --
  status code, message string -- is untouched; only two new lines run
  *before* two of the four existing `raise` statements.
- **Organization/team identity handling**: `payload["user_id"]`,
  `payload["email"]`, `idp_org_id`, `organization_sso_config_id`,
  `organization_saml_config_id` are all still read exclusively from the
  server-signed token payload, never from client-supplied body fields;
  this fix touches none of that plumbing.

## Why this equalizes the relevant work

Identical reasoning to
[docs/security-login-timing-side-channel.md](security-login-timing-side-channel.md)'s
own "Why this equalizes the relevant work" section: bcrypt's (and
`bcrypt_sha256`'s) verification cost is a function of the target hash's
own embedded cost parameter, not of the plaintext or of whether the two
match. `DUMMY_PASSWORD_HASH` is the exact same module-level constant
`authenticate_user` already uses -- one real `pwd_context.hash(...)`
call, computed once at import time, same scheme/cost factor every real
registration hash uses. No new hash, no new constant, no new place to
keep in sync.

## Tests

`tests/test_link_confirm_timing_side_channel.py` (10 tests), following
`tests/test_login_timing_side_channel.py`'s own explicit convention:
deterministic call-count/call-argument assertions on a
`verify_password` spy, never wall-clock duration.

- Invalid token, wrong token type: assert **zero** `verify_password`
  calls (branches (1)/(2), deliberately unequalized).
- Link token for a deleted account, link token with a `user_id`
  mismatch: assert exactly one call, against `DUMMY_PASSWORD_HASH`
  (branch (3)).
- Link token for a passwordless account: assert exactly one call,
  against `DUMMY_PASSWORD_HASH` (branch (4)).
- Wrong password: assert exactly one call, against the real hash, not
  `DUMMY_PASSWORD_HASH` (branch (5), unchanged).
- Successful link (3-provider flow) and successful link with MFA
  challenge: assert exactly one real-hash call, unchanged response
  shape, and (for the plain-success case) that a subsequent login via
  the now-linked provider identity still goes straight through --
  confirms `link_oauth_to_existing_user` actually ran.
- Enterprise-SSO-shaped token (`idp_org_id` set) with a wrong password:
  assert the same one-real-hash-call behavior as the 3-provider flow,
  with no membership provisioned (`jit_provision_membership` is
  downstream of a successful verification only).
- No secret leakage: neither the submitted password nor
  `DUMMY_PASSWORD_HASH` appears in the response body or in any audit
  event row.

## HIPAA Phase 4 follow-up mapping

Closes: residual limitation #1 from
[docs/security-login-timing-side-channel.md](security-login-timing-side-channel.md)
("`POST /auth/{provider}/link/confirm` has its own, separate,
lower-severity `verify_password` call site"). Status: **Implemented**
for the two branches ((3) account-not-found, (4) no-password-set) that
are structurally analogous to `authenticate_user`'s own equalized
branches; branches (1)/(2) (token decode/type failure) remain
deliberately unequalized, for the reasons given in "Scope" above -- not
an oversight. This is a security control implementation, **not a HIPAA
certification** of this service or the platform built on it.
