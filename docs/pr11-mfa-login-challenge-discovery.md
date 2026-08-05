# PR11.5.3 — Enterprise MFA Login Challenge: Discovery

Discovery performed before coding, per this PR's own instructions.
Builds directly on PR11.5.1 (`MFADevice`/`User.mfa_*` schema) and
PR11.5.2 (`mfa_service.py`'s TOTP primitives, enrollment). This is the
PR that actually makes `user.mfa_enabled=True` do something —
verified directly against current source; every claim below cites the
file it was read from.

## 1. Every login entry point

Confirmed by re-reading each route file in full this session (not
assumed from PR11.5's earlier summary). Every one of these seven call
sites currently calls `auth_service.generate_tokens` directly:

| # | File | Call site | `auth_method` |
|---|---|---|---|
| 1 | `app/api/routes_auth.py:159` | `login()` | `"password"` |
| 2 | `app/api/routes_oauth.py:70` | `_complete_oauth_flow`, linked user | `"oauth"` |
| 3 | `app/api/routes_oauth.py:81` | `_complete_oauth_flow`, new user | `"oauth"` |
| 4 | `app/api/routes_oauth.py:163` | `confirm_oauth_link` | `"oauth"` or `"sso"` |
| 5 | `app/api/routes_sso.py:111` | `_complete_sso_flow`, linked user | `"sso"` |
| 6 | `app/api/routes_sso.py:128` | `_complete_sso_flow`, new user | `"sso"` |
| 7 | `app/api/routes_license.py:42` | `validate_license` | `"license"` |

All seven are updated by this PR to call a new shared function instead
(§2) — none is skipped, including `confirm_oauth_link`, which PR11.5's
earlier discovery pass hadn't singled out by name but which is a real,
distinct `generate_tokens` call site issuing real tokens for a human,
so it is in scope exactly like the other six.

**Not a login entry point, deliberately unchanged:**
- `POST /auth/refresh` (`routes_auth.py:170` →
  `auth_service.rotate_refresh_token`) — calls `build_user_claims`
  directly, never `generate_tokens`. See §3 for why this must stay
  true.
- `POST /oauth/token` (`routes_oauth_token.py`, client_credentials
  grant) — calls `create_service_access_token` directly, never
  `generate_tokens`/`build_user_claims`. See §4.

## 2. Where the MFA check is inserted

**One new shared function**, `auth_service.generate_tokens_or_mfa_challenge`,
called from all seven sites in §1 instead of `generate_tokens`
directly. This satisfies this PR's own "All must use the same MFA
decision logic. Do not duplicate MFA checks" requirement literally —
the `if user.mfa_enabled` branch exists in exactly one place, not
copy-pasted into four route files.

```python
def generate_tokens_or_mfa_challenge(db, user, auth_method="password", idp_org_id=None) -> dict:
    if not user.mfa_enabled:
        access, refresh = generate_tokens(db, user, auth_method=auth_method, idp_org_id=idp_org_id)
        return {"mfa_required": False, "access_token": access, "refresh_token": refresh}

    challenge_token = create_mfa_challenge_token(user.id, auth_method=auth_method, idp_org_id=idp_org_id)
    # ... emit MFA_CHALLENGE_REQUIRED, return {"mfa_required": True, "challenge_token": ..., "methods": ["totp"]}
```

Each of the seven call sites is updated to call this instead, check
`result["mfa_required"]`, and either return the challenge shape
(new, additive branch) or continue exactly as before with
`result["access_token"]`/`result["refresh_token"]` in place of what
`generate_tokens` used to return directly — every other line of
existing route logic (session-cookie setting, Prometheus counters,
audit calls already inside `authenticate_user`, response-body
construction for the non-MFA case) is untouched.

**Deliberately NOT inserted inside `generate_tokens` itself.**
`generate_tokens` keeps its exact existing contract (`(access, refresh)`
tuple, writes `last_login_at`/`authentication_method`, creates the
`RefreshToken` row) and is still the function that actually finishes a
login — both the non-MFA branch above and `mfa_service.
verify_mfa_challenge` (§5, called from the new `/users/me/mfa/challenge`
endpoint on successful code verification) call it, unchanged. Splitting
the *decision* (a new, small function) from the *execution*
(the existing, unchanged `generate_tokens`) means:
- `last_login_at`/`authentication_method` are written exactly once,
  at the moment a login *actually completes* — not when a challenge is
  merely issued. A user who requests a challenge and abandons it (never
  enters a code) leaves no trace in `last_login_at`, correctly — they
  never finished logging in.
- `rotate_refresh_token` (§3) and every other existing caller of
  `generate_tokens`'s underlying claims machinery (`build_user_claims`)
  is completely unaffected — this PR touches zero lines inside
  `generate_tokens` itself.

## 3. Why refresh tokens bypass the MFA challenge

`auth_service.rotate_refresh_token` (`app/services/auth_service.py:194-263`)
never calls `generate_tokens` or the new `generate_tokens_or_mfa_challenge`
— it calls `build_user_claims` directly, exactly as it already did
before this PR, and this PR does not change that.

This is correct, not an oversight, for the same reason PR11.1's own
`last_login_at` design already established: **a token refresh
continues an existing, already-fully-authenticated session — it is
not a new login.** The refresh token being presented was itself only
ever issued *after* a completed login (either a non-MFA
`generate_tokens` call, or an MFA-gated one that only happens inside
`mfa_service.verify_mfa_challenge` post-verification, §5) — by the
time a refresh token exists at all, MFA (if required) has already been
satisfied once for that session. Re-challenging on every 15-minute
access-token rotation would be a materially worse user experience for
zero additional security: the refresh token itself is the proof of an
already-verified session, protected by its own existing
reuse-detection/family-revocation machinery (`_revoke_family`), not by
re-running MFA.

**`mfa_verified: true`** (§6) reflects this directly: `build_user_claims`
adds it unconditionally, so a *rotated* access token still correctly
asserts "this session cleared MFA" — because it did, at the original
login, and rotation doesn't reset that fact.

## 4. Why service accounts bypass MFA

`POST /oauth/token` (`app/api/routes_oauth_token.py`, RFC 6749 §4.4
client_credentials grant) calls `create_service_access_token`
directly (`app/core/jwt.py:119-135`) — a structurally distinct token
shape that deliberately never carries `sub`/`email` at all, exactly as
documented on that function already: *"a service token must never
carry `sub`/`email` at all (there is no user)."*

MFA is a **human** second factor — TOTP proves possession of a device
a *person* holds. A client_credentials exchange authenticates a
*service identity* (a `client_id`/`client_secret` pair belonging to an
application, not a person), which has no analogous concept of "a
second factor" to begin with. `User.mfa_enabled` is a column on the
`User` table; a service-account token was never built from a `User`
row in the first place (`oauth_client_service.verify_client_credentials`
resolves an `OAuthClient` row, not a `User`), so there is no
`mfa_enabled` value to even consult for this flow. This PR adds zero
code to `routes_oauth_token.py`/`create_service_access_token` — the
bypass is structural (these code paths were never wired to
`generate_tokens`/`build_user_claims` to begin with, confirmed by
PR11.5's own earlier discovery pass and re-confirmed here by grep),
not a new exception carved out by this PR.

`get_current_user`'s existing `auth_method == "client_credentials"`
rejection (`app/rbac.py:36-37`) already keeps service tokens from ever
satisfying a user-identity check anywhere in this service — this PR's
new `type == "mfa_challenge"` rejection (§7) sits right next to it,
following the exact same "one shared dependency, one explicit check"
shape for a different, unrelated reason (a *different* non-user token
type that must also never satisfy `get_current_user`).

**API keys** (`ApiKey` model, `apikey_service.py`) are likewise out of
scope for the same underlying reason: `apikey_service.verify_api_key`
(§ referenced in PR11.5's discovery, not yet wired into any live
authorization path per that function's own docstring — "not yet wired
into a route or consumed by any other service") never calls
`generate_tokens` either, and an API key authenticates a
machine-presented bearer secret, not a login session, so it has no
token-issuance moment for an MFA gate to intercept in the first place.

## 5. MFA challenge token

New: `app/core/jwt.py::create_mfa_challenge_token(user_id, auth_method, idp_org_id=None)`.
Same "no server-side session, self-contained, short-lived, `type`
discriminator" shape as the three existing short-lived tokens already
in this file (`create_oauth_state_token`, `create_sso_state_token`,
`create_link_token`) — not a new pattern, the fourth instance of an
established one.

```python
{
    "type": "mfa_challenge",
    "user_id": user.id,
    "mfa_required": True,
    "auth_method": auth_method,   # carried through so verification can
    "idp_org_id": idp_org_id,     # finish the login identically to what
                                   # primary auth would have produced directly
    "exp": now + 5 minutes,
    "jti": uuid4(),
}
```

**Deliberately no `sub` claim** (unlike a real access/refresh token,
which uses `sub`) — `user_id` instead. This is not cosmetic: it means
any code that reads `payload["sub"]` (e.g. `assert_token_usable`'s
`User.status` check, or any route's `int(user["sub"])`) simply doesn't
find a matching identity shape in this token at all, an extra layer of
structural distinction on top of the explicit `type` check in §7.

**No password, secret, or OTP code in any of these claims** — this
PR's own explicit requirement. The token proves "primary authentication
for this user_id already succeeded," nothing about *how* (no password
hash, no OAuth token, no OIDC claims) and nothing about the second
factor being verified (no OTP code — that travels in the *request
body* to `/users/me/mfa/challenge`, never in a token).

**Signed via the same `_sign()` choke point** every other token in
this file uses (`app/core/jwt.py:9-18`) — RS256 or HS256 depending on
`settings.JWT_ALGORITHM`, identical signature/expiry verification
story as every other token type, decoded by the same `decode_token`
(dispatches by the token's own `alg` header).

### Why this satisfies each explicit security requirement

| Requirement | How it's satisfied |
|---|---|
| Separate from access token | Distinct `type` claim (`"mfa_challenge"` vs `"access"`), distinct (minimal) claim shape, distinct 5-minute TTL vs 15-minute access-token TTL |
| Cannot access APIs | `app/rbac.py::get_current_user` explicitly rejects `type == "mfa_challenge"` (§7) — the one shared dependency every user-identity route depends on, so no route needs its own check |
| Cannot refresh session | Never written to the `refresh_tokens` table (no `RefreshToken` row is ever created for it) — `rotate_refresh_token`'s `db.query(RefreshToken).filter(RefreshToken.token == presented_token)` lookup simply finds nothing, returning `None` → the existing `401 Invalid refresh token` response, with zero new code in `rotate_refresh_token` |
| Short expiration | 5 minutes (`exp`), matching this PR's own example |
| Cannot be reused | On successful verification, its `jti` is inserted into the existing `revoked_tokens` table (`RevokedToken`, already checked by `assert_token_usable` for any token type) — a second presentation of the same token is rejected by `mfa_service.verify_mfa_challenge`'s own explicit re-check of that table before doing anything else (§8) |
| No passwords/secrets/OTP codes in claims | See above — the claim shape is fixed and minimal, never touched by any code path that has access to those values |

## 6. JWT claim changes: `mfa_verified`

`auth_service.build_user_claims` (`app/services/auth_service.py:47-106`)
gains one new key in its returned dict:

```python
"mfa_verified": True,
```

**Unconditionally `True`, not computed per-user.** This is correct by
construction, not a simplification that loses information:
`build_user_claims` is only ever called from two places —
`generate_tokens` (called either directly for a non-MFA user, or from
inside `mfa_service.verify_mfa_challenge` only *after* a correct TOTP
code has been verified) and `rotate_refresh_token` (continuing a
session that already cleared this bar once, per §3). There is no
calling path left by which `build_user_claims` runs for a user who
still owes a second factor — by the time this function is ever
invoked, either MFA doesn't apply to this user, or it has already been
satisfied. A dynamic `user.mfa_enabled and <verified-this-session>`
computation would require threading a "was this specific token
challenge-verified" flag all the way through `rotate_refresh_token`
too (which has no such context, and shouldn't need one, per §3) for a
value that is provably always `True` at every point the claim is
actually built.

**Backward compatible, per this PR's own explicit requirement**: a
purely additive dict key. Every existing consumer of a token's claims
(`get_current_user`, `require_permission`, `/auth/validate`, the
`omnibioai-iam-client` library, `omnibioai-api-gateway`) reads specific
named keys it already expects and ignores unknown ones — none of them
fail, error, or change behavior upon seeing a new key they don't look
for, the same "additive superset" property Phase 1 PR3's `org_id`/
`org_role`/`auth_method`/`token_version` claims and Phase 2 PR4's
`idp_org_id` claim already established for this exact function. A
token minted before this PR simply has no `mfa_verified` key at all
(not `false` — absent), exactly like every other claim this codebase
has ever added here; nothing in this PR treats its absence as an
error.

## 7. `app/rbac.py::get_current_user` change

One new rejection, immediately after the existing
`auth_method == "client_credentials"` check it already has
(`app/rbac.py:36-37`), same shape:

```python
if payload.get("type") == "mfa_challenge":
    raise HTTPException(401, "Invalid token")
```

This is the single place that makes "an MFA challenge token can never
satisfy a user-identity check" true everywhere in this service, the
same reasoning already documented for the existing
client_credentials rejection right above it ("Rejecting it here, once,
in the shared dependency every user-identity route already depends on
... rather than relying on every individual route to remember to check
... itself"). Not a change to the permission model (`require_permission`/
`require_role`/org-scoped checks are all built on top of this function
and are completely untouched) — a challenge token was never going to
satisfy a *permission* check anyway (it carries no `permissions`/`roles`
claims at all, §5), this closes the narrower gap where a bare
`get_current_user`-only route (no permission required at all, e.g.
`GET /auth/config`, `GET /users/me/mfa/devices`) would otherwise have
silently accepted it as if it were a real, logged-in session.

## 8. MFA verification endpoint

New: `POST /users/me/mfa/challenge` (`app/api/routes_mfa.py`, same
router/prefix as PR11.5.2's enrollment endpoints, though this one is
deliberately **not** gated by `get_current_user` — see below). Backed
by a new `mfa_service.verify_mfa_challenge(db, challenge_token, code)`.

```
1. decode_token(challenge_token)             -- malformed/expired -> MFAChallengeError
2. payload["type"] == "mfa_challenge"        -- wrong token type   -> MFAChallengeError
3. jti not already in revoked_tokens         -- reused             -> MFAChallengeError
4. User row for payload["user_id"] exists    -- deleted/unknown    -> MFAChallengeError
   and status == "active"
5. user.mfa_enabled is True                  -- disabled since     -> MFAChallengeError
                                                 challenge issued
6. code matches any of the user's verified   -- wrong code         -> ValueError
   MFADevice rows (constant-time compare,
   PR11.5.2's existing verify_totp_code)
7. on success: mark challenge jti used, set
   device.last_used_at / user.mfa_last_verified_at,
   emit MFA_VERIFIED, call the existing,
   unchanged generate_tokens() to finish the
   login exactly as primary auth would have
```

**`MFAChallengeError` (a `ValueError` subclass) vs plain `ValueError`**:
deliberately two different exception types, mapped to two different
HTTP statuses by the route (`401` vs `400`) — steps 1-5 all collapse
into the *same generic message* ("Invalid or expired challenge
token") regardless of which specific one failed, so a probing caller
learns nothing about whether a given token/user_id is malformed vs.
expired vs. already-used vs. belongs to a since-deactivated account —
only step 6 (a structurally valid, unexpired, unused challenge, but
the wrong 6-digit code) gets the more specific "Invalid verification
code" message and a `400`, mirroring PR11.5.2's own
`verify_totp_enrollment` distinction between "this resource/token
doesn't check out" (404-shaped in that PR, 401-shaped here since there
is no authenticated caller yet to withhold existence from) and "this
specific code is wrong."

**Not gated by `get_current_user`, deliberately** — unlike every other
route in `routes_mfa.py`. The caller has no bearer access token to
present at all at this point (that's the entire premise: they're
mid-login, one step before ever having one) — the `challenge_token` in
the request *body* is itself the credential, already scoped to exactly
one `user_id` by construction (§5), so there is no cross-user
ambiguity for `get_current_user` to resolve in the first place. Path
is still nested under `/users/me/mfa/...` per this PR's own literal
specification, even though "me" here resolves from the challenge
token's embedded `user_id`, not a bearer token's `sub` claim — a
one-off, explicitly commented exception to this router's otherwise
uniform "every route depends on `get_current_user`" shape.

**"Cross-user challenge rejected"**: there is no cross-user check to
write, by construction — `code` is only ever verified against
*the devices belonging to the `user_id` embedded in the token itself*
(step 6 above), never against any user_id from a request parameter or
header. A caller cannot even *express* "verify this code as a
different user" — the endpoint has no such parameter.

**Session cookie**: on success, sets the `omnibioai_session` cookie
via the existing `routes_auth._set_session_cookie` helper — imported
directly rather than reimplemented, so the cookie's domain/
secure/httponly/samesite/max-age stay in exact lockstep with
`/auth/login`'s own (any future change to cookie policy only needs to
happen in one place).

## 9. Login response shape (backward compatibility)

**Non-MFA users: byte-identical to today**, per this PR's own
explicit "existing response remains unchanged" requirement. Every
route's non-MFA branch is a straight `result["access_token"]`/
`result["refresh_token"]` substitution for what used to come directly
from `generate_tokens` — no new key is added to that response shape
anywhere, not even `mfa_required: false`. Existing API clients that
validate a response's exact shape see zero difference.

**MFA-enabled users** get a new, distinct shape instead of tokens:

```json
{"mfa_required": true, "challenge_token": "...", "methods": ["totp"]}
```

`methods` is always a real JSON list (`["totp"]`, matching this PR's
own literal example) in every route, including the two dict-returning
routes (`routes_oauth.py`'s `_complete_oauth_flow`,
`routes_sso.py`'s `_complete_sso_flow`) whose result also feeds a
`urlencode()` call on their GET-redirect variants
(`oauth_callback_redirect`/`sso_callback_redirect`). **Known, accepted
cosmetic limitation**: `urlencode()` without `doseq=True` renders a
list value as its Python `repr` in the query string (e.g.
`methods=%5B%27totp%27%5D`) rather than a clean comma-separated value.
Not fixed in this PR — the Admin Console/frontend consumption of this
new shape is explicitly out of scope here (per this PR's own DO NOT
list), no existing test or consumer depends on the redirect variant's
query-string encoding of this specific new field, and keeping `methods`
a uniform, real list everywhere (rather than a string in two routes and
a list in the other five) is simpler to reason about and test than a
bespoke encoding per route. Left as a documented note for whichever PR
builds the frontend consumer.

**`routes_license.py`'s `LicenseValidateResponse`** is the one
`response_model`-constrained route among the seven — Pydantic would
reject any dict key not declared on the model, so this PR adds three
new **optional** fields (`mfa_required: bool = False`,
`challenge_token: str | None = None`, `methods: list[str] | None = None`),
additive to the existing schema exactly like every prior field this
model has ever gained (`tier`/`expiry`/`days_remaining`/`org_id`, all
already optional with a documented default). The non-MFA response
shape is unchanged (those three fields simply stay at their defaults,
indistinguishable from before this PR to any consumer that doesn't
look for them).

## 10. Audit events

Three new `AuditEventType` constants
(`app/services/audit_service.py:32-56`), following the same naming
convention every prior PR11.x addition used:

```python
MFA_CHALLENGE_REQUIRED = "mfa_challenge_required"
MFA_VERIFIED = "mfa_verified"
MFA_VERIFICATION_FAILED = "mfa_verification_failed"
```

| Event | Emitted from | When |
|---|---|---|
| `MFA_CHALLENGE_REQUIRED` | `auth_service.generate_tokens_or_mfa_challenge` | Every time a challenge token is issued (one call site, shared by all seven login flows — §2) |
| `MFA_VERIFIED` | `mfa_service.verify_mfa_challenge` | On successful code verification, right before the real tokens are issued |
| `MFA_VERIFICATION_FAILED` | `mfa_service.verify_mfa_challenge` | Only when the challenge token itself was structurally valid, unexpired, unused, and MFA-still-enabled, but the *code* was wrong — a garbled/expired/reused/already-invalid token produces no audit row at all, since there is no reliably identifiable subject to attribute it to at that point (mirrors `auth_service._log_login_failure`'s own precedent of only auditing when an actor is actually resolvable) |

**Metadata allowlist**, exactly the three fields this PR names as
permitted (`user_id`/`organization_id`/`authentication_method`) —
`user_id` maps to the existing `actor_user_id`/`target_user_id`
*columns* (both set to the same user, self-referential, same as every
PR11.5.2 event), `organization_id` to the existing column (resolved
via `org_service.resolve_primary_membership`, the same helper
`build_user_claims`/`routes_license.py` already call — no new
resolution logic), and `metadata={"authentication_method": auth_method}`
is the only key ever placed in the JSON `metadata` column. **Never**:
the OTP code, the challenge token (or its `jti`), the TOTP secret in
any form. None of these three call sites reference `code`,
`challenge_token`, or `encrypted_secret` in any `before_state`/
`after_state`/`metadata` argument — verified by construction (the
values simply aren't in scope at the point each `log_event` call is
written) and re-verified by this PR's own tests (§11).

## 11. Security requirements — how each is met

| Requirement | Implementation |
|---|---|
| Challenge token cannot be reused | `RevokedToken` insert on success, checked before any other step on every verification attempt (§5, §8) |
| Challenge token expires | 5-minute `exp` claim, enforced by `decode_token`'s existing signature+expiry verification (no new expiry logic written) |
| Invalid OTP rejected | `verify_totp_code` (PR11.5.2, unchanged) against every verified device; no match -> `ValueError` -> `400`, `MFA_VERIFICATION_FAILED` audit event |
| MFA-disabled users cannot use the challenge endpoint | Step 5 in §8 re-checks `user.mfa_enabled` at verification time, not just at issuance time — a user who disables MFA between requesting and completing a challenge (e.g. removes their last device via `DELETE /users/me/mfa/devices/{id}`, PR11.5.2) cannot complete a stale challenge |
| Cross-user challenge rejected | Structural — see §8, no cross-user parameter exists to misuse |
| No sensitive data in logs | No `logger.*` call anywhere in this PR's new code references a code, token, or secret — the only logging in the vicinity is `audit_service.log_event`'s own `except`-block `logger.exception`, which logs only `event_type` (a fixed string) |

## 12. Backward compatibility strategy, summarized

1. **`generate_tokens` itself is untouched** — same signature, same
   return shape, same side effects. Every existing direct caller
   outside the seven login routes (there are none today, confirmed by
   grep) would be unaffected regardless.
2. **Non-MFA users' response shape is byte-identical** — the
   overwhelming majority of accounts today (`mfa_enabled` defaults to
   `False` for every row, PR11.5.1), so this PR changes nothing
   observable for them.
3. **`mfa_verified: true` is purely additive** to the JWT claim set —
   no existing consumer breaks on an unrecognized key (§6).
4. **`LicenseValidateResponse`'s three new fields are optional with
   defaults** — no existing consumer of that schema breaks (§9).
5. **Refresh and service-account flows are provably untouched** by
   this PR's diff — zero lines changed in `rotate_refresh_token`,
   `routes_oauth_token.py`, or `create_service_access_token` (§3, §4).
6. **No rate limiting added** — explicitly out of scope per this PR's
   own DO NOT list ("separate security PR"). This codebase has zero
   rate limiting anywhere today (`docs/pr11-security-foundation-discovery.md`,
   Critical risk R2); `/users/me/mfa/challenge` inherits that same
   pre-existing gap, same as `/totp/verify` already does since
   PR11.5.2. Flagged here, not silently left undocumented, consistent
   with how PR11.5.2's own discovery doc handled the identical
   caveat for its endpoint.

## 13. Verification method

- Full re-read of `app/services/auth_service.py`,
  `app/api/routes_auth.py`, `app/api/routes_oauth.py`,
  `app/api/routes_sso.py`, `app/api/routes_license.py`,
  `app/core/jwt.py`, `app/rbac.py`, `app/core/token_revocation.py`,
  `app/schemas/license.py` in full this session — every call site and
  claim shape cited above was read directly, not carried over from
  memory of PR11.5's earlier, higher-level discovery pass.
- Grepped for any other caller of `generate_tokens`/
  `build_user_claims`/`create_service_access_token` outside the files
  already covered — none found.
- Confirmed `apikey_service.verify_api_key` (`app/services/apikey_service.py:103-115`)
  remains, per its own docstring, "not yet wired into a route or
  consumed by any other service" — still true, unrelated to this PR's
  changes, cited in §4 only to explain why API keys need no MFA
  consideration either.
