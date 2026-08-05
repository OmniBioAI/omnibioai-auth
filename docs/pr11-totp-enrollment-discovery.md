# PR11.5.2 — Enterprise TOTP MFA Enrollment: Discovery

Discovery performed before coding, per this PR's own instructions.
Builds directly on PR11.5.1's schema
(`docs/pr11-mfa-database-foundation-discovery.md`) — no new columns
or tables are added here, only the first read/write code path that
actually uses them. Verified directly against current source; every
convention below cites the existing file it was copied from.

## 1. Where enrollment logic belongs

**Service layer**: `app/services/mfa_service.py`, a new module — not
routes, per this PR's own instruction and this codebase's own
established convention (`app/services/apikey_service.py`,
`app/services/oauth_client_service.py`, `app/services/org_sso_service.py`
all keep every state transition, encryption call, and audit call
inside the service; route handlers only decode the path/body, call the
service, and translate exceptions to HTTP status codes).

**Routes**: `app/api/routes_mfa.py`, mounted at `/users/me/mfa` — a
new top-level prefix scoped to the caller's own identity, not an org
(`{org_id}` path param). This matches the existing self-service
precedent `app/api/routes_config.py:39-44`'s `GET /auth/config`
already sets: `user=Depends(get_current_user)  # any authenticated
user, no permission required` — MFA enrollment is exactly this shape
(a user acting on their own account, not needing any RBAC permission
grant), so the same bare `get_current_user` dependency is reused
verbatim, with **zero new permission** added (confirmed no MFA
permission exists anywhere — see
`docs/pr11-security-foundation-discovery.md`, omnibioai-control-center).
Grepped `app/api/*.py` for any existing `/users` prefix
(`routes_roles.py`, `routes_platform_roles.py` — both unrelated,
`/orgs/.../roles` and `/platform/roles` respectively) — no collision
with `/users/me/mfa/*`.

`test_route_authorization_coverage.py`'s automated check only scans
routes under `/orgs/{org_id}/...` (`_org_scoped_routes()`,
`tests/test_route_authorization_coverage.py:73-76`) — `/users/me/mfa/*`
is outside that scan's scope entirely, by design (it is not an
org-membership-gated resource, it is a self-service one, the same
category `/auth/config` already falls into unchecked by that test).

## 2. Secret generation approach

**No new dependency.** `requirements.txt` has no `pyotp`/TOTP library
today, and every existing dependency entry carries an inline comment
justifying why it's needed (e.g. `cryptography  # explicit dep for
Fernet ... was only an implicit python-jose extra before`) — this
codebase visibly minimizes its dependency footprint. RFC 6238 TOTP is
~30 lines of stdlib `hmac`/`hashlib`/`struct`/`base64`/`time` — small
enough, and security-sensitive enough, that vendoring it directly
(rather than pulling in a third-party package whose own dependency
tree and update cadence this PR would then inherit) is the better
tradeoff here.

- **Secret**: `secrets.token_bytes(20)` (160 bits — the width Google
  Authenticator and most TOTP implementations use, well above RFC
  4226's 128-bit minimum), base32-encoded (`base64.b32encode`) into
  the standard human/QR-friendly alphabet every TOTP app expects.
- **Code derivation**: standard RFC 6238 (HOTP with a time-derived
  counter, RFC 4226 §5.3): `HMAC-SHA1(secret, counter)` →
  dynamic-truncate → 6-digit code, `period=30s`. SHA1 (not SHA256) is
  the deliberate choice here — it's what every mainstream
  authenticator app (Google Authenticator, Authy, 1Password, Microsoft
  Authenticator) assumes when no `algorithm` parameter is scanned or
  is scanned as `SHA1`; deviating would silently break compatibility
  with the apps users actually have installed.
- **Verification window**: `±1` step (accepts the current, previous,
  and next 30-second code, i.e. an effective ~90s tolerance) — the
  standard mitigation for clock drift between the server and the
  user's device, without widening the window enough to meaningfully
  help a brute-force attacker (still only 3 valid codes at any instant
  out of 1,000,000 possible).
- **Comparison**: `hmac.compare_digest(candidate, code)`, not `==` —
  this PR's own explicit "constant-time verification comparison where
  applicable" requirement. `hmac.compare_digest` is the same stdlib
  primitive this codebase already reaches for in `hmac`-adjacent
  contexts (`app/core/jwt.py`'s signing itself uses `python-jose`,
  which internally does the same for HS256 verification) — using it
  here for the code comparison specifically prevents a timing
  side-channel from leaking how many of the 6 digits an attacker has
  guessed correctly so far.

## 3. Encryption flow

Reuses `app/core/crypto.py` exactly as-is — **zero changes to that
module**. Same `encrypt(plaintext: str) -> str` / `decrypt(ciphertext:
str) -> str` pair, same `CONFIG_ENCRYPTION_KEY`-derived Fernet
instance already backing `OrganizationSSOConfig.client_secret_encrypted`
and `OrganizationConfig.llm_api_key_encrypted` — no new environment
variable, no new key material, no new failure mode: `crypto.encrypt()`
already raises a clear `RuntimeError` if the key isn't configured
(rather than silently storing plaintext), and `routes_mfa.py` catches
that exactly the way `routes_config.py:64-69` already does (`except
RuntimeError as e: raise HTTPException(500, str(e))`).

**The plaintext secret's lifetime, precisely:**
1. Generated in `mfa_service.start_totp_enrollment`.
2. Immediately encrypted (`crypto.encrypt(secret)`) before the
   `MFADevice` row is constructed — the plaintext is never assigned to
   any column.
3. Used once more, in the same function, to build the `otpauth://` URI
   returned to the caller.
4. Falls out of scope when the function returns. Nothing references it
   again. It is never logged (no `logger.*` call in this module
   touches it), never included in an audit event's `metadata`, and the
   HTTP response itself is the only place it — or rather, the URI
   *derived* from it — ever leaves the process, exactly once, at
   enrollment-start time.
5. On verification, the *encrypted* column is read back and decrypted
   inside `mfa_service.verify_totp_enrollment` only long enough to
   compute the expected codes and compare; the decrypted value is a
   local variable that goes out of scope at function return, same
   lifetime discipline as step 2-4.

This mirrors `config_service.py`'s own handling of
`llm_api_key`/`cloud_credentials` (accepted, encrypted immediately,
never echoed back — `GlobalConfigOut` in `app/schemas/config.py` has
`has_llm_api_key: bool` instead of the value itself) — this PR's
`MFADeviceOut` schema follows the identical shape: no
`encrypted_secret` field, no plaintext-secret field, ever.

## 4. API design

Four endpoints, all under `/users/me/mfa`, all gated by bare
`get_current_user` (own-account only, no permission):

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/users/me/mfa/totp/enroll` | Generate a secret, create a pending `MFADevice`, return `{device_id, otpauth_uri}` |
| `POST` | `/users/me/mfa/totp/verify` | Verify a code against a pending device; on success, mark it verified and flip the user's MFA status fields |
| `GET` | `/users/me/mfa/devices` | List the caller's own devices, safe metadata only |
| `DELETE` | `/users/me/mfa/devices/{device_id}` | Soft-remove one of the caller's own devices |

**`DELETE` is a soft-remove (`disabled_at = now()`), not a SQL row
delete** — this is not a new pattern invented for this PR, it is the
exact shape `DELETE /orgs/{org_id}/api-keys/{key_id}` already uses
today: the route is literally named `revoke_api_key`
(`app/api/routes_apikeys.py:60-70`) and calls
`apikey_service.revoke_api_key`, which sets `status="revoked"` /
`revoked_at` rather than deleting the row
(`app/services/apikey_service.py:82-100`). `MFADevice.disabled_at`
plays the identical role. Reasons this matters for MFA specifically:
a hard-deleted device row would break `AuditEvent.resource_id`'s
historical reference (the ledger must survive the resource it
describes — `AuditEvent`'s own docstring,
`app/db/models.py:395-399`), and a soft-removed row still lets a
future admin-reset feature (PR11.5.4) distinguish "never had MFA" from
"had MFA, removed it."

**Every response schema (`app/schemas/mfa.py`) omits
`encrypted_secret` entirely** — `MFADeviceOut` exposes only `id`,
`device_type`, `label`, `created_at`, `verified_at`, `last_used_at`,
matching this PR's own explicit requirement and the `GlobalConfigOut`
precedent from §3.

**Enrollment replacement, not accumulation**: starting a new TOTP
enrollment (`POST .../totp/enroll`) first soft-disables any of the
caller's *existing pending* (unverified, not yet disabled) TOTP
devices, so re-scanning a fresh QR code after an abandoned attempt
replaces it rather than leaving an ever-growing pile of dead pending
rows — this is this PR's answer to "pending devices expire or can be
replaced safely" (§6): replacement, not a TTL/expiry job (out of scope
for this PR; a background expiry sweep would need its own
infrastructure this codebase doesn't have anywhere yet). An abandoned
pending device grants no access regardless — `mfa_enabled` only flips
on a *verified* device, never a pending one — so a dead pending row
is inert, not a security hole, while it exists.

**Multiple verified devices are allowed**, deliberately not blocked:
PR11.5.1's own discovery doc named "support multiple devices in
future" as an explicit schema requirement (`user_id` is a plain
indexed FK, not a unique one) — a user who already has one verified
TOTP device (e.g. their phone) enrolling a second (e.g. a backup
device) is exactly that future being exercised, not a bug to prevent.
"Prevent duplicate active TOTP enrollment" (this PR's own security
requirement) is satisfied at the *pending* stage (only one live
in-flight enrollment attempt at a time, per the paragraph above), not
by capping verified devices at one.

## 5. Audit integration point

All five new event types requested by this PR are added to the
existing `AuditEventType` class (`app/services/audit_service.py:32-56`)
as new string constants, following its own established
`SCREAMING_SNAKE_CASE` / `"snake_case"` naming convention exactly
(matching PR11.5.1's discovery doc §6, which already named these five
plus a sixth reserved for PR11.5.4):

```python
MFA_DEVICE_ENROLLMENT_STARTED = "mfa_device_enrollment_started"
MFA_DEVICE_ADDED = "mfa_device_added"
MFA_DEVICE_REMOVED = "mfa_device_removed"
MFA_ENABLED = "mfa_enabled"
MFA_DISABLED = "mfa_disabled"
```

(`MFA_RESET_BY_ADMIN`/`MFA_RECOVERY_USED`, also named in PR11.5.1's
§6, are **not** added here — this PR implements neither admin reset
nor recovery codes, so adding their constants now would be dead code
with nothing to emit them; they're deferred to the PRs that actually
need them, PR11.5.4.)

Every call site follows `audit_service.log_event`'s existing contract
(never raises, called from inside the service function at the exact
point the mutation happens, never from the route handler) — same as
every PR11.4b/PR11.4c call site:

| Event | Emitted from | When |
|---|---|---|
| `MFA_DEVICE_ENROLLMENT_STARTED` | `start_totp_enrollment` | Every call, including a replacement of an abandoned pending device |
| `MFA_DEVICE_ADDED` | `verify_totp_enrollment` | On successful code verification (device transitions pending → verified) |
| `MFA_ENABLED` | `verify_totp_enrollment` | Only when `user.mfa_enabled` actually flips `False → True` — **not** re-logged if the user already had MFA enabled and is verifying an additional device, mirroring `org_sso_service.set_enforced`'s existing "don't log a no-op" convention |
| `MFA_DEVICE_REMOVED` | `remove_device` | Every successful device removal |
| `MFA_DISABLED` | `remove_device` | Only when removing this device drops the caller's verified-device count to zero **and** `user.mfa_enabled` was actually `True` beforehand — same no-op-avoidance convention |

**Never in `metadata`/`before_state`/`after_state`**: the TOTP secret
(plaintext or encrypted), the OTP code being verified, or the
`otpauth://` URI. Every call site's `metadata`/`before_state`/
`after_state` dict is hand-built from a small, explicit allowlist
(`device_type`, `verified` boolean, `mfa_enabled` boolean) — never a
blind `vars(device)`/`device.__dict__` dump, which is exactly the kind
of mistake that would leak `encrypted_secret` by accident. This is the
same defensive-construction discipline already documented for every
PR11.4b/c audit call site (`apikey_service.py`'s own comment: "never
the plaintext key or its hash in audit metadata").

## 6. Security considerations

- **Own-resource-only enforcement**: every service function takes
  `user_id` as an explicit parameter (never trusts a client-supplied
  user id) and every query filters `MFADevice.user_id == user_id` —
  `verify_totp_enrollment`/`remove_device` both raise `LookupError`
  (translated to `404`, not `403`) if the device doesn't belong to the
  caller, mirroring `get_org_membership`'s own "404, not 403 — do not
  confirm... whether [it] exists at all" reasoning
  (`app/rbac.py:85-88`) applied here to *device* existence instead of
  *org* existence.
- **Constant-time comparison** (§2) prevents a timing side-channel on
  the 6-digit code compare.
- **No secrets in logs**: `mfa_service.py` contains zero `logger.*`
  calls referencing the secret or code — the only logging in the
  module's neighborhood is `audit_service.log_event`'s own
  `except`-block `logger.exception`, which only ever logs
  `event_type` (a fixed string), never the payload.
- **No secrets in audit metadata**: see §5's explicit allowlist
  discipline.
- **Pending-device replacement, not silent accumulation** (§4) closes
  off an unbounded-row-growth nuisance, though not itself a security
  hole (§4).
- **Rate limiting / brute-force protection on `/totp/verify` is a
  known, pre-existing gap this PR does not close.**
  `docs/pr11-security-foundation-discovery.md` (omnibioai-control-center)
  already found zero rate limiting anywhere in this codebase
  (`Critical` risk R2) — `/totp/verify` inherits that same gap, same
  as every other endpoint. Adding rate limiting here would be solving
  a platform-wide problem inside one PR's narrow scope; flagged here
  as a residual risk for a future, dedicated PR rather than silently
  left undocumented. The ±1-step window (§2) keeps the *guessable
  space per attempt* the same regardless (3 valid codes out of
  1,000,000 at any instant) — the absence of rate limiting affects how
  many attempts an attacker can make per unit time, not how easy any
  single attempt is.
- **`CONFIG_ENCRYPTION_KEY` unset in an environment**: `crypto.encrypt`
  already fails loudly (`RuntimeError`) rather than storing plaintext
  — this PR adds no new failure mode here, it inherits the existing
  one and surfaces it as a `500` with a clear message, same as
  `routes_config.py`.
- **No login-time enforcement whatsoever** (explicitly out of scope,
  per this PR's own "DO NOT enforce MFA during login" instruction) —
  `mfa_enabled=True` on a `User` row has no effect on any existing
  authentication path today; that is PR11.5.3's job, per
  `docs/pr11-security-foundation-discovery.md`'s roadmap.

## 7. Verification method

- Full read of `app/db/models.py`'s `MFADevice`/`MFARecoveryCode`/`User`
  (PR11.5.1) to confirm exact column names/types this PR's service
  code must match.
- Full read of `app/core/crypto.py` (unchanged by this PR) to confirm
  `encrypt`/`decrypt`'s exact signature and failure behavior.
- Full read of `app/services/apikey_service.py` and
  `app/api/routes_apikeys.py` as the direct structural template for
  `mfa_service.py`/`routes_mfa.py` (service owns all mutation +
  audit logic; route only translates exceptions to HTTP status).
- Full read of `app/services/audit_service.py` (`AuditEventType`,
  `log_event`) to confirm the naming convention and no-op-avoidance
  precedent this PR's five new event types and their emission
  conditions follow.
- Full read of `app/rbac.py` (`get_current_user`,
  `get_org_membership`'s 404-not-403 reasoning) and
  `app/api/routes_config.py` (bare-`get_current_user`,
  no-permission-required precedent for a self-service endpoint).
- Grepped `app/api/*.py` for any pre-existing `/users` route prefix —
  none conflicts with `/users/me/mfa/*`.
- Confirmed `tests/test_route_authorization_coverage.py`'s automated
  scan is scoped to `/orgs/{org_id}/...` only, so it does not (and
  should not) apply to this PR's self-service routes.
- Confirmed via `requirements.txt` that no TOTP library is already a
  dependency, and via this codebase's own inline-comment convention on
  every existing dependency that new dependencies are added
  deliberately, not by default — informing the decision to implement
  RFC 6238 directly against the stdlib rather than adding `pyotp`.
