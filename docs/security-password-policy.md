# Password Security Policy & Compromised-Password Protection (HIPAA Phase 1 PR2)

Local-password security policy for `POST /auth/register`. Builds on
[PR1's authentication abuse protection](security-auth-rate-limiting.md)
without redesigning authentication.

## Security gap

Before this PR: no minimum password length, no strength policy, no
compromised-password checking, and (as a side finding) a real silent-
truncation weakness in how passwords were hashed. Discovery for this PR
found the password lifecycle in this service is narrower than typical:
**the only two places a local password is ever created are `POST
/auth/register` and `init_admin.py`'s one-time bootstrap-admin
creation.** There is no password-change, password-reset, admin-creates-
user, or invitation/activation endpoint anywhere in this codebase today
-- those sections of this document are marked N/A, not silently
skipped.

## Policy

| Rule | Default | Rationale |
|---|---|---|
| Minimum length | 12 characters | Primary strength lever -- see below for why character-class rules aren't imposed instead |
| Maximum length | 128 characters | Not a strength control -- rejects pathological input before it reaches hashing/the compromised-password check |
| Common-password blocklist | ~150 entries, local, always-on | See `app/core/common_passwords.py` |
| Compromised-password check | HIBP k-anonymity API | See below |
| Password == own email | Rejected | Free, obviously unsafe |

**No mandatory uppercase/lowercase/number/symbol rules.** This is a
deliberate choice, not an oversight: mandatory character-class rules are
well-documented (NIST SP 800-63B, among others) to push users toward
predictable, easily-guessed patterns (`Password1!`) while adding little
real resistance to guessing -- length and compromised-password
rejection provide much more actual security for the same or less user
friction. `test_password_not_overconstrained_no_mandatory_character_classes`
locks this in: an all-lowercase, punctuation-free passphrase is accepted
as long as it's long enough and not common/compromised.

## Compromised-password protection

**Mechanism**: Have I Been Pwned's "Pwned Passwords" k-anonymity API
(`app/core/compromised_password.py`). The password is SHA-1 hashed
*locally*; only the first 5 hex characters of that digest (the
"prefix") are ever sent over the network. The response contains every
suffix in the multi-hundred-million-entry database sharing that prefix
(typically several hundred to a few thousand candidates) plus each
one's breach count; the real 35-character suffix is compared *locally*.
An observer of the request -- including the API operator -- cannot
recover the real password from it. This is the standard mechanism for
this problem (referenced by NIST SP 800-63B, used by 1Password, Firefox
Monitor, GitHub), not a bespoke design. SHA-1's use here is not a
cryptographic-security claim about anything this service stores or
verifies -- it's simply the API's own indexing scheme.

**Never sent**: the plaintext password, the full SHA-1 digest, or
anything password-derived beyond the 5-character prefix.
`test_only_prefix_sent_never_plaintext_or_full_hash` asserts this
directly against the captured outbound request.

**Local common-password blocklist** (`app/core/common_passwords.py`)
runs first, with zero network dependency, as an always-available floor
-- see that module's own docstring for source/update-process/
limitations.

## Provider outage behavior

Configurable via `PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED` (default
`false` -- fails **open**). On a timeout, connection error, or
malformed response from the Pwned Passwords API:

- **Default (fail open)**: registration proceeds. The length and local-
  blocklist checks already ran and passed -- this is "proceeding
  without the network-backed check," not "proceeding without any
  check." Chosen as the default because registration is a low-
  frequency, non-critical-path operation for this service, and making
  it hard-dependent on a third party's uptime introduces a new single
  point of failure for a brand-new user's very first interaction with
  the product.
- **`PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED=true`**: registration is
  rejected (generic message, same as any other policy failure -- no
  distinct error is exposed) until the provider is reachable again. An
  operator who wants strict enforcement can opt into this.

Either way, every unperformed check increments
`password_compromise_check_errors_total` (Prometheus) -- never silent,
regardless of which policy is active. Both paths are tested directly:
`test_provider_unavailable_fails_open_by_default`,
`test_provider_unavailable_fails_closed_when_configured`,
`test_provider_timeout_handled_same_as_connection_error`,
`test_malformed_provider_response_does_not_crash`.

## Password lifecycle coverage

| Flow | Status |
|---|---|
| Registration (`POST /auth/register`) | Enforced |
| Password change | **N/A -- endpoint does not exist** |
| Password reset | **N/A -- endpoint does not exist** |
| Admin-created user | **N/A -- endpoint does not exist** |
| Admin password reset/change | **N/A -- endpoint does not exist** |
| Invitation/activation | **N/A -- no flow sets a password; team/org "invitation" in this codebase is a membership concept only, verified to never touch `hashed_password`** |
| Bootstrap admin (`init_admin.py::create_admin`) | **Deliberately not routed through this policy** -- see below |

**Existing passwords**: not force-reset. A password created before this
PR continues to authenticate exactly as it did before, until the user
changes it (no such endpoint exists yet) or it's reset (ditto). What
*does* happen automatically: see "Hashing" below.

**Bootstrap admin**: `init_admin.py::create_admin` is intentionally
**not** gated by `validate_new_password`. Two reasons: (1) it already
defaults to a cryptographically random 192-bit token
(`secrets.token_urlsafe(24)`) whenever `ADMIN_BOOTSTRAP_PASSWORD` is
unset, which trivially satisfies this policy without needing to check
it; (2) gating service *startup* on a network-dependent compromised-
password lookup would turn a Pwned Passwords outage into "this service
cannot boot at all," a strictly worse failure mode than an operator
setting a weak `ADMIN_BOOTSTRAP_PASSWORD` once -- which is already
correctable by rotating it immediately, as the bootstrap's own printed
message instructs. This is a documented boundary, not an oversight.

## Password reuse / history

Not implemented. Discovery found no existing password-history
mechanism, and building one (requiring a new table of historical
hashes, retention policy, etc.) is a materially larger change than this
PR's scope -- consistent with this PR's own instruction not to expand
into password-history enforcement unless the existing architecture
makes it trivial, which it doesn't. Documented here as a possible
future control, not implemented.

## Hashing

`app/core/security.py`'s `pwd_context` now uses
`CryptContext(schemes=["bcrypt_sha256", "bcrypt"], deprecated="auto")`,
changed from plain `bcrypt`-only.

**Why**: verified directly that plain bcrypt only ever hashes the first
72 *bytes* of its input -- a password differing only past byte 72 still
verified as correct against a plain-bcrypt hash. That's a silent
truncation this PR's own "must support passwords substantially longer
than the minimum... do not silently truncate" requirement directly
prohibits, now that registration is expected to accept long passphrases.
`bcrypt_sha256` is passlib's own built-in scheme for exactly this
problem: it SHA-256-hashes the password first (a fixed 32-byte digest,
always under bcrypt's 72-byte limit) and bcrypts *that* -- still bcrypt
underneath, no new dependency, not a change of algorithm for its own
sake. `test_no_silent_truncation_full_password_required_to_login`
demonstrates the fix end-to-end.

**Backward compatibility**: listing `"bcrypt"` second (not removed)
means `verify()` still recognizes and validates every hash already in
the database (`$2b$...`) exactly as before -- no forced rehash, no mass
password reset. `deprecated="auto"` marks the non-default scheme as
needing an update; `auth_service.authenticate_user` checks
`needs_rehash()` after a *successful* login and transparently upgrades
that one user's hash to `bcrypt_sha256` in place, using the plaintext
password already in hand from the verification that just succeeded.
This is how "existing passwords continue to function until changed"
(this PR's own requirement) becomes "...and are opportunistically
migrated to the stronger hash the next time their owner logs in,"
without a mass migration job or forced reset. Verified in
`test_legacy_plain_bcrypt_hash_still_verifies_and_gets_upgraded`.

**Verified, unchanged by this PR**: `hashed_password` never appears in
any Pydantic response schema or route response (grepped across
`app/schemas/` and `app/api/` -- confirmed zero occurrences beyond the
hashing/verification call sites themselves); password verification goes
through passlib's own constant-time-safe comparison, unchanged.

## Error handling

Every policy rejection -- too short, too long, common password,
matches-own-email, compromised, or (if fail-closed is configured)
provider-unavailable -- returns the identical generic message:

> "This password cannot be used because it does not meet the security
> requirements."

`PasswordPolicyError.__str__` always returns this fixed string
regardless of its internal `reason` field, which exists for
metrics/logging only and is never surfaced in the HTTP response --
verified directly in `test_registration_error_does_not_reveal_which_rule_failed`.
HTTP status is `400`, matching this endpoint's existing error
convention (`User already exists` also already used 400).

## Privacy

- Plaintext passwords: never logged (`test_password_not_present_in_application_logs`,
  using `caplog` across a full register+login+reject cycle), never in
  audit event metadata (`test_password_not_present_in_audit_events`),
  never in HTTP responses (`test_registration_response_never_contains_password`).
- Password hashes: never in HTTP responses
  (`test_hashed_password_never_in_register_or_validate_response`).
- The compromised-password lookup cannot reconstruct the password --
  see "Compromised-password protection" above.
- Metrics (`password_policy_rejected_total{reason=...}`,
  `password_compromise_check_errors_total`) carry no password material
  -- `reason` is one of 6 fixed enum values, never the password or a
  derivative of it.

## SSO / SAML / OIDC boundary

This policy is consulted from exactly one place: inside `POST
/auth/register`. OAuth/SSO/SAML-provisioned users
(`oauth_service.create_user_with_oauth`, `license_service`,
`routes_saml.py`) are created with `hashed_password=None` and never
call `validate_new_password` at all -- confirmed by
`test_oauth_user_creation_has_no_local_password_and_bypasses_policy`.
`hashed_password=None` also means `authenticate_user`'s `not
user.hashed_password` branch rejects any local-password login attempt
against such an account outright (pre-existing behavior, unchanged) --
so a `None` local-password field cannot be used as an unintended
authentication path.

> **Local-password users** → this policy.
> **SAML/OIDC users** → their own external identity provider's policy.

## Configuration

All in `app/core/config.py`, env-overridable:

| Setting | Default | Meaning |
|---|---|---|
| `PASSWORD_MIN_LENGTH` | 12 | Minimum characters |
| `PASSWORD_MAX_LENGTH` | 128 | Maximum characters (abuse guard, not a strength control) |
| `PASSWORD_COMPROMISE_CHECK_ENABLED` | `true` | Master on/off for the HIBP check specifically (length/blocklist always run) |
| `PASSWORD_COMPROMISE_CHECK_TIMEOUT_SECONDS` | 3.0 | HTTP timeout for the provider call |
| `PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED` | `false` | See "Provider outage behavior" above |

## Observability

- `password_policy_rejected_total{reason=...}` -- 6 bounded reason
  values (`too_short`, `too_long`, `matches_email`, `common_password`,
  `compromised`, `check_unavailable`), never the password.
- `password_compromise_check_errors_total` -- provider-unreachable
  count, no labels.

## Limitations (intentionally unresolved in this PR)

1. No password-change or password-reset endpoint exists yet -- this
   policy has nowhere else to apply until those are built.
2. Bootstrap-admin password is not policy-validated -- see "Bootstrap
   admin" above.
3. No password-history/reuse detection.
4. The local common-password blocklist (~150 entries) is illustrative,
   not comprehensive -- the HIBP check is the comprehensive mechanism;
   the local list is a zero-dependency floor.
5. `PASSWORD_MAX_LENGTH` is an abuse guard, not derived from any
   specific threat model beyond "reject pathological input."

## HIPAA Phase 1 mapping

Closes: **Password Security Policy / Authentication Controls** --
verified by `tests/test_password_policy.py` (33 tests: length,
strength/common-password behavior, compromised-password checking
including provider-outage and malformed-response handling, registration
enforcement and generic error shape, the SSO/OAuth boundary, and privacy/
security regressions for logs/audit-events/API-responses). This PR does
not, on its own, establish full HIPAA compliance -- see "Limitations"
above and PR1's own equivalent section for what remains.
