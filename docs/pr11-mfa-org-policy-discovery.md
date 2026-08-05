# PR11.5.5 — Enterprise Organization MFA Policy: Discovery

Discovery performed before coding, per this PR's own instructions.
Builds on PR11.5.1 (MFA database foundation), PR11.5.2 (TOTP
enrollment), PR11.5.3 (login challenge), PR11.5.4 (recovery codes +
admin reset) — none of that is redesigned, only extended with an
organization-level policy layer. Verified directly against current
source in this session.

## 1. Where MFA policy belongs

**A new table, `OrganizationMFAPolicy`, not columns on `Organization`.**
Re-read `app/db/models.py`'s `Organization` (`:220-240`) and
`OrganizationSSOConfig` (`:330-381`) in full. `Organization` itself
carries only identity/lifecycle fields (`slug`, `name`, `plan`,
`status`, `status_changed_*`) — every *authentication-policy* concern
this codebase has ever added (SSO configuration, SSO enforcement, SSO
break-glass override) lives on `OrganizationSSOConfig`, a sibling
table, never bolted onto `Organization` directly. This PR follows that
exact precedent for the same reasons that table's own docstrings give
implicitly and this PR's own task spec makes explicit: security
configuration grows independently of organization identity, future
policies (session timeout, password requirements, IP restriction —
all named as gaps in `docs/pr11-security-foundation-discovery.md`,
omnibioai-control-center) can each get their own table the same way
without every one of them crowding `Organization` itself.

**Field shape mirrors `OrganizationSSOConfig` deliberately closely** —
not a coincidence, a reused pattern:

| `OrganizationMFAPolicy` field | `OrganizationSSOConfig` analog |
|---|---|
| `required` (bool) | `enforced` (bool) |
| `override_active`/`override_reason`/`override_at`/`override_by_user_id` | `sso_override_at`/`sso_override_reason`/`sso_override_by_user_id` |
| `enabled_at`/`enabled_by_user_id` | *(no direct analog — see §3)* |

One deliberate difference: `OrganizationSSOConfig`'s override state is
signaled purely by `sso_override_at is not None` (no separate
boolean); this PR's own field list explicitly names a distinct
`override_active` boolean *in addition to* `override_at`. Implemented
literally as specified — `override_active` is the authoritative
signal, `override_reason`/`override_at`/`override_by_user_id` are the
"who/why/when" detail, all four set and cleared together (same set/
clear symmetry `clear_sso_override` already uses for its three
fields).

## 2. Migration requirements

**Additive only, one new table, zero existing-table changes.** No
column is added to `Organization`, `OrganizationSSOConfig`, or `User`
— `User.mfa_enabled` (PR11.5.1) already exists and is reused as-is for
"has this specific person personally enrolled MFA," a question
entirely orthogonal to "does their org require it." Migration
`0014_organization_mfa_policy` (`down_revision =
"0013_mfa_foundation"`) follows `0011_audit_events.py`'s/
`0004_org_sso_schema.py`'s own `op.create_table` shape: `organization_id`
foreign-keyed to `organizations.id` and `UNIQUE` (one policy row per
org, same as `OrganizationSSOConfig.organization_id`), an index on
`organization_id` for lookup, reversible `downgrade()` dropping the
table. Existing organizations survive the upgrade with zero policy row
— absence of a row means "no policy configured," not "policy
required=false enforced" (mirrors `OrganizationSSOConfig`'s own
"no CRUD exists until explicitly configured" precedent — `GET
/orgs/{org_id}/mfa-policy` 404s until a `POST` creates one, exactly
like `GET /orgs/{org_id}/sso` already does today).

## 3. Enforcement point

**`auth_service.generate_tokens_or_mfa_challenge` remains the single
MFA decision point** — this PR's own explicit requirement, and the
same function PR11.5.3 already established as the one place every
login flow (password/OAuth/SSO/license — all 7 `generate_tokens` call
sites) funnels through. No new decision point is added anywhere else;
in particular `verify_mfa_challenge` (PR11.5.3/PR11.5.4) needs **zero
changes** — a user blocked for lacking enrollment never reaches a
challenge at all (§5), so there is nothing for that function to know
about org policy.

**The org's primary-membership resolution already happens inside this
function today** (`org_service.resolve_primary_membership(db,
user.id)`, called once, for the existing `MFA_CHALLENGE_REQUIRED`
audit event's `organization_id`). This PR hoists that one call to the
top of the function and reuses its result for both purposes — no
second query.

**Combined decision logic** (replacing the current single
`if user.mfa_enabled` branch):

```python
org_membership = org_service.resolve_primary_membership(db, user.id)
organization_id = org_membership.organization_id if org_membership else None

org_requires_mfa = False
if organization_id is not None:
    policy = get_org_mfa_policy(db, organization_id)
    if policy is not None and policy.required and not policy.override_active:
        org_requires_mfa = True

if not user.mfa_enabled:
    if org_requires_mfa:
        raise MFAEnrollmentRequiredError()
    access, refresh = generate_tokens(...)
    return {"mfa_required": False, ...}

# user.mfa_enabled is True -- personal MFA challenge, unchanged from PR11.5.3
challenge_token = create_mfa_challenge_token(...)
...
return {"mfa_required": True, ...}
```

**Why personal MFA always wins, regardless of org policy state** — a
user who has personally enrolled TOTP (`user.mfa_enabled=True`) is
*always* challenged, whether the org requires MFA, doesn't, or has an
active override. This resolves a literal ambiguity in this PR's own
spec: the break-glass override section says both "Allows organization
users to authenticate without completing MFA" and, immediately after,
"Does not disable user MFA... Only suspends enforcement." Read
together, "enforcement" is specifically the *organization's* added
requirement — the override's job is to stop *that* requirement from
blocking an unenrolled member, not to switch off a member's own,
independently-chosen personal MFA. `user.mfa_enabled` is never read or
written by any override-related code in this PR; the override only
ever affects the value of `org_requires_mfa` computed above, which is
only consulted in the `not user.mfa_enabled` branch. This is the
compatibility matrix this PR's own task spec names explicitly:

| `user.mfa_enabled` | org `required` (no override) | Outcome |
|---|---|---|
| `False` | `False` | Normal tokens (unchanged, PR11.5.3) |
| `True` | `False` | MFA challenge (unchanged, "personal MFA still works") |
| `True` | `True` | MFA challenge (personal MFA branch handles it — org requirement is moot, already satisfied) |
| `False` | `True` | `mfa_enrollment_required`, no tokens (new) |
| `False` | `True`, override active | Normal tokens (org requirement suspended) |
| `True` | `True`, override active | MFA challenge (personal MFA is not what the override suspends) |

## 4. Response shape for the enrollment-required case

`MFAEnrollmentRequiredError` (new, defined in `auth_service.py` next
to `generate_tokens_or_mfa_challenge`, the only function that raises
it) — a distinct exception, not a third dict shape returned by that
function. Each of the 7 route call sites wraps its existing
`generate_tokens_or_mfa_challenge(...)` call in a
`try/except MFAEnrollmentRequiredError`, translating to:

```python
raise HTTPException(403, detail={
    "error": "mfa_enrollment_required",
    "message": "Your organization requires MFA enrollment",
})
```

**Why an exception, not a third `if`/`elif` branch on the returned
dict**: every one of the 7 call sites already has an established
`if result["mfa_required"]: ... else: ...` shape from PR11.5.3 —
wrapping the whole call in `try/except` is a smaller, lower-risk diff
at each site than restructuring that existing conditional into a
three-way branch, and keeps `generate_tokens_or_mfa_challenge`'s
return contract for its two existing, already-tested outcomes
completely unchanged.

**Why HTTP 403, matching this PR's own literal JSON example
verbatim**: this codebase already has a direct precedent for exactly
this shape — `routes_auth.py`'s existing SSO-enforcement rejection
(`login()`, pre-PR11.5) raises `HTTPException(403, detail={"reason":
"sso_required", "org_slug": ..., "sso_login_url": ...})` *before any
token is issued*, for the identical underlying situation ("this
organization has an authentication requirement you haven't satisfied
yet, no tokens for you"). This PR's `mfa_enrollment_required` case is
the same shape, applied to MFA instead of SSO, so it reuses `403` for
consistency with that existing convention rather than picking a new
status code for a conceptually identical situation.

`routes_license.py`'s `LicenseValidateResponse` (a `response_model`-
constrained route) needs **no schema change** for this case — a
raised `HTTPException` always bypasses `response_model` validation
entirely (FastAPI's exception-handling path, not the normal return
path), unlike the `mfa_required=True` case PR11.5.3 added, which
*does* return a value through the model and needed new optional
fields for that reason.

## 5. Why this closes the "does routes_license.py bypass MFA
enforcement" question

Re-read `app/api/routes_license.py::validate_license` in full this
session. Since PR11.5.3, it already calls
`generate_tokens_or_mfa_challenge(db, user, auth_method="license")` —
**not** `generate_tokens` directly — exactly like the other 6 login
call sites. Because this PR's org-policy logic lives entirely inside
`generate_tokens_or_mfa_challenge` itself (§3), license login inherits
org MFA policy enforcement automatically, with the only change to
`routes_license.py` being the same `try/except
MFAEnrollmentRequiredError` wrapper every other call site gets — no
license-specific bypass logic exists to remove, because none was ever
added. Verified by a dedicated test
(`test_license_login_respects_org_mfa_policy` in
`tests/test_mfa_org_policy.py`) exercising this exact path end-to-end,
not just asserted from reading the code.

## 6. Permission decision

**Reuses `manage_sso` (org-scoped) for policy CRUD, `manage_all_orgs`
(global) for override — no new permission**, per this PR's own
explicit constraint ("Reuse: manage_sso or manage_all_orgs... Do not
create new permission").

- `GET`/`POST`/`PATCH /orgs/{org_id}/mfa-policy`: gated by
  `require_org_permission_or_platform_admin(MANAGE_SSO)`, the exact
  same dependency `routes_org_sso.py`'s config CRUD already uses.
  **Why `manage_sso` over `manage_all_orgs` for this half**: this is
  routine, org-admin-level management of an org's own authentication
  requirements — conceptually the same authority level as configuring
  the org's own SSO identity provider (both answer "how must a member
  of this org authenticate"), not a cross-tenant platform-operator
  action. `manage_all_orgs` remains available as a bypass for platform
  admins via the same `_or_platform_admin` dependency variant, so no
  capability is lost — a platform admin can still manage any org's MFA
  policy without holding a real membership there, same as they already
  can for SSO config today.
- `POST`/`DELETE /orgs/{org_id}/mfa-policy/override`: gated by
  `require_permission(MANAGE_ALL_ORGS)`, a **global** permission
  check, deliberately not the org-scoped one above. Mirrors
  `override_sso_enforcement`'s own reasoning exactly ("a
  platform-operator break-glass tool... must work even if the org's
  own admin is the one locked out") — but reuses the *existing* global
  `manage_all_orgs` permission instead of introducing a parallel
  `override_mfa_enforcement` the way SSO's own override did, because
  this PR is explicitly constrained to the two names above only. No
  capability gap results: `manage_all_orgs` is already the platform's
  general cross-tenant administrative permission (used identically for
  `/platform/users/*`, the synthetic org_admin bypass in `app/rbac.py`),
  so reusing it here is consistent with, not a dilution of, its
  existing meaning.

## 7. Audit requirements

Four new `AuditEventType` constants, same `SCREAMING_SNAKE_CASE`/
`"snake_case"` convention every prior PR11.x addition used:

```python
MFA_POLICY_ENABLED = "mfa_policy_enabled"
MFA_POLICY_DISABLED = "mfa_policy_disabled"
MFA_POLICY_OVERRIDE_CREATED = "mfa_policy_override_created"
MFA_POLICY_OVERRIDE_REMOVED = "mfa_policy_override_removed"
```

This PR's own audit rule states every one of these four events "must
contain `{organization_id, actor_user_id, reason}`." `organization_id`/
`actor_user_id` are existing `AuditEvent` *columns*, populated exactly
as every prior PR11.x event already does. `reason` has no column on
`OrganizationMFAPolicy` for the enable/disable case (only the override
fields have a persisted `override_reason`) — it is carried in the
event's `metadata` dict instead:

- `MFA_POLICY_ENABLED`/`MFA_POLICY_DISABLED`: `reason` is an
  **optional** field on the `PATCH` request body
  (`app/schemas/org_mfa.py`), included in `metadata` whenever supplied
  (`None` if omitted — an honest "no reason given," not a required
  field that would break a routine toggle). Only emitted on an actual
  flip of `required` (same "don't log a no-op" convention
  `set_enforced` already uses) — `MFA_POLICY_ENABLED` on False→True,
  `MFA_POLICY_DISABLED` on True→False.
- `MFA_POLICY_OVERRIDE_CREATED`: `reason` is **required** on the
  request body (`OrgMFAOverrideRequest`, mirroring `SSOOverrideRequest`
  exactly) — an override is a significant, deliberately-justified
  action, same reasoning the SSO break-glass endpoint already
  establishes.
- `MFA_POLICY_OVERRIDE_REMOVED`: no request body (`DELETE`, same as
  SSO's `clear_sso_override`) — `reason` in this event's metadata is
  the *outgoing* override's own `override_reason` (the reason it was
  created), giving the removal event context about what's being closed
  out, without requiring a body on a `DELETE`. Only emitted if an
  override was actually active before clearing (same no-op-avoidance
  convention).

**Never in any of these four events**: a TOTP secret, an OTP code, a
recovery code, a challenge token, or any MFA device/recovery-code
identifier — none of that data is in scope of anything this PR's new
code touches (`OrganizationMFAPolicy` has no relationship to
`MFADevice`/`MFARecoveryCode` at all), so this is true by construction,
re-verified by this PR's own tests.

## 8. A genuine operational risk this PR does not solve, flagged
   explicitly rather than hidden

Enabling `required=True` for an organization **before** its members
have personally enrolled MFA creates a real bootstrapping problem:
`POST /users/me/mfa/totp/enroll` (PR11.5.2) itself requires a valid
Bearer access token (`get_current_user`) — but a member who hasn't
enrolled yet, attempting a *fresh* login after the policy takes
effect, is rejected with `mfa_enrollment_required` *before* any token
is issued (§3/§4). They have no access token to present to the
enrollment endpoint in the first place.

Unlike SSO's `set_enforced`, which has a real lockout guard (cannot
turn on `enforced` until at least one member has completed a
successful SSO login), **this PR adds no equivalent guard** — not an
oversight, but a direct consequence of the task's own explicit
non-goals ("no token architecture redesign" forecloses the natural
technical fix, a scoped enrollment-only token; a lockout guard analogous
to SSO's own wasn't requested either, and this PR sticks to what was
asked rather than silently inventing additional protective mechanisms
beyond spec).

**Partial, incidental mitigation already exists, not by design of this
PR**: `/auth/refresh` is unconditionally unaffected by this PR (§ see
"Important Compatibility Rules" — "Refresh tokens: No change"), so a
member with an *already-valid* refresh token from before the policy
took effect can keep refreshing (up to the existing 7-day
`REFRESH_TOKEN_TTL_DAYS`) and use that still-working access token to
enroll during that window. This does **not** help a brand-new member
who has never logged in, or anyone whose session has already fully
expired by the time the policy takes effect.

**Recommendation, documented here rather than silently left implicit**:
an operator turning on org-required MFA should first confirm members
have voluntarily enrolled personal MFA (there's no structural
enforcement of this order today), and a future PR (Admin Console UI,
PR11.5.6, or a dedicated follow-up) should surface this risk to the
admin turning the policy on, and/or add a proper bootstrap mechanism.
Not solved here — flagged, per this session's established practice of
surfacing known gaps rather than leaving them undocumented (e.g. the
zero-rate-limiting gap every MFA PR so far has similarly disclosed).

## 9. `test_route_authorization_coverage.py` — a required, not
   optional, update

Re-read `tests/test_route_authorization_coverage.py` in full. Its
`_org_scoped_routes()` scan matches any route whose path starts with
`/orgs` and contains `{org_id}` — this PR's five new routes
(`/orgs/{org_id}/mfa-policy` × 3 methods,
`/orgs/{org_id}/mfa-policy/override` × 2 methods) all match. Two
consequences, both required updates, not optional cleanup:

1. `test_org_scoped_route_inventory_matches_expected_count` — a bare
   tripwire asserting the *count* of scanned routes; goes from `25` to
   `30`.
2. `test_sso_override_routes_are_the_only_global_permission_exception` —
   currently asserts the global-permission-only route set is *exactly*
   `{"/orgs/{org_id}/sso/override"}`. This PR's override routes are
   legitimately in the same category (§6: `require_permission`, not
   org-membership-based) — the assertion must grow to include
   `/orgs/{org_id}/mfa-policy/override` too, and the test's own
   docstring updates to reflect that SSO's override is no longer the
   *only* deliberate global-permission exception, just the first one.

Both are additive, reviewed test changes (not weakened assertions) —
the coverage check itself (`test_every_org_scoped_route_has_a_real_
authorization_dependency`, `test_every_org_scoped_route_uses_the_
platform_admin_aware_dependency`) needs no change at all: this PR's
new routes already satisfy both by construction (§6).

## 10. Verification method

- Full read of `app/services/org_sso_service.py` and
  `app/api/routes_org_sso.py` (the direct structural template for
  every piece of this PR: config CRUD shape, override shape, audit
  call shape, no-op-avoidance convention).
- Full read of `app/schemas/org_sso.py` for the request/response
  schema shape this PR's `app/schemas/org_mfa.py` mirrors.
- Full read of `app/core/permission_names.py`'s registry to confirm
  `manage_sso` (ORG scope) and `manage_all_orgs` (GLOBAL scope) are
  both already registered, legacy, in active use — confirming no new
  permission is needed for either half of this PR.
- Re-read `app/services/auth_service.py::generate_tokens_or_mfa_challenge`
  (current state, unchanged since PR11.5.3) to confirm the exact
  integration point and the existing `org_service.resolve_primary_
  membership` call this PR reuses rather than duplicates.
- Re-read `app/api/routes_license.py::validate_license` (current
  state, unchanged since PR11.5.3) to confirm it already funnels
  through `generate_tokens_or_mfa_challenge`, closing §5's question by
  construction rather than requiring new license-specific logic.
- Full read of `tests/test_route_authorization_coverage.py` to
  identify the two required, additive test updates in §9 ahead of
  time, rather than discovering them as test failures after writing
  the routes.
- Grepped `app/db/models.py` for any existing organization-level
  security-policy field beyond `OrganizationSSOConfig` — none found,
  confirming this PR introduces the *first* such policy beyond SSO,
  consistent with `docs/pr11-security-foundation-discovery.md`'s own
  finding (omnibioai-control-center) that SSO enforcement was, before
  this PR, "the only real, enforced org-level security toggle in the
  entire system."
