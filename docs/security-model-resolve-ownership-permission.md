# `model.resolve_ownership` Permission (omnibioai-model-registry Phase 2E, IAM-side)

Registers and grants the IAM permission that
[omnibioai-model-registry's Phase 2E](../../omnibioai-model-registry/docs)
legacy-ownership-resolution feature depends on. That repo's `POST
/v1/ownership/resolve` route and `omr resolve-ownership` CLI command were
already merged and already check for this permission string on the
caller's JWT `permissions` claim -- until this change, the permission did
not exist in this repo's registry at all, so the feature was reachable
but unusable in any `AUTH_ENABLED=true` deployment. This document covers
the IAM-side registration/grant only; the resolution logic itself
(eligibility rules, race handling, ownership-file writes) lives entirely
in omnibioai-model-registry and is documented there.

## What it's for

Authorizes resolving a `legacy_unowned` Model Registry model's ownership
to the caller's own organization -- a one-time, narrow administrative
action for models registered before per-org ownership tracking existed
(or otherwise orphaned). It does **not** grant any ability to read,
write, promote, or otherwise use a model, and it does **not** allow
reassigning a model that is already owned by a different organization --
omnibioai-model-registry enforces that boundary itself and remains the
sole source of truth for model ownership (`ownership.json`). This repo
only decides *who is allowed to ask* for resolution; the resolution
logic and its eligibility rules live entirely on the model-registry
side.

## Distinct from `model.use`

`model.resolve_ownership` is a fully independent permission, not a
capability layered on top of `model.use`:

- Holding `model.use` alone does **not** grant `model.resolve_ownership`.
- Holding `model.resolve_ownership` alone does **not** grant `model.use`.
- The two are registered as separate `PermissionDef` entries
  (`app/core/permission_names.py`) with no implication relationship
  encoded between them anywhere in the registry, JWT-claim assembly, or
  role-seed data.

This is deliberate: ordinary model read/write access (`model.use`,
granted to the `scientist` role) is a routine, high-frequency
capability; resolving orphaned ownership is an infrequent, higher-
privilege administrative action, and the two should be gradable
independently of one another.

## Format

`model.resolve_ownership` (single dot, `resource.action` shape) --
`model.ownership.resolve` (two dots) was considered and rejected because
it fails this repo's own non-legacy permission-name format validator
(`_PERMISSION_FORMAT_RE`, single dot only).

| Field | Value |
|---|---|
| `resource` | `model` |
| `action` | `resolve_ownership` |
| `scope` | `both` (grantable at either global or org-scoped role level, same as `model.use`) |
| `category` | `model` |
| `legacy` | `false` |

## Who is granted it

Added to `ORG_ADMIN_PERMISSIONS` (`app/services/org_service.py`) --
granted to the `org_admin` role, the same "administer this org's own
resources" role that already carries `manage_teams`, `manage_api_keys`,
`workflow.manage`, and `runs.read`. This follows that existing
precedent directly rather than inventing new authorization semantics:
an org's own admin can claim ownership of an orphaned model on behalf
of their organization; an ordinary `scientist` (which holds `model.use`)
cannot.

**Not** added to `SCIENTIST_PERMISSIONS`, **not** gated by any
`org_role == "org_admin"` string check, and **not** automatically
implied by any other permission. It is registered as any other
permission is, and can also be granted to a custom role via the normal
`POST /roles` / `PUT /roles/{id}` CRUD surface -- the `org_admin` grant
described here is the default seed, not the only way to hold it.

## Grant mechanism (no migration required)

The permission *registry* is pure code (`permission_names.py`), never
touches the database. Actual *grants* are DB-backed `Permission`/`Role`
rows, populated exclusively through the existing idempotent, additive-
only startup functions -- no new Alembic migration was needed or added
(grepped the existing migration history: no prior migration has ever
inserted a `Permission` row or referenced a permission string; this is
consistent with every prior permission addition in this repo, e.g.
`workflow.execute`, `runs.read`).

- **Fresh deployments**: the first `create_organization()` call seeds a
  new `org_admin` Role row using the current `ORG_ADMIN_PERMISSIONS`
  list, which already includes `model.resolve_ownership`.
- **Existing deployments** (an `org_admin` Role row already exists from
  before this change): `ensure_org_admin_permissions()`, already called
  at every app startup, tops it up additively -- adds
  `model.resolve_ownership` to the existing role's permission set
  without touching or removing anything an operator may have manually
  changed.
- **No org created yet**: `ensure_org_admin_permissions()` is a no-op
  (there is no `org_admin` role row to top up); the permission is
  granted automatically the moment the first organization is created,
  same as any other `ORG_ADMIN_PERMISSIONS` entry.

Both paths are idempotent -- re-running startup any number of times
converges to the same state and never removes a permission.

## Security invariants (unchanged / preserved)

- Identity is taken from the verified JWT only; no new gateway-header
  trust was introduced.
- Organization context comes from `UserContext`/JWT org membership, not
  any client-supplied `organization_id` -- this permission carries no
  organization-identity payload of its own; it is a pure yes/no
  authorization flag checked against the caller's own JWT `permissions`
  claim, exactly like every other permission in the registry.
- No role-name (`org_role == "org_admin"`) authorization check was
  added anywhere -- authorization is permission-based throughout, per
  this repo's existing IAM architecture.
- Model ownership itself remains authoritative in
  omnibioai-model-registry's `ownership.json`; this repo has no
  knowledge of, and makes no claim about, any specific model's
  ownership state.
- `assert_no_unregistered_permissions()` (startup drift check) continues
  to pass -- every DB `Permission` row has a matching code-registry
  entry.

## Not a HIPAA compliance claim

This change registers and grants one IAM permission so that an already-
merged, already-audited feature in a different repository
(omnibioai-model-registry) becomes usable. It does not, on its own,
constitute or claim HIPAA compliance or certification for this service
or the platform as a whole.

## Tests

`tests/test_model_resolve_ownership_permission.py` (new) plus targeted
additions to `tests/test_permission_registry.py` (new
`MODEL_REGISTRY_OWNERSHIP_NAMES` group) and
`tests/test_platform_permissions_api.py` (updated registry-size/
`FUTURE_NAMES` counts) cover: registration/recognition, format
validation (including the rejected two-dot alternative), grant/no-grant
behavior via real JWT claims, independence from `model.use` in both
directions, unchanged `scientist`/`org_admin` permission sets otherwise,
and the absence of any client-controlled organization field on the
registry entry.
