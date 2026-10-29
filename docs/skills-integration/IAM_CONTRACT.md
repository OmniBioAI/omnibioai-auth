# Skills IAM v1 owner contract

The supported schema is `skills.iam/v1`, implemented by the injected,
process-local port in `app.services.skills_identity_service`. It is not an
HTTP bearer-introspection endpoint: callers pass opaque credential handles to
their runtime-injected providers, and neither requests, responses, nor audit
records contain credential material.

## Activation

The integration is unavailable unless all conditions hold:

- `SKILLS_IAM_LIVE=true` (default `false`);
- `SKILLS_IAM_APPROVAL_REF` is non-empty;
- the expected tenant is in `SKILLS_IAM_TENANT_ALLOWLIST` (default empty);
- the injected workload identity is active, tenant-bound, and currently holds
  `identity.verify` or `delegation.verify` as appropriate.

There is no service-account fallback and no role-derived administrator bypass.
The four `skill.*` permissions are registered but are not seeded or implicitly
granted to any role or OAuth client.

## Complete claims and time contract

A successful response contains principal, tenant, sorted complete permission
set, identity and optional delegation identifiers, actor workload identity,
issued/expiry/revocation-check times, schema version, authority, and an
immutable verification reference. Unknown, partial, malformed, stale,
cross-tenant, or unavailable state fails closed.

Skills delegated identities:

- audience: exactly `omnibioai-skills`;
- maximum lifetime: 300 seconds (configurable down to 30 seconds);
- allowed clock uncertainty: 5 seconds;
- revocation freshness objective: 30 seconds by default, configurable from 1
  through 60 seconds;
- revocation enforcement: checked live on every verification against token
  blacklist/database revocation, grant, user, membership, effective
  permissions, workload client status/current scopes, tenant, and audience.

No successful authorization decision is cached by this implementation.

## Availability and evidence

The port is in-process and inherits the Auth service availability objective.
Provider lookup failure is `UNAVAILABLE`; it never produces an anonymous or
partially verified context. Production activation still requires an immutable
owner approval reference supplied at runtime and independent security review;
this repository does not fabricate those external approvals.
