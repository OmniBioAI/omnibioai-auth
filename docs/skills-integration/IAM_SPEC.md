# IAM live-interface design (B-02, B-03)

Status: design complete; implementation and owner approval are gated. This document is not an endpoint approval.

## Current offline contract

`VerifiedIdentity` retains only user, organization, permissions, and `valid=True`; `TrustedContextIssuer` seals that projection and rejects anonymous, malformed, stale, future, or tampered contexts (`src/omnibioai_skills/integration/context.py:34-50`, `src/omnibioai_skills/integration/context.py:92-173`). IAM-claim authorization requires exact permission membership and creates a content-derived decision reference (`src/omnibioai_skills/integration/policy_engine.py:48-83`). No bearer token is accepted by those models.

## Target interface

Injected port `verify_identity(request) -> VerifiedIdentityResponse`.

- Request: `credential_handle`, expected `tenant_id`, `correlation_id`, audience `omnibioai-skills`, optional delegation chain. A handle is opaque and process-local; never serialize the bearer.
- Response: `principal_id`, `tenant_id`, exact permission set, `identity_id`, `issued_at`, `expires_at`, `revocation_checked_at`, optional `delegation_id`/actor, `schema_version`, authority, and immutable verification reference.
- Errors: `INVALID`, `EXPIRED`, `REVOKED`, `TENANT_MISMATCH`, `DELEGATION_INVALID` (non-retryable); `UNAVAILABLE`, `TIMEOUT`, `RATE_LIMITED` (retryable). Unknown errors become unavailable, never anonymous.
- Idempotency: verification is read-only; `(credential handle, audience, expected tenant)` may be coalesced only until the earlier of expiry or revocation-freshness SLO. Do not cache a successful authorization.
- Timeout/retry: 250 ms connect, 750 ms response, 1 s total; at most two retries with full-jitter exponential backoff (50/100 ms) for connection failure, 429, and 5xx. Never retry invalid/deny responses.
- Pagination: none. Permission results must be complete; truncation or continuation metadata is an error.

## Authentication, authorization, and tenancy

The host injects a workload-identity credential provider or request bearer verifier. Configuration contains only provider references, never token values. Service token scope is `identity.verify` and `delegation.verify`; the caller token audience must be Skills. The expected tenant is supplied independently from the route/session and must equal the verified identity and delegation tenant. Service-account fallback, role-derived admin, cross-tenant delegation, and caller-supplied permission claims are forbidden.

## Audit

Emit `skill_identity_verified` on success and `skill_identity_rejected` on reject/unavailability: `event_id`, time, correlation/trace, tenant, principal (only after verification), identity/delegation reference, outcome, error code, IAM authority/version, and latency bucket. Never emit bearer/credential handle, email, roles, raw claims, permission list, inputs, or PHI/PII; hash a stable principal only if Security Audit requires pseudonymization.

## Failure and fail-closed rules

Missing credentials, partial permission data, stale revocation evidence, tenant/delegation mismatch, malformed response, clock uncertainty beyond five seconds, timeout, or unavailable service produces no caller context and no downstream call. Revocation invalidates local contexts immediately within the approved freshness SLO.

## Flags and kill switches

`SKILLS_IAM_LIVE=false` by default; activation also requires an immutable owner-approval reference and a configured injected provider. `SKILLS_EXECUTION_KILL=true` wins over every flag and blocks new validation/submission. IAM read-only verification may have a separate tenant allowlist, default empty. No environment value is interpreted as a credential.

## Test plan

First run the fake contract for valid, invalid, expired, revoked, stale, unavailable, delegation, and cross-tenant cases; assert no token appears in models/logs. Then qualify against a non-production real IAM instance with owner-issued test identities, schema/version and revocation-latency evidence, clock skew, workload identity, and tenant isolation. Production remains disabled until evidence is signed and reviewed.

## Owned outside this repo

- [ ] IAM owner registers and approves `skill.discover`, `skill.plan`, `skill.validate`, and `skill.execute` without implicit grants (B-03).
- [ ] IAM publishes the supported client/schema version and complete-claims guarantee.
- [ ] IAM defines audience, workload identity, delegation, expiry, revocation, and clock-skew contracts.
- [ ] IAM proves tenant-bound verification and no service-account fallback.
- [ ] IAM publishes availability and revocation-freshness SLOs plus immutable approval evidence.
