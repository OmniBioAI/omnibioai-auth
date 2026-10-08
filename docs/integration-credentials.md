# Integration credential foundation

Auth is the canonical owner of integration credential identity, encrypted storage, lifecycle, authorization, and audit events. Workbench remains the canonical owner of provider definitions, plugin membership, capabilities, and execution.

## Ownership and scopes

Credentials use `user`, `organization`, or reserved `platform` scope. User ownership comes only from the validated access-token subject. Organization ownership comes only from the access token's active organization plus a live organization membership. Organization mutation additionally requires the live `manage_org` permission. Request bodies contain no user or organization owner identifiers.

Platform scope is represented in the model and provider policy but has no mutation API in V1. This avoids inventing a platform-owner administration surface.

Secret payloads are JSON-serialized and encrypted with the existing `CONFIG_ENCRYPTION_KEY` Fernet implementation. Metadata responses include configuration state and an optional four-character mask only. No browser route decrypts or returns a payload. Existing OpenAI/Claude Organization Connections remain on their existing storage and reveal path.

## Resolution

Workbench provider definitions declare allowed scopes and an explicit resolution policy. Auth fetches the non-secret policy projection from Workbench and fails closed if it is unavailable. V1 policy may resolve user, then organization, then a future platform credential, then anonymous access only where the provider explicitly allows each step.

`POST /integrations/credentials/{provider}/references` creates a short-lived random reference. Only its SHA-256 digest is stored. A reference is bound to provider, credential version, issuing user, active organization context, consumer `workbench`, and purpose `integration_execution`. Replacement and revocation invalidate existing references.

Workbench resolves a reference through `POST /internal/integration-credentials/resolve` using `INTEGRATION_CREDENTIAL_SERVICE_SECRET`. The shared service secret authenticates Workbench but possession of it or of a reference alone is insufficient: bindings, expiry, credential state/version, ownership, and live organization membership are rechecked. There is no generic plaintext-by-ID endpoint.

## Routes

- `GET /integrations/credentials`
- `GET /integrations/credentials/{provider}/status`
- `PUT /integrations/credentials/{provider}/{user|organization}`
- `DELETE /integrations/credentials/{provider}/{user|organization}`
- `POST /integrations/credentials/{provider}/references`
- `POST /integrations/credentials/{provider}/test`
- Internal only: `POST /internal/integration-credentials/resolve`

Connection tests are authenticated and audited. V1 returns `TEST_NOT_SUPPORTED` unless Workbench explicitly allowlists a bounded, non-destructive provider probe; it never fabricates success.

## Operations

Both Auth and Workbench must receive the same `INTEGRATION_CREDENTIAL_SERVICE_SECRET`. Auth uses `WORKBENCH_PROVIDER_POLICY_BASE_URL` for the Workbench policy projection. References default to 300 seconds and are bounded to 30–900 seconds by `INTEGRATION_CREDENTIAL_REFERENCE_TTL_SECONDS`.

Run `alembic upgrade head` before starting the new Auth image. Because the
legacy startup path still invokes `Base.metadata.create_all()`, revision 0031
also recognizes the exact empty table shape that startup may have already
created while Alembic still records 0030. It verifies all expected columns,
indexes, checks, and foreign keys before advancing; partial or foreign schemas
fail closed. Operators must not manually stamp around a mismatch.

Audit events record provider, scope, actor, organization, consumer, purpose, and outcome metadata where applicable. Credential values and ciphertext are excluded.

OAuth lifecycle support and remaining provider definitions are deferred.
