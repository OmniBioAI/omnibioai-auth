# omnibioai-auth

**JWT authentication and authorization service for the OmniBioAI platform.**

Central identity layer for the OmniBioAI zero-trust security plane.
Handles user registration, login, token issuance, refresh, logout,
and validation across all platform services.

---

## Architecture Role

`omnibioai-auth` runs as a containerized service inside the OmniBioAI Docker
Compose stack. All platform services — TES (workflow execution), Studio
(Electron UI), LIMS (data management), and Control Center — delegate token
validation to this service rather than implementing their own auth logic.

```
Studio / TES / LIMS / Control Center / SDK
              |
        POST /auth/validate
              |
       omnibioai-auth (:8001)
         /         \
      MySQL        Redis
  (users, tokens)  (blacklist, pub/sub)
```

Redis also carries a `policy:invalidate` pub/sub channel. On logout,
`omnibioai-auth` publishes an invalidation event so downstream services can
flush any cached token state immediately.

---

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/register` | Create a new user account |
| `POST` | `/auth/login` | Authenticate and issue access + refresh tokens; sets the `omnibioai_session` cookie |
| `POST` | `/auth/refresh` | Exchange a valid refresh token (body or `omnibioai_session` cookie) for a new access + refresh token pair |
| `POST` | `/auth/logout` | Revoke refresh token; blacklist access token in Redis; clears the `omnibioai_session` cookie |
| `POST` | `/auth/validate` | Validate a token and return user identity, roles, and org context |
| `GET`  | `/auth/{provider}/login` | Redirect to `google`/`github`/`microsoft` OAuth2.1+PKCE authorize URL |
| `GET`/`POST` | `/auth/{provider}/callback` | Complete third-party OAuth login (browser-redirect and SPA-JSON variants) |
| `POST` | `/auth/link/confirm` | Confirm linking an OAuth identity to an existing password account |
| `GET`  | `/auth/sso/discover?email=` | Domain-based lookup: does this email's org enforce Enterprise OIDC? |
| `GET`  | `/auth/sso/{org_slug}/login` | Redirect to the organization's configured Enterprise OIDC IdP |
| `GET`/`POST` | `/auth/sso/{org_slug}/callback` | Complete an Enterprise OIDC login for that organization |
| `GET`  | `/auth/saml/{org_slug}/metadata` | This SP's SAML 2.0 metadata for that organization (entity ID, ACS URL, NameID format) |
| `GET`  | `/auth/saml/{org_slug}/login` | SP-initiated SAML login: redirects to the organization's configured IdP with a SAMLRequest + signed RelayState — no ACS endpoint exists yet |
| `POST` | `/oauth/token` | `client_credentials` grant — issues a service-identity access token |
| `GET`/`POST`/`DELETE` | `/orgs/{org_id}/oauth-clients` | Manage an organization's `client_credentials` clients |
| `GET`  | `/.well-known/jwks.json` | RS256 public-key set (JWKS), for future RS256 verifiers |
| `GET`  | `/health` | Liveness check — returns `{"status": "ok"}` |
| `GET`  | `/metrics` | Prometheus metrics (jwt_auth_total counter) |

This is the core identity/session surface. The service also registers 18
more routers covering organization management, platform administration,
MFA, and service credentials — grouped below rather than flattened into
one table, since each group has its own permission model.

### Organizations & Teams

| Router | Prefix | Covers | Gate |
|---|---|---|---|
| `routes_orgs.py` | `/orgs` | Create/list/get/update an org, invite a member, list/assign/revoke a member's org-scoped roles | `manage_org` (org-scoped) or `platform_admin` |
| `routes_teams.py` | `/orgs/{org_id}/teams` | Create/list teams, manage team membership, delete a team | `manage_teams` (org-scoped) or `platform_admin` |
| `routes_organization_roles.py` | `/organizations/{organization_id}` | Org-scoped custom role CRUD (`/roles`), org permission catalog (`/permissions`), member role assignment (`/members/{user_id}/roles`) — PR13's dynamic RBAC activation | `manage_org` (org-scoped) or `platform_admin` |

### Platform Administration

Everything under `/platform/*` requires the `manage_all_orgs` permission
(the `platform_admin` role's defining grant) — this is the backend
`omnibioai-control-center`'s Admin Console proxies to for its
Organizations/Users/Roles/Audit Logs pages.

| Router | Prefix | Covers |
|---|---|---|
| `routes_platform_admin.py` | `/platform/orgs` | Cross-tenant org listing/detail |
| `routes_platform_users.py` | `/platform/users` | Cross-tenant user listing/detail/update, remote MFA reset |
| `routes_platform_roles.py` | `/platform/roles` | Platform-wide role catalog CRUD, user↔role assignment |
| `routes_platform_permissions.py` | `/platform/permissions` | Permission Registry listing + usage stats |
| `routes_platform_audit.py` | `/platform/audit-events` | Cross-tenant audit event stream |

### Roles (legacy global surface)

`routes_roles.py` (`/roles`, `/users/{user_id}/roles`) — the original,
pre-PR13 global role CRUD API, gated by `manage_roles`. Distinct from
both the platform-wide catalog (`/platform/roles`, above) and org-scoped
custom roles (`/organizations/{id}/roles`, above); all three currently
coexist. `app/rbac.py` is what actually enforces a role's permissions at
request time regardless of which of the three surfaces created it.

### MFA (Multi-Factor Authentication)

| Router | Prefix | Covers | Gate |
|---|---|---|---|
| `routes_mfa.py` | `/users/me/mfa` | TOTP enroll/verify, device list/remove, recovery-code generate/list/regenerate, login challenge | Authenticated self-service (own account only) |
| `routes_org_mfa.py` | `/orgs/{org_id}/mfa-policy` | Per-org MFA requirement CRUD + platform-admin override | `manage_sso` (org-scoped) for the policy itself; `override_mfa_policy` for the override endpoints |

Full design trail: `docs/pr11-mfa-database-foundation-discovery.md`,
`pr11-totp-enrollment-discovery.md`, `pr11-mfa-login-challenge-discovery.md`,
`pr11-mfa-org-policy-discovery.md`, `pr11-mfa-recovery-codes-discovery.md`.

### API Keys & Service Credentials

| Router | Prefix | Covers | Gate |
|---|---|---|---|
| `routes_apikeys.py` | `/orgs/{org_id}/api-keys` | Create/list/revoke an org's API keys | `manage_api_keys` (org-scoped) or `platform_admin` |
| `routes_oauth_clients.py` | `/orgs/{org_id}/oauth-clients` | Create/list/revoke an org's `client_credentials` OAuth clients | `manage_oauth_clients` (org-scoped) or `platform_admin` |
| `routes_service_identity.py` | `/service/me`, `/platform/services/{client_id}` | A service-identity token's own claims; platform-admin lookup of a registered service client | `require_service_identity()` / `manage_all_orgs` |

### Config, License & Identity

| Router | Prefix | Covers | Gate |
|---|---|---|---|
| `routes_config.py` | `/auth/config` (`GET`/`PUT`) | Platform-wide global config (LLM/cloud credentials) — the exact endpoint Control Center's Admin Console Settings page reads | `manage_config` |
| `routes_license.py` | `/license` | Validate/pull-token/generate/status/revoke | `manage_licenses` |
| `routes_identity.py` | `/me`, `/platform/users/{user_id}/identity` | The caller's own resolved identity; platform-admin lookup of another user's | self / `manage_all_orgs` |

### Login

```http
POST /auth/login
Content-Type: application/json

{"email": "user@example.com", "password": "..."}
```

```json
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "bearer"
}
```

### Validate

```http
POST /auth/validate
Content-Type: application/json

{"token": "<jwt>"}
```

```json
{
  "valid": true,
  "user_id": 1,
  "email": "user@example.com",
  "roles": ["researcher"],
  "permissions": ["workflow:run", "dataset:read"]
}
```

---

## Authentication

`omnibioai-auth` is the ecosystem's single identity provider. Every other
service delegates authentication to it rather than implementing its own —
see [Architecture Role](#architecture-role) above. It supports four ways
for a user to establish a session, all converging on the same signed-JWT
output:

### Username / password

`POST /auth/login` — `authenticate_user` verifies the password hash and
`generate_tokens` issues an access + refresh token pair (`auth_method="password"`).
If the email's domain belongs to an organization that enforces Enterprise
OIDC (see below), password login is rejected outright with a 403 pointing
at that org's SSO login — credentials are never checked for an
SSO-enforced identity.

### OAuth login

Three static, ecosystem-wide providers — **Google**, **GitHub**, **Microsoft**
(`app/core/oauth_providers.py`). `GET /auth/{provider}/login` redirects to the
provider's own authorize endpoint; `/auth/{provider}/callback` (both a
browser-redirect and an SPA-JSON variant) completes the exchange. A returning
identity already linked to an account signs straight in
(`auth_method="oauth"`); an unlinked identity whose email matches an
existing password account gets a short-lived confirmation token instead of
auto-linking (`POST /auth/link/confirm`); no match creates a new user.

### OAuth 2.1 / PKCE

Every OAuth and Enterprise OIDC authorize step uses PKCE (RFC 7636, S256
only) — `code_verifier`/`code_challenge` are generated per attempt, and the
verifier travels inside the signed, short-lived `state` JWT itself (not a
server-side session), so it survives a stateless redirect round-trip. On
this callback, the state JWT is signature/expiry/type/provider-checked
before the code exchange runs. PKCE here is defense-in-depth, not a load-bearing
boundary — this service is a confidential OAuth client holding its own
`client_secret`.

### Enterprise OIDC (organization-aware SSO)

A per-organization identity provider, distinct from the three static OAuth
providers above. `GET /auth/sso/discover?email=` lets a client check —
without revealing whether the account exists — whether an email's domain
belongs to an org with SSO configured. `GET /auth/sso/{org_slug}/login`
redirects to that org's own IdP (PKCE + an OIDC `nonce` for replay
protection, carried the same way as the OAuth flow's state token); the
callback fully validates the returned `id_token` (signature via the IdP's
own JWKS, issuer, audience, expiry, nonce — RS256/ES256 only, an explicit
algorithm-confusion guard) before trusting any claim from it. A successful
login JIT-provisions org membership and issues `auth_method="sso"` with
`idp_org_id` set. When an org sets `enforced=true` on its SSO config,
password and generic OAuth login are both blocked for that org's domains —
Enterprise OIDC becomes the only way in.

### Enterprise SAML (in progress)

A second enterprise SSO protocol, additive to — not a replacement for —
Enterprise OIDC above; `OrganizationSAMLConfig` (its own table, not a
generalization of `OrganizationSSOConfig`) is the per-org IdP
registration. `GET /auth/saml/{org_slug}/metadata` is this SP's own
metadata (entity ID, ACS URL, NameID format) for that org, independent
of whether the org has configured a SAML IdP yet — that document is what
an org admin hands to their IdP administrator *before* any config can be
created. `GET /auth/saml/{org_slug}/login` is the SP-initiated login
redirect: 404 unless the org has an `active` `OrganizationSAMLConfig`,
then redirects to that IdP's `sso_url` with a SAMLRequest and a signed,
opaque RelayState binding the resolved `organization_id`/
`organization_saml_config_id` server-side. No ACS, assertion validation,
identity linking, CRUD API, admin UI, or SLO endpoint exists yet.

### Organization-aware authentication

Every issued token carries `org_id`/`org_role` alongside the base identity
claims, resolved fresh from the database on every login *and* every
refresh (`build_user_claims`, never replayed from a stale payload). A
token predating this claim set (schema v1) simply omits these fields
rather than erroring — every consumer treats them as optional. A separate,
narrower identity exists for machine-to-machine calls: `POST /oauth/token`
issues a `client_credentials`-grant token scoped to one org, carrying no
`sub`/`email` at all, gated by its own `require_service_scope` dependency
so it can never be mistaken for a user session.

---

## Token Lifecycle

| Token | Format | TTL | Storage | Revocation |
|-------|--------|-----|---------|------------|
| **Access token** | JWT | 15 min | Not persisted (bearer, stateless) | JTI written to the Redis blacklist on logout, checked on every `/auth/validate` and every downstream `verify_token()` call |
| **Refresh token** | JWT | 7 days | MySQL (`refresh_tokens` table) | Single-use — `POST /auth/refresh` **rotates** it: the presented token is revoked and a new one issued on every call. Re-presenting an already-rotated token is treated as token-family compromise and revokes the whole family |
| **Session cookie** (`omnibioai_session`) | Same value as the current refresh token | Matches refresh TTL | Browser-held, `HttpOnly` | Cleared on `/auth/logout`; rotates in lockstep with the refresh token on every `/auth/refresh` |

**Rotation** — `rotate_refresh_token` never trusts the presented token's own
claims; it re-derives the user's current roles/org context from the
database and mints both a new access token and a new refresh token,
invalidating the one just used.

**Revocation** — two independent mechanisms, by design: refresh tokens are
revoked in MySQL (`revoked_tokens`), access tokens are blacklisted by
`jti` in Redis with a TTL matching their remaining lifetime (never longer
than 15 minutes of exposure after logout). A `policy:invalidate` Redis
pub/sub event is also published on logout so services with their own
short-lived caches (e.g. the API gateway's IAM client cache) can drop
stale entries immediately instead of waiting out their TTL.

**Redis blacklist** — the fast path every access-token verification checks
first (`assert_token_usable`, shared by `/auth/validate` and this service's
own `get_current_user`); downstream services run the identical check
locally against the same Redis instance via their own `jwt_verify.py`
(see [omnibioai-control-center](../omnibioai-control-center) and
[omnibioai-security-audit](../omnibioai-security-audit)) rather than
calling back into this service on every request.

**Logout** — `POST /auth/logout` revokes the refresh token, blacklists the
access token's `jti`, publishes the invalidation event, and clears the
session cookie — all four in one call, fail-open on any individual step
(a Redis blip must never turn "log me out" into a stuck request).

**Session cookies** — see the dedicated section below.

---

## JWT

### Current

**HS256** is the production default (`JWT_ALGORITHM=HS256`, `core/config.py`) —
every token issued today is HS256, signed with the shared `SECRET_KEY`.

### Ready

**RS256** signing, verification, and a `GET /.well-known/jwks.json` endpoint
are fully implemented and available today, but **not yet enabled** — an
operator must explicitly set `JWT_ALGORITHM=RS256` to switch issuance over:

- **RS256** — `core/jwt.py::_sign` signs with an RSA private key
  (`core/rsa_keys.py`) whenever `JWT_ALGORITHM=RS256`, stamping a `kid`
  header on every token it mints.
- **JWKS endpoint** — `GET /.well-known/jwks.json` publishes the public
  half of whatever key is configured (or, in dev/test with no key
  configured, an ephemeral process-local keypair — never safe for
  production), keyed by `kid`.
- **`kid` support** — the stable key identifier (a SHA-256 hash of the
  public key, not random) lets a verifier pick the right JWKS entry today
  and supports multi-key rotation in the future.
- **Dual verification** — `core/jwt.py::decode_token` dispatches on each
  token's own `alg` header rather than on the current `JWT_ALGORITHM`
  setting, so HS256 tokens issued before a cutover keep validating for
  their full remaining lifetime after RS256 issuance is switched on. This
  service's own verification, and the local `jwt_verify.py` modules in
  omnibioai-control-center and omnibioai-security-audit, all follow this
  same dispatch-by-header pattern (SSO Phase 2 PR15/PR16).

**Production still defaults to HS256 until an operator deliberately flips
`JWT_ALGORITHM=RS256`** — RS256 readiness does not change any token issued
by a default deployment today. See the [Deployment Notes](#deployment-notes)
in the ecosystem root README for the rollout plan.

---

## Session Cookies

Alongside the existing JSON `access_token`/`refresh_token` response body
(unchanged, still returned on every login/refresh for API clients that
read it directly), `/auth/login` and `/auth/refresh` also set a
browser-oriented session cookie:

| Attribute | Value | Why |
|-----------|-------|-----|
| Name | `omnibioai_session` | |
| Value | The current refresh token (same value the JSON body's `refresh_token` carries) | No separate session store — the cookie IS the refresh token, in a form JavaScript never has to touch |
| `HttpOnly` | Yes | Not readable by page JavaScript — mitigates token theft via XSS |
| `Secure` | Yes | Never sent over plain HTTP |
| `SameSite` | `Lax` | Sent on same-site top-level navigation and same-origin requests; blocks it from being attached to cross-site POSTs |
| `Domain` | `.omnibioai.org` (configurable via `SESSION_COOKIE_DOMAIN`) | Shared across every first-party subdomain — `webstudio.`, `control.`, etc. — without any token ever passing through frontend JS |

**How browsers refresh sessions** — a browser holding only this cookie (no
token in `localStorage`/JS memory at all) can still call `POST /auth/refresh`
with an empty body: the endpoint falls back to the cookie when the request
body omits `refresh_token`, rotates it, and re-sets the cookie on the
response. Frontends that proxy this call through their own backend (e.g.
Control Center's `routes_auth_proxy.py`) must relay the `Cookie` request
header upstream and the `Set-Cookie` response header back downstream —
each hop is an independent HTTP request that doesn't forward cookies
automatically.

---

## Authentication Architecture Diagram

```
Browser
   │
   ▼
Auth Service (omnibioai-auth)
   │
   ├──▶ JWT              access_token (15 min) + refresh_token (7 days),
   │                      returned in the JSON response body
   │
   ├──▶ Refresh Cookie    omnibioai_session (HttpOnly, Secure, SameSite=Lax,
   │                      Domain=.omnibioai.org) — same value as refresh_token
   │
   └──▶ JWKS              GET /.well-known/jwks.json — RS256 public key set,
                           ready for downstream RS256 verification once
                           JWT_ALGORITHM=RS256 is enabled
```

---

## RBAC

Roles and permissions are DB-backed (fully dynamic, CRUD-managed — not a
fixed enum), embedded in the JWT payload at issuance, and enforced by
`app/rbac.py` via FastAPI dependency injection. Seeded roles:

| Role | Scope | Key permissions |
|------|-------|------------------|
| `user` | Global | Default role on signup |
| `admin` | Global | `manage_roles`, `manage_licenses`, `manage_config`, `override_sso_enforcement` |
| `platform_admin` | Global, cross-tenant | `manage_all_orgs` — the only role that bypasses per-org isolation |
| `org_admin` | Per-organization | `manage_org`, `manage_teams`, `manage_api_keys`, `manage_oauth_clients`, `manage_sso` |
| `org_member` | Per-organization | Baseline organization membership |

Downstream services that can't reach the database to resolve a permission
from a role name (e.g. omnibioai-control-center, omnibioai-security-audit)
check for the specific seeded role name on the JWT instead (`admin`,
`platform_admin`) — see each service's own README.

### Beyond the 5 seeded roles: three role-CRUD surfaces

The table above is the seeded baseline, not the whole story — **PR13**
("dynamic permission assignment and enterprise RBAC activation," `main`'s
tip commit) activated org-scoped custom roles on top of it. Three separate
role-management APIs currently coexist (see
[Roles & Permissions](#roles-legacy-global-surface) /
[Organizations & Teams](#organizations--teams) above for their endpoints):

1. **`/roles`** (`routes_roles.py`) — the original global role catalog, `manage_roles`-gated.
2. **`/platform/roles`** (`routes_platform_roles.py`) — the platform-wide catalog surfaced to `omnibioai-control-center`'s Admin Console, `manage_all_orgs`-gated.
3. **`/organizations/{id}/roles`** (`routes_organization_roles.py`) — org-scoped custom roles an `org_admin` (or platform admin) can define per-organization, on top of the seeded `org_admin`/`org_member` baseline.

`app/rbac.py`'s enforcement doesn't care which of the three created a
role — a role's `permissions` array on the JWT is checked the same way
regardless of origin. `assert_no_unregistered_permissions` (`app/main.py`
startup, `app/services/role_service.py`) fails startup loud if any
`Permission` row in the database has drifted out of sync with
`app/core/permission_names.py`'s registry — the single source of truth
for every permission name across all three surfaces. See
`test_pr13_role_catalog_crud.py`, `test_pr13_role_org_scope.py`, and
`test_pr13_escalation_guards.py` for the guarantees this activation adds
(an org admin cannot escalate a custom role beyond what the assigning
admin's own permissions already allow).

---

## Running in the Stack

This service is not intended to run in isolation. Start it via the top-level
`docker-compose.yml` in the `machine/` monorepo:

```bash
docker compose up omnibioai-auth
```

The service depends on `mysql` and `redis` compose services being healthy
before it starts. An admin user is bootstrapped automatically on first startup.

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_USER` | — | MySQL username |
| `DB_PASSWORD` | — | MySQL password |
| `DB_HOST` | `localhost` | MySQL host (use `mysql` inside compose) |
| `DB_PORT` | `3306` | MySQL port |
| `DB_NAME` | `omnibioai` | Database name |
| `SECRET_KEY` | — | HS256 JWT signing secret (required) |
| `JWT_ALGORITHM` | `HS256` | Signing algorithm for *newly issued* tokens. Verification always accepts both regardless of this setting — see [JWT](#jwt) |
| `JWT_PRIVATE_KEY` / `JWT_PUBLIC_KEY` | *(generated)* | PEM-encoded RSA keypair for RS256 signing + JWKS. Unset in dev/test generates an ephemeral, process-local keypair — never safe for production |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `15` | Access token lifetime |
| `REFRESH_TOKEN_EXPIRE_DAYS` | `7` | Refresh token lifetime |
| `SESSION_COOKIE_DOMAIN` | `.omnibioai.org` | `Domain` attribute on the `omnibioai_session` cookie |
| `GOOGLE_OAUTH_CLIENT_ID` / `_SECRET` | — | Google OAuth login; unset disables that provider (503) |
| `GITHUB_OAUTH_CLIENT_ID` / `_SECRET` | — | GitHub OAuth login; unset disables that provider (503) |
| `MICROSOFT_OAUTH_CLIENT_ID` / `_SECRET` | — | Microsoft OAuth login; unset disables that provider (503) |
| `OAUTH_REDIRECT_BASE_URL` | `https://webstudio.omnibioai.org` | Must match each provider's registered redirect URI |
| `FRONTEND_BASE_URL` | `https://webstudio.omnibioai.org` | Where the browser lands after an OAuth/SSO callback completes |
| `REQUIRE_HTTPS_FOR_SSO_ISSUER` | `true` | Require HTTPS for an org's configured Enterprise OIDC issuer URL |
| `REDIS_URL` | `redis://redis:6379` | Redis connection URL (jti blacklist, `policy:invalidate` pub/sub) |

---

## Project Structure

```
app/
├── main.py                  # FastAPI entrypoint — registers all 24 routers, admin
│                             # bootstrap, Permission Registry drift check at startup,
│                             # /metrics, /health
├── rbac.py                  # Role + permission dependency helpers (require_permission,
│                             # require_org_permission_or_platform_admin, ...)
├── api/
│   ├── routes_auth.py            # /auth/register, /login, /refresh, /logout, /validate
│   ├── routes_oauth.py           # /auth/{provider}/login, /callback, /link/confirm
│   ├── routes_oauth_token.py     # /oauth/token (client_credentials grant)
│   ├── routes_sso.py             # /auth/sso/discover, /{org_slug}/login, /{org_slug}/callback
│   ├── routes_org_sso.py         # /orgs/{org_id}/sso config CRUD + override
│   ├── routes_saml.py            # /auth/saml/{org_slug}/metadata, /login -- no ACS yet
│   ├── routes_jwks.py            # /.well-known/jwks.json
│   ├── routes_orgs.py            # /orgs — org CRUD, invite, member roles
│   ├── routes_teams.py           # /orgs/{org_id}/teams
│   ├── routes_organization_roles.py  # /organizations/{id}/roles, /permissions, /members
│   ├── routes_roles.py           # /roles — legacy global role catalog
│   ├── routes_mfa.py             # /users/me/mfa — TOTP, devices, recovery codes, challenge
│   ├── routes_org_mfa.py         # /orgs/{org_id}/mfa-policy
│   ├── routes_apikeys.py         # /orgs/{org_id}/api-keys
│   ├── routes_oauth_clients.py   # /orgs/{org_id}/oauth-clients
│   ├── routes_service_identity.py # /service/me, /platform/services/{client_id}
│   ├── routes_config.py          # /auth/config
│   ├── routes_license.py         # /license/*
│   ├── routes_identity.py        # /me, /platform/users/{id}/identity
│   ├── routes_platform_admin.py       # /platform/orgs
│   ├── routes_platform_users.py       # /platform/users
│   ├── routes_platform_roles.py       # /platform/roles
│   ├── routes_platform_permissions.py # /platform/permissions
│   ├── routes_platform_audit.py       # /platform/audit-events
│   ├── deps.py               # Shared FastAPI dependencies
│   └── services/
│       └── token_service.py  # Shared token-issuance helper used by multiple routers
├── core/
│   ├── config.py             # Settings from environment
│   ├── jwt.py                 # Token creation, decoding, dual HS256/RS256 dispatch
│   ├── security.py           # Password hashing
│   ├── crypto.py             # Low-level crypto helpers
│   ├── oauth_providers.py    # Google/GitHub/Microsoft provider config
│   ├── permission_names.py   # Permission Registry — single source of truth for every
│   │                          # permission name (PR4)
│   ├── rsa_keys.py           # RS256 keypair loading / ephemeral dev-key generation
│   └── token_revocation.py   # Redis jti-blacklist + refresh-token-family revocation
├── db/
│   ├── models.py              # User, RefreshToken, RevokedToken, Org, Role, ... models
│   ├── session.py             # SQLAlchemy engine + session factory
│   ├── base.py                 # Declarative base
│   ├── init_admin.py           # Admin user bootstrap
│   └── schema_guard.py         # Startup schema-verification guard (main's latest
│                                # commit — see "fix(auth): add schema guard and
│                                # startup regression tests")
├── services/
│   ├── auth_service.py        # authenticate, generate_tokens, revoke_token
│   ├── user_service.py        # User CRUD helpers
│   ├── user_admin_service.py  # Platform-admin user management
│   ├── service_tokens.py      # Service-to-service token helpers
│   ├── service_identity.py    # Service-identity resolution
│   ├── org_service.py         # Organization CRUD
│   ├── team_service.py        # Team CRUD/membership
│   ├── role_service.py        # Role CRUD across all 3 role surfaces + registry drift check
│   ├── org_sso_service.py     # Org SSO config CRUD
│   ├── org_oidc_service.py    # Enterprise OIDC login flow
│   ├── sso_discovery_service.py # Domain → org SSO lookup
│   ├── mfa_service.py         # TOTP/recovery-code logic
│   ├── apikey_service.py      # API key issuance/revocation
│   ├── oauth_client_service.py # OAuth client_credentials client management
│   ├── oauth_service.py       # OAuth 2.1/PKCE provider login flow
│   ├── platform_admin_service.py # Cross-tenant platform-admin queries
│   ├── audit_service.py       # Audit event recording/query
│   ├── config_service.py      # Global config get/set
│   ├── identity_service.py    # Identity resolution
│   └── license_service.py     # License validate/generate/status/revoke
└── schemas/
    ├── auth.py, user.py, orgs.py, teams.py, roles.py, organization_roles.py,
    ├── mfa.py, org_mfa.py, apikeys.py, oauth.py, oauth_client.py,
    ├── service_identity.py, config.py, license.py, identity.py,
    └── permissions.py, platform_admin.py, role_admin.py, user_admin.py, org_sso.py
        # Pydantic request/response models, one module per feature area above
```

---

## Tests

```bash
pytest tests/
```

**701 tests** across 52 files (`pytest --collect-only`). Core coverage —
auth flows (`test_auth.py`), RBAC (`test_rbac.py`), security primitives
(`test_security.py`), health check (`test_health.py`) — plus dedicated
suites per feature area:

| Area | Files |
|---|---|
| MFA | `test_mfa.py`, `test_mfa_login_challenge.py`, `test_mfa_org_policy.py`, `test_mfa_recovery_codes.py` |
| SSO / Enterprise OIDC | `test_sso_login.py`, `test_sso_enforcement.py`, `test_org_sso.py`, `test_pkce.py` |
| OAuth | `test_oauth.py`, `test_oauth_clients.py`, `test_oauth_token.py` |
| Organizations, teams, roles | `test_orgs.py`, `test_teams.py`, `test_roles.py`, `test_organization_role_assignment_api.py` |
| PR13 (dynamic RBAC activation) | `test_pr13_role_catalog_crud.py`, `test_pr13_role_org_scope.py`, `test_pr13_escalation_guards.py`, `test_pr13_jwt_permission_merge.py` |
| Platform administration | `test_platform_admin.py`, `test_platform_admin_api.py`, `test_platform_users_api.py`, `test_platform_roles_api.py`, `test_platform_role_detail_api.py`, `test_platform_permissions_api.py` |
| Audit | `test_audit_ledger.py`, `test_pr11_identity_audit.py` |
| JWT / tokens | `test_jwt_iss_aud.py`, `test_jwt_org_context.py`, `test_rs256_jwks.py`, `test_refresh_rotation.py`, `test_token_revocation.py`, `test_session_cookie.py` |
| API keys / service identity | `test_apikeys.py`, `test_service_identity_api.py` |
| License | `test_license.py`, `test_legacy_license_import.py` |
| Config | `test_config.py` |
| Authorization hardening | `test_idor_org_scoping.py`, `test_permission_registry.py`, `test_registry_drift_detection.py`, `test_route_authorization_coverage.py` |
| Schema / startup / migrations | `test_schema_guard.py`, `test_startup_smoke.py`, `test_migrations.py`, `test_admin_bootstrap_schema_regression.py`, `test_backfill_default_org.py` |
| Identity | `test_identity_api.py` |
| PR12 (enterprise auth flow) | `test_pr12_auth_flow.py` |

MFA design trail and other feature-specific audits live in `docs/`
(`pr11-mfa-*.md`); deployment and migration procedure in
`docs/DEPLOYMENT_CHECKLIST.md` and `docs/MIGRATIONS.md`.
