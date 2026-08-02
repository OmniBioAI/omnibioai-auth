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
| `POST` | `/oauth/token` | `client_credentials` grant — issues a service-identity access token |
| `GET`/`POST`/`DELETE` | `/orgs/{org_id}/oauth-clients` | Manage an organization's `client_credentials` clients |
| `GET`  | `/.well-known/jwks.json` | RS256 public-key set (JWKS), for future RS256 verifiers |
| `GET`  | `/health` | Liveness check — returns `{"status": "ok"}` |
| `GET`  | `/metrics` | Prometheus metrics (jwt_auth_total counter) |

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
├── main.py                  # FastAPI entrypoint, admin bootstrap, /metrics, /health
├── rbac.py                  # Role + permission dependency helpers
├── api/
│   ├── routes_auth.py       # Auth endpoints + Redis blacklist logic
│   └── deps.py              # Shared FastAPI dependencies
├── core/
│   ├── config.py            # Settings from environment
│   ├── jwt.py               # Token creation and decoding
│   └── security.py          # Password hashing
├── db/
│   ├── models.py            # User, RefreshToken, RevokedToken models
│   ├── session.py           # SQLAlchemy engine + session factory
│   ├── base.py              # Declarative base
│   └── init_admin.py        # Admin user bootstrap
├── services/
│   ├── auth_service.py      # authenticate, generate_tokens, revoke_token
│   ├── user_service.py      # User CRUD helpers
│   └── service_tokens.py    # Service-to-service token helpers
└── schemas/
    ├── auth.py              # LoginRequest, RefreshRequest, LogoutRequest
    └── user.py              # User response schemas
```

---

## Tests

```bash
pytest tests/
```

Coverage targets: auth flows (`test_auth.py`), RBAC (`test_rbac.py`),
security primitives (`test_security.py`), health check (`test_health.py`).
