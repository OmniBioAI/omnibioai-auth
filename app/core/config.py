import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    DB_USER = os.getenv("DB_USER")
    DB_PASSWORD = os.getenv("DB_PASSWORD")
    DB_HOST = os.getenv("DB_HOST", "localhost")
    DB_PORT = os.getenv("DB_PORT", "3306")
    DB_NAME = os.getenv("DB_NAME", "omnibioai")

    SECRET_KEY = os.getenv("SECRET_KEY")
    ALGORITHM = "HS256"

    # SSO Phase 2 PR15: which algorithm *newly issued* tokens are signed
    # with. Defaults to HS256 so existing deployments see zero behavior
    # change unless an operator explicitly opts in. Verification (see
    # core/jwt.py::decode_token) always accepts both HS256 and RS256
    # regardless of this setting -- it inspects each token's own `alg`
    # header rather than trusting this value, since already-issued HS256
    # tokens must keep validating through and past any switch to RS256.
    JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

    # PEM-encoded RSA keypair for RS256 signing/verification and the
    # GET /.well-known/jwks.json endpoint. Both unset -> core/rsa_keys.py
    # generates an ephemeral, process-local keypair (dev/test only; see
    # that module's docstring for why it's unsafe in production). Only
    # JWT_PRIVATE_KEY is strictly required to sign+verify locally, but an
    # operator should set both: JWT_PUBLIC_KEY is what a *different*
    # service would eventually fetch/pin instead of deriving it from the
    # private key, and setting it explicitly here keeps the two in sync
    # with whatever's actually deployed.
    JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "")
    JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", "")

    # PR12: iss/aud claims identifying this service as the token issuer and
    # the platform as the intended audience. Verified opportunistically (see
    # core/jwt.py::decode_token) -- present-and-mismatched is always
    # rejected, but a token that predates this claim entirely (issued
    # before a rolling deploy of this change, or a synthetic test token)
    # still validates, same migration-window philosophy as JWT_ALGORITHM
    # above.
    JWT_ISSUER = os.getenv("JWT_ISSUER", "omnibioai-auth")
    JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "omnibioai-platform")

    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

    # Phase 2 PR1: client_credentials-grant tokens are a service identity,
    # not a user session -- kept shorter-lived than a normal access token
    # since there's no refresh_token to fall back on (RFC 6749 SS4.4.3); a
    # compromised one self-expires quickly rather than lingering for the
    # full 15 minutes a user access token gets.
    CLIENT_CREDENTIALS_TOKEN_EXPIRE_MINUTES = int(
        os.getenv("CLIENT_CREDENTIALS_TOKEN_EXPIRE_MINUTES", 10)
    )

    # Phase 2 PR3: an org admin's issuer URL is untrusted input this
    # service makes a real HTTP request to (OIDC discovery) -- require
    # HTTPS by default. Only reason to ever set this false is standing up
    # a local/self-hosted test IdP without TLS during development; real
    # deployments should never override it.
    REQUIRE_HTTPS_FOR_SSO_ISSUER = os.getenv("REQUIRE_HTTPS_FOR_SSO_ISSUER", "true").lower() == "true"

    # Comma-separated allowlist of browser origins permitted to call this API
    # directly (e.g. omnibioai-studio's web build). Production domains match
    # the CORS_ALLOWED_ORIGINS already set for the lims service in
    # docker-compose.yml; localhost:5174 covers the Vite dev server.
    CORS_ALLOWED_ORIGINS = [
        origin.strip()
        for origin in os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:5174,http://127.0.0.1:5174,"
            "https://webstudio.omnibioai.org,https://app.omnibioai.org,https://lims.omnibioai.org,https://omnibioai.org",
        ).split(",")
        if origin.strip()
    ]

    # OAuth2 SSO — optional. Empty defaults mean the stack starts fine with
    # SSO unconfigured; /auth/{provider}/login returns 503 until a client
    # id/secret pair is set for that provider.
    GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
    GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
    GITHUB_OAUTH_CLIENT_ID = os.getenv("GITHUB_OAUTH_CLIENT_ID", "")
    GITHUB_OAUTH_CLIENT_SECRET = os.getenv("GITHUB_OAUTH_CLIENT_SECRET", "")
    MICROSOFT_OAUTH_CLIENT_ID = os.getenv("MICROSOFT_OAUTH_CLIENT_ID", "")
    MICROSOFT_OAUTH_CLIENT_SECRET = os.getenv("MICROSOFT_OAUTH_CLIENT_SECRET", "")

    # Must exactly match the redirect URIs registered with each provider.
    OAUTH_REDIRECT_BASE_URL = os.getenv("OAUTH_REDIRECT_BASE_URL", "https://webstudio.omnibioai.org")
    # Where the browser is sent after GET /auth/{provider}/callback completes
    # (carries the token, or a link-confirmation prompt, as query params).
    FRONTEND_BASE_URL = os.getenv("FRONTEND_BASE_URL", "https://webstudio.omnibioai.org")

    # GHCR credential returned by /license/pull-token to a licensed Electron
    # client right before it `docker pull`s a private image -- same secret
    # the now-decommissioned license_server.py exposed (Phase 1 PR4 cutover).
    GHCR_PULL_TOKEN = os.getenv("GHCR_PULL_TOKEN", "")

    # HIPAA Phase 1 PR1: local-password login brute-force protection
    # (app/core/rate_limit.py, app/services/login_throttle_service.py).
    # Three independently-tunable layers -- account, source IP, and the
    # (account, IP) pair -- see login_throttle_service.py's module
    # docstring for why all three exist and what each defends against.
    # Every _MAX_ATTEMPTS/_WINDOW_SECONDS/_LOCKOUT_SECONDS default below
    # is a production-safe starting point, not a hard requirement --
    # operators tune via env var, no code change or redeploy needed
    # (this Settings class already re-reads os.getenv on process start,
    # same as every other setting here).
    RATE_LIMIT_ENABLED = os.getenv("RATE_LIMIT_ENABLED", "true").lower() == "true"

    # Account dimension: keyed on a truncated SHA-256 of the submitted
    # email (not the raw address -- consistent with this module's own
    # "don't retain unnecessary account-identifying data" requirement,
    # and with the existing _hash_refresh_token/_hash_key convention
    # elsewhere in this service). Primary defense against an attacker
    # who varies source IP but targets one account.
    RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_ACCOUNT_MAX_ATTEMPTS", 10))
    RATE_LIMIT_ACCOUNT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_ACCOUNT_WINDOW_SECONDS", 900))
    RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS = int(os.getenv("RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS", 900))

    # IP dimension: keyed on source IP. Primary defense against an
    # attacker who varies the account (credential stuffing / spraying)
    # but attacks from one IP. Threshold is deliberately higher than the
    # account dimension -- a shared/corporate/NAT IP can legitimately
    # produce more failed attempts across many real users than one
    # account ever should.
    RATE_LIMIT_IP_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_IP_MAX_ATTEMPTS", 30))
    RATE_LIMIT_IP_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_IP_WINDOW_SECONDS", 900))
    RATE_LIMIT_IP_LOCKOUT_SECONDS = int(os.getenv("RATE_LIMIT_IP_LOCKOUT_SECONDS", 900))

    # (account, IP) pair dimension: the tight, fast circuit-breaker for
    # the common case -- one attacker hammering one account. Neither
    # varying the email nor varying the IP alone resets this key, since
    # it's the *combination* that's tracked; changing either one starts
    # a fresh pair-key, but the unchanged dimension keeps accumulating
    # against its own (account or IP) counter above.
    RATE_LIMIT_PAIR_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_PAIR_MAX_ATTEMPTS", 5))
    RATE_LIMIT_PAIR_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_PAIR_WINDOW_SECONDS", 300))
    RATE_LIMIT_PAIR_LOCKOUT_SECONDS = int(os.getenv("RATE_LIMIT_PAIR_LOCKOUT_SECONDS", 300))

    # Progressive escalation, account dimension only: each time the same
    # account's lockout is re-triggered before its "strike" window
    # expires, the lockout duration actually applied is
    # RATE_LIMIT_ACCOUNT_LOCKOUT_SECONDS * (multiplier ** (strikes-1)),
    # capped at RATE_LIMIT_MAX_LOCKOUT_SECONDS. A legitimate user who
    # mistypes their password a few times, once, is unaffected -- this
    # only escalates for an account still under repeated attack across
    # multiple lockout cycles.
    RATE_LIMIT_PROGRESSIVE_MULTIPLIER = int(os.getenv("RATE_LIMIT_PROGRESSIVE_MULTIPLIER", 2))
    RATE_LIMIT_MAX_LOCKOUT_SECONDS = int(os.getenv("RATE_LIMIT_MAX_LOCKOUT_SECONDS", 3600))
    RATE_LIMIT_STRIKE_TTL_SECONDS = int(os.getenv("RATE_LIMIT_STRIKE_TTL_SECONDS", 86400))

    # Redis-unavailable behavior (app/core/rate_limit.py). Deliberately
    # NOT the same fail-open policy this service's token-revocation
    # blacklist uses (see token_revocation.py's own docstring) -- that
    # precedent is for a check that runs on every authenticated request;
    # this one exists specifically to stop credential-guessing, so
    # failing fully open on a Redis outage would silently disable the
    # control for the exact scenario (sustained attack traffic that
    # might itself be straining shared infra) it matters most in. Nor is
    # it fully closed -- see RATE_LIMIT_FALLBACK_* below -- since that
    # would make a Redis outage a total login outage, turning an
    # availability problem into an authentication one.
    RATE_LIMIT_FALLBACK_MAX_ATTEMPTS = int(os.getenv("RATE_LIMIT_FALLBACK_MAX_ATTEMPTS", 5))
    RATE_LIMIT_FALLBACK_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_FALLBACK_WINDOW_SECONDS", 300))
    # Hard cap on the number of distinct keys the in-process fallback
    # counter will track -- bounds its memory use during a prolonged
    # Redis outage under attack traffic. Deliberately small: this path
    # is degraded-mode-only, not the steady-state mechanism.
    RATE_LIMIT_FALLBACK_MAX_KEYS = int(os.getenv("RATE_LIMIT_FALLBACK_MAX_KEYS", 10000))

    # HIPAA Phase 1 PR2: local-password security policy
    # (app/core/password_policy.py). Applies only to POST /auth/register --
    # the only user-facing local-password-creation endpoint this service
    # has (see that module's docstring for the full discovery). Length is
    # the primary lever, not character-class rules -- see PR2's own
    # security-policy discussion for why complexity requirements are
    # deliberately not implemented.
    PASSWORD_MIN_LENGTH = int(os.getenv("PASSWORD_MIN_LENGTH", 12))
    # Generous, not a real strength constraint -- exists only to reject a
    # pathological input (e.g. someone submitting megabytes of text) before
    # it reaches bcrypt/the compromised-password check at all. Comfortably
    # above any real passphrase; not the reason long passwords are safe now
    # (see security.py's bcrypt_sha256 switch for that).
    PASSWORD_MAX_LENGTH = int(os.getenv("PASSWORD_MAX_LENGTH", 128))

    # Compromised-password checking (app/core/compromised_password.py) --
    # the Have I Been Pwned "Pwned Passwords" k-anonymity API. Only a
    # 5-character SHA-1 prefix of the password ever leaves this service;
    # see that module's docstring for the full privacy mechanism.
    PASSWORD_COMPROMISE_CHECK_ENABLED = os.getenv("PASSWORD_COMPROMISE_CHECK_ENABLED", "true").lower() == "true"
    PASSWORD_COMPROMISE_CHECK_TIMEOUT_SECONDS = float(
        os.getenv("PASSWORD_COMPROMISE_CHECK_TIMEOUT_SECONDS", 3.0)
    )
    # Deliberately NOT the default "reject registration until we can prove
    # it's clean" -- registration is a low-frequency, non-critical-path
    # operation for THIS service, but making it hard-dependent on a third
    # party's uptime introduces a new single point of failure for a brand
    # new user's very first interaction with the product, which this PR's
    # own guidance ("do not make password creation dependent on an
    # unreliable external service without an explicit policy") reads as
    # something to avoid defaulting into. The local length/blocklist
    # checks above always run regardless of this setting or provider
    # health -- this only controls the network-dependent check specifically.
    # An operator who prefers strict fail-closed behavior can set this true;
    # every skipped check is still counted in the
    # password_compromise_check_errors_total metric either way, never silent.
    PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED = (
        os.getenv("PASSWORD_COMPROMISE_CHECK_FAIL_CLOSED", "false").lower() == "true"
    )

    @property
    def DATABASE_URL(self):
        return (
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

settings = Settings()