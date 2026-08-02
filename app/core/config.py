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

    @property
    def DATABASE_URL(self):
        return (
            f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}"
            f"@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        )

settings = Settings()