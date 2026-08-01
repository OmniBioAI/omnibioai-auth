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

    ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
    REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

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