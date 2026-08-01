from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.routes_auth import router as auth_router
from app.api.routes_roles import router as roles_router
from app.api.routes_oauth import router as oauth_router
from app.api.routes_license import router as license_router
from app.api.routes_config import router as config_router
from app.api.routes_orgs import router as orgs_router
from app.api.routes_teams import router as teams_router
from app.api.routes_apikeys import router as apikeys_router
from app.api.routes_oauth_clients import router as oauth_clients_router
from app.api.routes_oauth_token import router as oauth_token_router
from app.api.routes_org_sso import router as org_sso_router
from app.db.base import Base
from app.db.session import engine
from app.db.session import SessionLocal
from app.db.init_admin import create_admin, ensure_default_organization
from app.services.org_service import ensure_org_admin_permissions
from app.core.config import settings

import app.db.models

app = FastAPI(title="OmniBioAI Auth Service")

# Electron itself runs with webSecurity disabled and ignores CORS entirely;
# this only matters for the web build, so the allowlist is scoped to known
# Studio web origins rather than left wide open.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# bootstrap admin
db = SessionLocal()
create_admin(db)
ensure_default_organization(db)
ensure_org_admin_permissions(db)
db.close()

app.include_router(auth_router)
app.include_router(roles_router)
app.include_router(oauth_router)
app.include_router(license_router)
app.include_router(config_router)
app.include_router(orgs_router)
app.include_router(teams_router)
app.include_router(apikeys_router)
app.include_router(oauth_clients_router)
app.include_router(oauth_token_router)
app.include_router(org_sso_router)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
def health():
    return {"status": "ok"}