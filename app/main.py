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
from app.api.routes_sso import router as sso_router
from app.api.routes_saml import router as saml_router
from app.api.routes_org_saml import router as org_saml_router
from app.api.routes_platform_admin import router as platform_admin_router
from app.api.routes_platform_users import router as platform_users_router
from app.api.routes_platform_roles import router as platform_roles_router
from app.api.routes_platform_permissions import router as platform_permissions_router
from app.api.routes_platform_audit import router as platform_audit_router
from app.api.routes_organization_roles import router as organization_roles_router
from app.api.routes_identity import router as identity_router
from app.api.routes_service_identity import router as service_identity_router
from app.api.routes_jwks import router as jwks_router
from app.api.routes_mfa import router as mfa_router
from app.api.routes_org_mfa import router as org_mfa_router
from app.api.routes_sessions import router as sessions_router
from app.api.routes_platform_interactions import router as platform_interactions_router
from app.db.base import Base
from app.db.session import engine
from app.db.session import SessionLocal
from app.db.schema_guard import assert_schema_matches_models
from app.db.init_admin import (
    create_admin,
    ensure_default_organization,
    ensure_platform_admin_role,
    ensure_platform_owner,
)
from app.services.org_service import ensure_default_org_roles, ensure_org_admin_permissions
from app.services.role_service import assert_no_unregistered_permissions
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

# create_all() above only ever creates tables that don't exist yet -- it
# never alters an existing table, so a database that's behind on Alembic
# migrations (see docs/MIGRATIONS.md) sails through it unnoticed and then
# crashes on whatever bootstrap query below happens to touch the missing
# column first. Catch that here, once, with an actionable message instead.
assert_schema_matches_models(engine, Base.metadata)

# bootstrap admin
db = SessionLocal()
create_admin(db)
ensure_platform_admin_role(db)
# Opt-in only -- a no-op unless the operator has set PLATFORM_OWNER_EMAIL.
# Must run after ensure_platform_admin_role (needs the Role to exist) and
# after create_admin (in case the designated owner IS the bootstrap admin
# account created just above). See ensure_platform_owner's own docstring.
ensure_platform_owner(db)
ensure_default_organization(db)
ensure_org_admin_permissions(db)
ensure_default_org_roles(db)
# PR6: registry/database drift is a deployment error -- fail startup
# loudly rather than serve traffic against a Permission row the registry
# doesn't know about. Runs once, here, never per-request.
assert_no_unregistered_permissions(db)
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
app.include_router(sso_router)
app.include_router(saml_router)
app.include_router(org_saml_router)
app.include_router(platform_admin_router)
app.include_router(platform_users_router)
app.include_router(platform_roles_router)
app.include_router(platform_permissions_router)
app.include_router(platform_audit_router)
app.include_router(organization_roles_router)
app.include_router(identity_router)
app.include_router(service_identity_router)
app.include_router(jwks_router)
app.include_router(mfa_router)
app.include_router(org_mfa_router)
app.include_router(sessions_router)
app.include_router(platform_interactions_router)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
def health():
    return {"status": "ok"}