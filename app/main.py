"""
OmniBioAI app.main.

Purpose:
    Defines HTTP route handlers for app.main, including metrics and health.

Author:
    Manish Kumar <manish@omnibioai.org>
"""

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.routes_auth import router as auth_router
from app.api.routes_roles import router as roles_router
from app.api.routes_oauth import router as oauth_router
from app.api.routes_license import router as license_router
from app.api.routes_platform_licenses import router as platform_licenses_router
from app.api.routes_config import router as config_router
from app.api.routes_orgs import router as orgs_router
from app.api.routes_teams import router as teams_router
from app.api.routes_apikeys import router as apikeys_router
from app.api.routes_apikeys import exchange_router as apikeys_exchange_router
from app.api.routes_apikeys import me_router as apikeys_me_router
from app.api.routes_organization_config import router as provider_keys_router
from app.api.routes_organization_config import reveal_router as provider_key_reveal_router
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
from app.api.routes_preferences import router as preferences_router
from app.api.routes_service_identity import router as service_identity_router
from app.api.routes_service_mint import router as service_mint_router
from app.api.routes_delegated_execution import router as delegated_execution_router
from app.api.routes_jwks import router as jwks_router
from app.api.routes_mfa import router as mfa_router
from app.api.routes_org_mfa import router as org_mfa_router
from app.api.routes_sessions import router as sessions_router
from app.api.routes_platform_interactions import router as platform_interactions_router
from app.api.routes_integration_credentials import router as integration_credentials_router
from app.api.routes_integration_credentials import internal_router as integration_credentials_internal_router
from app.db.base import Base
from app.db.session import engine
from app.db.session import SessionLocal
from app.db.startup_schema import prepare_startup_schema
from app.db.init_admin import (
    create_admin,
    ensure_bio_agent_service_role,
    ensure_default_organization,
    ensure_dev_test_personas,
    ensure_platform_admin_role,
    ensure_platform_owner,
)
from app.services.org_service import ensure_default_org_roles, ensure_org_admin_permissions
from app.services.role_service import assert_no_unregistered_permissions
from app.core.config import settings

import app.db.models

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Validate the migrated schema before bootstrap and serve traffic."""
    prepare_startup_schema(
        engine,
        Base.metadata,
        app_env=settings.APP_ENV,
        mode=settings.AUTH_STARTUP_SCHEMA_MODE,
        script_location=Path(__file__).resolve().parent.parent / "alembic",
    )

    db = SessionLocal()
    try:
        create_admin(db)
        ensure_platform_admin_role(db)
        ensure_platform_owner(db)
        ensure_bio_agent_service_role(db)
        ensure_default_organization(db)
        ensure_org_admin_permissions(db)
        ensure_default_org_roles(db)
        ensure_dev_test_personas(db)
        assert_no_unregistered_permissions(db)
    finally:
        db.close()
    yield


app = FastAPI(title="OmniBioAI Auth Service", root_path="/_svc/auth", lifespan=lifespan)

# Electron itself runs with webSecurity disabled and ignores CORS entirely;
# this only matters for the web build, so the allowlist is scoped to known
# Studio web origins rather than left wide open.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(roles_router)
app.include_router(oauth_router)
app.include_router(license_router)
app.include_router(platform_licenses_router)
app.include_router(config_router)
app.include_router(orgs_router)
app.include_router(teams_router)
app.include_router(apikeys_router)
app.include_router(apikeys_exchange_router)
app.include_router(apikeys_me_router)
app.include_router(provider_keys_router)
app.include_router(provider_key_reveal_router)
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
app.include_router(preferences_router)
app.include_router(service_identity_router)
app.include_router(service_mint_router)
app.include_router(delegated_execution_router)
app.include_router(jwks_router)
app.include_router(mfa_router)
app.include_router(org_mfa_router)
app.include_router(sessions_router)
app.include_router(platform_interactions_router)
app.include_router(integration_credentials_router)
app.include_router(integration_credentials_internal_router)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
def health():
    return {"status": "ok"}
