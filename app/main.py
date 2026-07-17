from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

from app.api.routes_auth import router as auth_router
from app.api.routes_roles import router as roles_router
from app.db.base import Base
from app.db.session import engine
from app.db.session import SessionLocal
from app.db.init_admin import create_admin
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
db.close()

app.include_router(auth_router)
app.include_router(roles_router)


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/health")
def health():
    return {"status": "ok"}