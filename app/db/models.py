from sqlalchemy import Column, Integer, String, ForeignKey, Table, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db.base import Base
from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, JSON
from app.db.base import Base

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    token = Column(String(500), unique=True, index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)

user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)

role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column("role_id", Integer, ForeignKey("roles.id")),
    Column("permission_id", Integer, ForeignKey("permissions.id")),
)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True)
    hashed_password = Column(String(255))
    status = Column(String(50), default="active")

    roles = relationship("Role", secondary=user_roles, back_populates="users")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True)

    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions)


class Permission(Base):
    __tablename__ = "permissions"

    id = Column(Integer, primary_key=True)
    name = Column(String(100), unique=True)

class RevokedToken(Base):
    __tablename__ = "revoked_tokens"

    id = Column(Integer, primary_key=True)
    token_jti = Column(String(255), unique=True, index=True)
    revoked_at = Column(DateTime, default=datetime.utcnow)


class OAuthAccount(Base):
    __tablename__ = "oauth_accounts"
    __table_args__ = (
        UniqueConstraint("provider", "provider_user_id", name="uq_oauth_provider_account"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String(20), nullable=False)  # "google" | "github" | "microsoft"
    provider_user_id = Column(String(255), nullable=False)
    email = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")


class GlobalConfig(Base):
    """Singleton row (id=1 by convention -- see config_service.get_config)
    for webstudio's shared, admin-managed platform config. Distinct from
    the Electron desktop app's own per-machine Settings/LLM/Cloud pages,
    which stay local (IPC-backed config file, no server involved)."""
    __tablename__ = "global_config"

    id = Column(Integer, primary_key=True)

    llm_provider = Column(String(50), nullable=True)  # "claude" | "codex"
    llm_api_key_encrypted = Column(String(1000), nullable=True)

    cloud_provider = Column(String(50), nullable=True)  # "k8s" | "gcp" | "aws" | "azure"
    # JSON-serialized, then Fernet-encrypted as one blob -- credential shape
    # differs per provider (AWS keys vs. Azure service principal vs. GCP
    # service-account JSON vs. K8s kubeconfig), a single opaque encrypted
    # blob avoids a rigid column-per-field schema across four providers.
    cloud_credentials_encrypted = Column(String(4000), nullable=True)

    work_directory = Column(String(500), nullable=True)
    data_directory = Column(String(500), nullable=True)

    updated_at = Column(DateTime, nullable=True)
    updated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class LicenseKey(Base):
    __tablename__ = "license_keys"

    id = Column(Integer, primary_key=True)
    key = Column(String(29), unique=True, index=True)  # OMNI-XXXX-XXXX-XXXX-XXXX
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)  # bound on first successful validate
    email = Column(String(255), index=True)
    plan = Column(String(50), default="beta")  # beta | pro | enterprise
    platform = Column(String(20), default="both")  # web | desktop | both
    max_uses = Column(Integer, default=1)
    usage_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)

    # Added by the 0002_multi_tenant_schema migration -- nullable, and not
    # yet read or written by license_service.py/routes_license.py (that
    # cutover is Phase 1's PR3, not this change). Present here purely so the
    # ORM reflects the schema that already exists in the database.
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    machine_id = Column(String(64), nullable=True)
    max_devices = Column(Integer, nullable=True)

    user = relationship("User")


# ---------------------------------------------------------------------------
# Multi-tenant identity (Phase 1 PR2). Schema was created by
# 0002_multi_tenant_schema (PR1); these are the first ORM classes for it.
# Role/Permission remain a single global catalog shared across every
# organization -- only the *assignment* of roles to a user is org-scoped,
# via OrganizationMembership -> membership_roles -> Role. See
# app/services/org_service.py and ~/phase1_design.md for the reasoning.
# ---------------------------------------------------------------------------

membership_roles = Table(
    "membership_roles",
    Base.metadata,
    Column("membership_id", Integer, ForeignKey("organization_memberships.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
)

team_memberships = Table(
    "team_memberships",
    Base.metadata,
    Column("team_id", Integer, ForeignKey("teams.id"), primary_key=True),
    Column("user_id", Integer, ForeignKey("users.id"), primary_key=True),
)


class Organization(Base):
    __tablename__ = "organizations"

    id = Column(Integer, primary_key=True)
    slug = Column(String(100), unique=True, nullable=False)
    name = Column(String(255), nullable=False)
    plan = Column(String(50), default="beta")
    status = Column(String(50), default="active")
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class Team(Base):
    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_teams_org_name"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    members = relationship("User", secondary=team_memberships)


class OrganizationMembership(Base):
    __tablename__ = "organization_memberships"
    __table_args__ = (UniqueConstraint("organization_id", "user_id", name="uq_org_memberships_org_user"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    status = Column(String(50), default="active")  # active | invited
    invited_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    joined_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User", foreign_keys=[user_id])
    organization = relationship("Organization")
    roles = relationship("Role", secondary=membership_roles)


class ApiKey(Base):
    __tablename__ = "api_keys"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=True)
    key_prefix = Column(String(12), nullable=True)
    key_hash = Column(String(64), unique=True, nullable=True)
    scopes = Column(JSON, nullable=True)
    status = Column(String(20), default="active")  # active | revoked
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)


class OrganizationConfig(Base):
    __tablename__ = "organization_config"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), unique=True, nullable=False)
    llm_provider = Column(String(50), nullable=True)
    llm_api_key_encrypted = Column(String(1000), nullable=True)
    cloud_provider = Column(String(50), nullable=True)
    cloud_credentials_encrypted = Column(String(4000), nullable=True)
    work_directory = Column(String(500), nullable=True)
    data_directory = Column(String(500), nullable=True)
    updated_at = Column(DateTime, nullable=True)
    updated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)