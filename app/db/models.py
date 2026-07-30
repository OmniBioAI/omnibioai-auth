from sqlalchemy import Column, Integer, String, ForeignKey, Table, UniqueConstraint
from sqlalchemy.orm import relationship
from app.db.base import Base
from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean
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

    user = relationship("User")