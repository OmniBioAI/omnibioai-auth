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
        # Widened by Phase 2 PR2's 0004_org_sso_schema migration from
        # (provider, provider_user_id) to include organization_sso_config_id
        # -- every existing row has that column NULL, and MySQL treats each
        # NULL as distinct across a composite unique index, so every row
        # that satisfied the old 2-column constraint still satisfies this
        # one unchanged. Needed once org-IdP logins exist (Phase 2 PR4):
        # multiple orgs' custom OIDC IdPs can otherwise collide on the same
        # generic provider="oidc" + a provider_user_id namespace that's
        # only unique *within* one IdP, not globally.
        UniqueConstraint(
            "provider", "provider_user_id", "organization_sso_config_id",
            name="uq_oauth_provider_account",
        ),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String(20), nullable=False)  # "google" | "github" | "microsoft" | "oidc"
    provider_user_id = Column(String(255), nullable=False)
    email = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Added by Phase 2 PR2's 0004_org_sso_schema migration -- nullable, and
    # not yet read or written by oauth_service.py (that cutover is Phase 2
    # PR4, not this change). NULL on every row created by today's 3 global
    # providers; populated only for accounts created via a future org-IdP
    # login.
    organization_sso_config_id = Column(Integer, ForeignKey("organization_sso_configs.id"), nullable=True)

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


class OAuthClient(Base):
    """Phase 2 PR1: registered OAuth 2.1 client_credentials clients (RFC
    6749 SS4.4) -- a service identity, not a user. Deliberately a separate
    table from ApiKey rather than reusing it: ApiKey is a shipped,
    human-facing feature (a bearer secret a person pastes into a script),
    while an OAuth client is a client_id/client_secret pair meant for a
    standards-shaped token endpoint. Keeping them apart means this PR
    touches none of ApiKey's existing code paths.
    """
    __tablename__ = "oauth_clients"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    client_id = Column(String(64), unique=True, nullable=False)
    client_secret_hash = Column(String(64), nullable=False)  # sha256 hex, plaintext never stored
    name = Column(String(255), nullable=True)
    scopes = Column(JSON, nullable=True)
    status = Column(String(20), default="active")  # active | revoked
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)


class OrganizationSSOConfig(Base):
    """Phase 2 PR2: schema only -- no CRUD exists yet (Phase 2 PR3) and no
    login path reads it yet (Phase 2 PR4). One row per org (org-scoped
    UNIQUE) registers that org's own OIDC identity provider (Okta, Entra
    ID, Google Workspace, ...), as opposed to the 3 global consumer OAuth
    apps in app/core/oauth_providers.py, which stay untouched by this
    table entirely.
    """
    __tablename__ = "organization_sso_configs"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), unique=True, nullable=False)
    provider_type = Column(String(20), default="oidc")
    issuer = Column(String(500), nullable=False)
    client_id = Column(String(255), nullable=False)
    # Fernet, same CONFIG_ENCRYPTION_KEY as OrganizationConfig's
    # llm_api_key_encrypted -- see app/core/crypto.py.
    client_secret_encrypted = Column(String(1000), nullable=False)
    # Cached from the issuer's /.well-known/openid-configuration at
    # registration time (Phase 2 PR3), not yet read by any login path.
    authorization_endpoint = Column(String(500), nullable=True)
    token_endpoint = Column(String(500), nullable=True)
    userinfo_endpoint = Column(String(500), nullable=True)
    jwks_uri = Column(String(500), nullable=True)
    allowed_domains = Column(JSON, nullable=True)  # e.g. ["acme.com"] -- read starting Phase 2 PR4
    enforced = Column(Boolean, default=False)  # read starting Phase 2 PR5, ignored until then
    status = Column(String(20), default="pending_verification")  # pending_verification | active | disabled
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    updated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)