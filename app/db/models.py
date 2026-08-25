from sqlalchemy import Column, Integer, String, ForeignKey, Table, UniqueConstraint, Index
from sqlalchemy.orm import relationship
from app.db.base import Base
from datetime import datetime
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Boolean, JSON, Text
from app.db.base import Base

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    # 0017: no longer indexed, and no longer length-capped for indexing
    # purposes -- see that migration's docstring. This had already been
    # widened once before (PR12, 500 -> 767) for the same underlying
    # reason: any VARCHAR cap on an indexed copy of the raw JWT eventually
    # gets exceeded again as claims grow (more roles -> a longer
    # `permissions` list). Kept as TEXT for reference only; every lookup
    # now goes through token_hash below instead.
    token = Column(Text)
    # SHA-256 hex digest of `token` (fixed-width, 64 hex chars) -- what
    # every lookup (app/services/auth_service.py's revoke_token/
    # rotate_refresh_token) filters on instead of the raw token, so this
    # column's index is unaffected by however long the JWT itself grows.
    token_hash = Column(String(64), unique=True, index=True)
    revoked = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime)
    # PR0.2: rotation + reuse detection. Every token minted from the same
    # login shares one family_id; rotating sets rotated_at on the
    # just-used row and creates a new row in the same family. A second
    # presentation of a token that already has rotated_at set is a replay
    # of an already-exchanged token -- the reuse signal -- and revokes
    # every row sharing that family_id (see auth_service.rotate_refresh_token).
    # Both nullable: existing rows predate this column and are treated as
    # a single-member family the first time they're used post-migration.
    family_id = Column(String(36), nullable=True, index=True)
    rotated_at = Column(DateTime, nullable=True)

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

    # Phase 3 PR3A: user-directory fields. created_at is nullable because
    # existing rows predate this column (added via migration, not
    # backfillable) -- new rows still get a real timestamp via the
    # ORM-level default. status_changed_* mirrors Organization's own
    # status-tracking columns (Phase 3 PR2) exactly, which itself mirrors
    # OrganizationSSOConfig's break-glass override columns (Phase 2 PR5)
    # -- the same "who/why/when for a privileged toggle" pattern, applied
    # here to user suspension instead of org suspension or SSO override.
    created_at = Column(DateTime, nullable=True, default=datetime.utcnow)
    status_changed_at = Column(DateTime, nullable=True)
    status_changed_reason = Column(String(500), nullable=True)
    status_changed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # PR11.1: user-management enhancement. Both nullable -- existing rows
    # predate these columns and have no history to backfill; a user who
    # has never logged in since this migration also has a real, honest
    # `None`/`None` rather than a fabricated value. Written in exactly one
    # place, auth_service.generate_tokens (the shared choke point every
    # login flow -- password/oauth/sso/license -- already funnels
    # through), never per-route, so every login path stays in sync by
    # construction. Deliberately NOT touched by rotate_refresh_token: a
    # token refresh continues an existing session, it is not a new login.
    last_login_at = Column(DateTime, nullable=True)
    authentication_method = Column(String(20), nullable=True)

    # PR11.5.1 (MFA database foundation): status metadata only, no
    # secrets -- see docs/pr11-mfa-database-foundation-discovery.md §2.1.
    # mfa_enabled is a live current-state flag (not a historical fact
    # like the fields above), so unlike them it gets a real
    # NOT NULL DEFAULT false rather than a nullable/no-backfill column --
    # every pre-existing row is unambiguously "MFA not enabled" today,
    # since MFA doesn't exist anywhere in this codebase yet. Schema only:
    # no login flow reads these columns, no enrollment/challenge logic
    # exists yet (that's PR11.5.2/11.5.3).
    mfa_enabled = Column(Boolean, nullable=False, default=False)
    mfa_status = Column(String(20), nullable=False, default="disabled")  # disabled | pending | enabled
    mfa_primary_method = Column(String(20), nullable=True)  # "totp" | "webauthn"
    mfa_enabled_at = Column(DateTime, nullable=True)
    mfa_last_verified_at = Column(DateTime, nullable=True)

    roles = relationship("Role", secondary=user_roles, back_populates="users")


class Role(Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True)
    # PR13: no longer globally unique at the DB level -- uniqueness is
    # scope-aware (platform-wide names are reserved everywhere, a custom
    # org role's name only has to be unique within its own org), and MySQL
    # treats NULLs as distinct in a unique index so a DB-level composite
    # constraint couldn't express that anyway. Enforced in role_service
    # instead. See 0016_role_org_scope's migration docstring.
    name = Column(String(100), index=True)
    # Phase 3 PR3B: nullable -- existing rows (and any role created via the
    # legacy create_role() call sites that don't pass one) simply have no
    # description until an operator sets one via the role CRUD endpoints.
    description = Column(String(500), nullable=True)
    # PR13: NULL = platform-wide role (visible/assignable in every org,
    # editable only by a Platform Admin). Non-NULL = a custom role owned by
    # that organization, invisible to every other org. See
    # 0016_role_org_scope's migration docstring.
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)

    users = relationship("User", secondary=user_roles, back_populates="roles")
    permissions = relationship("Permission", secondary=role_permissions)
    organization = relationship("Organization")


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
        # Established by Phase 2 PR2's 0004_org_sso_schema migration --
        # unchanged by SAML PR6. Deliberately NOT widened to also include
        # organization_saml_config_id: verified empirically (both SQLite
        # and MySQL follow the same ANSI SQL "NULL is never equal to
        # anything, including another NULL" rule for composite UNIQUE
        # indexes) that adding a 4th column that is NULL on every existing
        # OIDC/3-provider row would make the *whole* constraint stop
        # rejecting duplicates for those rows -- a real, present-tense
        # NULL in *any* column of a composite unique index defeats
        # uniqueness enforcement across *all* of that index's columns for
        # that row, not just the NULL one. Two rows with the exact same
        # (provider="oidc", provider_user_id, organization_sso_config_id)
        # and organization_saml_config_id=NULL on both would silently stop
        # being rejected -- reintroducing the cross-tenant `sub`-collision
        # bug this constraint exists to prevent, for every environment
        # that has ever created a SAML row anywhere. See
        # uq_oauth_provider_saml_account below for SAML's own, separate
        # constraint instead.
        UniqueConstraint(
            "provider", "provider_user_id", "organization_sso_config_id",
            name="uq_oauth_provider_account",
        ),
        # SAML PR6's own analogue, added as a SEPARATE constraint rather
        # than folded into the one above for exactly the NULL-poisoning
        # reason explained there -- this constraint's own 3 columns have
        # no NULLs for a real SAML row (organization_saml_config_id is
        # always populated for provider="saml"), so it enforces SAML
        # NameID uniqueness per org/config correctly, independent of
        # organization_sso_config_id's value (always NULL for SAML rows,
        # and irrelevant to this constraint since it isn't one of its
        # columns).
        UniqueConstraint(
            "provider", "provider_user_id", "organization_saml_config_id",
            name="uq_oauth_provider_saml_account",
        ),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    provider = Column(String(20), nullable=False)  # "google" | "github" | "microsoft" | "oidc" | "saml"
    provider_user_id = Column(String(255), nullable=False)
    email = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)

    # Added by Phase 2 PR2's 0004_org_sso_schema migration -- nullable, and
    # not yet read or written by oauth_service.py (that cutover is Phase 2
    # PR4, not this change). NULL on every row created by today's 3 global
    # providers; populated only for accounts created via a future org-IdP
    # login.
    organization_sso_config_id = Column(Integer, ForeignKey("organization_sso_configs.id"), nullable=True)

    # SAML PR6 (0022_oauth_saml_config_id): the SAML equivalent of
    # organization_sso_config_id above -- a separate column, not a reuse of
    # it, because it is a real ForeignKey to a different table
    # (organization_saml_configs, not organization_sso_configs). Populating
    # organization_sso_config_id with a organization_saml_configs.id value
    # instead would either violate that FK (if enforced) or, left NULL,
    # collapse this table's uniqueness scoping for SAML rows back to a bare
    # (provider, provider_user_id) pair -- reintroducing the exact
    # cross-tenant NameID-collision bug organization_sso_config_id was
    # added to prevent for OIDC (see org_saml_service's module docstring
    # and OrganizationSAMLConfig's own class docstring, which anticipated
    # exactly this column and this reasoning back in PR2). NULL on every
    # pre-PR6 row (all 4 pre-existing providers); populated only for
    # accounts linked via a SAML login (provider="saml").
    organization_saml_config_id = Column(Integer, ForeignKey("organization_saml_configs.id"), nullable=True)

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
    # Team Management v0.8.0 Step 1 (0020_team_member_roles): the three
    # columns below are new. `role` is intentionally a plain, app-checked
    # string ("admin" | "member" | "viewer") -- not routed through the
    # Role/Permission machinery `membership_roles` above uses -- per this
    # feature's decision to keep team RBAC lightweight. `default="member"`/
    # `default=datetime.utcnow` are Python-side conveniences for inserts
    # that go through the ORM without setting them explicitly (e.g. the
    # pre-existing `Team.members = [...]` full-replace path below); the
    # migration's `server_default='member'` is what actually backfills
    # pre-existing rows at the DB level.
    Column("role", String(20), nullable=False, default="member"),
    Column("invited_by_user_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("joined_at", DateTime, nullable=True, default=datetime.utcnow),
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

    # Phase 3 PR2: status-change tracking for the platform-admin suspend/
    # reactivate action (routes_orgs.py's PATCH /orgs/{org_id}) -- mirrors
    # OrganizationSSOConfig's sso_override_at/reason/by_user_id (Phase 2
    # PR5) exactly, the same "who/why/when for a privileged toggle"
    # pattern. An explicit extension point for Phase 3 PR4's audit
    # pipeline, not a replacement for it: these three columns record the
    # *current* status change only, not a full history.
    status_changed_at = Column(DateTime, nullable=True)
    status_changed_reason = Column(String(500), nullable=True)
    status_changed_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class Team(Base):
    __tablename__ = "teams"
    __table_args__ = (UniqueConstraint("organization_id", "name", name="uq_teams_org_name"),)

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=False)
    name = Column(String(255), nullable=False)
    # Team Management v0.8.0 Step 1 (0020_team_member_roles).
    description = Column(String(1000), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    # team_memberships now carries a second FK to users.id
    # (invited_by_user_id, added alongside role/joined_at below) --
    # explicit primaryjoin/secondaryjoin (lambdas: evaluated lazily at
    # mapper-configure time, once both Team and User are fully defined
    # module globals) keep this relationship resolving through user_id
    # only, exactly as it did before that column existed.
    members = relationship(
        "User",
        secondary=team_memberships,
        primaryjoin=lambda: Team.id == team_memberships.c.team_id,
        secondaryjoin=lambda: User.id == team_memberships.c.user_id,
    )


class TeamMember(Base):
    """Association-object mapping onto the exact same physical table as
    `team_memberships` above (`Team.members`'s `secondary=`) -- not a
    second table. `Team.members` and the pre-existing full-replace
    `set_team_members`/`PUT .../members` path keep writing through the
    plain `secondary=` relationship, completely untouched by this class;
    `TeamMember` exists so the new per-member invite/role/remove/leave
    endpoints (Team Management v0.8.0 Step 2+) can read and write `role`,
    `invited_by_user_id`, and `joined_at`, which a bare `secondary=`
    relationship has no access to. Both paths issue ordinary INSERT/
    UPDATE/DELETE against the same `team_memberships` rows; they are
    never both touched for the same row within a single request, so there
    is no unit-of-work conflict between the two mappings of this table.
    """

    __table__ = team_memberships

    team = relationship("Team", viewonly=True)
    user = relationship("User", foreign_keys=[team_memberships.c.user_id], viewonly=True)
    invited_by = relationship(
        "User", foreign_keys=[team_memberships.c.invited_by_user_id], viewonly=True
    )


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

    # Phase 2 PR3: operational fields for future enterprise troubleshooting.
    # last_verified_at is set on every successful discovery (create or an
    # issuer-changing update). verification_error is reserved for a future
    # periodic re-verification job (not this PR) -- org_sso_service never
    # persists a *failed* discovery attempt at all, so nothing in this PR
    # writes verification_error yet; it exists now so that job doesn't
    # need its own migration later.
    last_verified_at = Column(DateTime, nullable=True)
    verification_error = Column(Text, nullable=True)

    # Phase 2 PR5: break-glass bypass for `enforced` -- kept on this table
    # (not on Organization, despite the original design doc sketching it
    # there) so every piece of SSO enforcement state lives in one place,
    # next to `enforced` itself. Non-null sso_override_at means
    # enforcement is currently suspended for this org regardless of the
    # `enforced` value, without having to touch (and therefore lose) the
    # org's own stated enforced=true intent -- clearing the override
    # resumes enforcement exactly as it was configured.
    sso_override_at = Column(DateTime, nullable=True)
    sso_override_reason = Column(String(500), nullable=True)
    sso_override_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class OrganizationSAMLConfig(Base):
    """SAML SSO PR2: schema only -- no CRUD API exists yet (PR8), no SP
    metadata/login/ACS endpoint exists yet (PR3-PR7), and no login path
    reads it yet. One row per org (org-scoped UNIQUE) registers that org's
    own SAML 2.0 identity provider (Okta, Entra ID, ADFS, ...).

    Deliberately a separate table from OrganizationSSOConfig, not a
    generalization of it into a shared/polymorphic `organization_idp_
    configs` table -- SAML's own discovery report flagged that
    generalization as a real option but explicitly deferred it, since it
    would touch OrganizationSSOConfig's existing, shipped OIDC code paths
    for no benefit to this PR. Mirrors OrganizationSSOConfig's shape and
    column conventions (nullable lifecycle/audit columns with an
    ORM-level, not server_default, default -- see `enabled`/`status`
    below) anyway, so the two tables read as one family and a future
    admin UI (PR9) can treat them symmetrically.

    SAML PR6 implemented the plan this docstring anticipated: OAuthAccount
    gained a nullable organization_saml_config_id FK to this table
    (0022_oauth_saml_config_id), and provider="saml" rows are keyed by
    provider_user_id=the assertion's NameID, scoped by that column -- see
    OAuthAccount's own comment. PR6 only links/resolves *existing* users
    this way (an already-linked identity, or an explicit password-
    confirmed link to a matching email) -- auto-creating a brand-new user
    purely from an unrecognized SAML identity (JIT provisioning) is still
    PR7 scope, not implemented here.

    #263: enforced/allowed_domains added -- see those columns' own
    comments. Login paths (routes_auth.py password login, routes_oauth.py
    OAuth callback) now read this table too, the same way they already
    read OrganizationSSOConfig.enforced for OIDC.
    """
    __tablename__ = "organization_saml_configs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), unique=True, nullable=False)

    # IdP trust configuration -- administrator-controlled input, not a
    # secret. The SP private key is deliberately NOT stored on this table
    # (or anywhere yet): it's environment/deployment configuration, to be
    # handled in a later implementation step, same as JWT_PRIVATE_KEY in
    # app/core/config.py today.
    entity_id = Column(String(500), nullable=False)  # IdP Entity ID
    sso_url = Column(String(500), nullable=False)  # IdP SSO (AuthnRequest destination) endpoint
    x509_certificate = Column(Text, nullable=False)  # IdP signing certificate, PEM -- Text, not String, since a chain can exceed a few hundred bytes
    # #263: per-org SAML enforcement. Mirrors OrganizationSSOConfig's own
    # allowed_domains/enforced pair exactly (0004_org_sso_schema) --
    # allowed_domains is the domain-to-org lookup find_enforced_saml_org_
    # for_email needs (this table had no such mechanism before #263;
    # OrganizationSAMLConfig.enabled is a separate, older, currently-
    # unread-by-any-login-path field -- see OrgSAMLConfigOut's own
    # comment -- not to be confused with this one). No sso_override_at-
    # style break-glass override for SAML (deliberately out of scope for
    # #263 -- see org_saml_service.set_enforced's own docstring).
    allowed_domains = Column(JSON, nullable=True)  # e.g. ["acme.com"]
    enforced = Column(Boolean, default=False)
    # PR11 (SLO): the IdP's SingleLogoutService endpoint -- a genuinely
    # distinct URL from sso_url above. python3-saml's own settings schema
    # (onelogin/saml2/settings.py) requires idp.singleLogoutService.url as
    # a separate key from idp.singleSignOnService.url and does not fall
    # back to the latter (verified by reading get_idp_slo_url() directly
    # -- it returns None, not sso_url, when unset), so reusing sso_url for
    # both purposes was not an option. Nullable: an org's SAML config can
    # exist and support login without its IdP also supporting SLO (many
    # smaller IdPs don't), and every pre-PR11 config row has no value for
    # this by construction.
    slo_url = Column(String(500), nullable=True)

    # Configuration only -- no attribute extraction/processing exists yet
    # (a later PR's scope). Example shape: {"email": "NameID",
    # "first_name": "givenName", "last_name": "sn", "groups": "groups",
    # "department": "department"}.
    attribute_mapping = Column(JSON, nullable=True)

    # Nullable at the DB level with only an ORM-level (not server_default)
    # default, deliberately matching OrganizationSSOConfig.enforced/status
    # exactly rather than tightening to NOT NULL here -- see that class's
    # own columns for the precedent this mirrors.
    enabled = Column(Boolean, default=False)
    status = Column(String(20), default="pending_verification")  # pending_verification | active | disabled

    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)
    updated_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class AuditEvent(Base):
    """PR9 (Enterprise IAM Foundation): persistent IAM audit ledger,
    colocated with Users/Organizations/Roles in this repo's own database
    -- deliberately not routed through the separate omnibioai-security-
    audit service's Redis/consumer pipeline (a real, existing system, but
    a generic cross-service request/policy log with no columns for
    actor/target/organization/before-after state; extending it would mean
    a second, cross-repo migration for a difference in kind, not degree).
    See app/services/audit_service.py for the single place rows here are
    written from.

    actor_user_id/target_user_id/organization_id are nullable and NOT
    foreign keys with ON DELETE behavior -- an audit row must survive and
    keep its historical identifiers even if the referenced user/org is
    later deleted (this codebase has no user/org hard-delete path today,
    but a ledger must never be designed to assume that stays true).
    before_state/after_state/event_metadata are JSON so each event_type's
    payload shape can differ without a schema migration per event kind.
    """
    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    event_type = Column(String(100), nullable=False, index=True)
    actor_user_id = Column(Integer, nullable=True, index=True)
    target_user_id = Column(Integer, nullable=True, index=True)
    organization_id = Column(Integer, nullable=True, index=True)
    resource_type = Column(String(50), nullable=True)
    resource_id = Column(String(100), nullable=True)
    before_state = Column(JSON, nullable=True)
    after_state = Column(JSON, nullable=True)
    # Python attribute can't be named `metadata` -- that name is reserved
    # by SQLAlchemy's declarative Base (Base.metadata is the schema
    # MetaData object). The actual database column is still named
    # `metadata`, matching the requested schema exactly.
    event_metadata = Column("metadata", JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)


class MFADevice(Base):
    """PR11.5.1: a single enrolled MFA factor. Separate from `User`
    (see docs/pr11-mfa-database-foundation-discovery.md §2.2) because a
    user may enroll more than one factor -- mirrors ApiKey/OAuthClient's
    own "secret-bearing row, separate from its owning identity, FK +
    indexed by owner" shape exactly.

    Schema only: no enrollment/verification logic exists yet (that's
    PR11.5.2), so nothing in this codebase writes a row here today.
    `encrypted_secret` uses the same Fernet CONFIG_ENCRYPTION_KEY as
    OrganizationSSOConfig.client_secret_encrypted / OrganizationConfig.
    llm_api_key_encrypted (app/core/crypto.py) -- reversible encryption,
    not a hash, because a TOTP code can only be verified by decrypting
    the shared secret back to plaintext.
    """
    __tablename__ = "mfa_devices"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    device_type = Column(String(20), nullable=False)  # "totp" | "webauthn"
    label = Column(String(255), nullable=True)  # user-chosen display name, e.g. "iPhone"
    encrypted_secret = Column(String(1000), nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    last_used_at = Column(DateTime, nullable=True)
    disabled_at = Column(DateTime, nullable=True)

    user = relationship("User")


class MFARecoveryCode(Base):
    """PR11.5.1: one-time-use recovery codes, hashed at rest -- never
    the plaintext code. Same "store a hash, never the plaintext"
    convention as ApiKey.key_hash / OAuthClient.client_secret_hash, not
    MFADevice's reversible-encryption pattern, because a recovery code
    only ever needs to be *checked*, never decrypted for reuse.

    code_hash is deliberately not unique=True: a recovery code is
    always looked up scoped to an already-known user_id (the user is
    mid-login, missing only their second factor), unlike ApiKey/
    OAuthClient secrets which must resolve to their owner on a global
    lookup -- see docs/pr11-mfa-database-foundation-discovery.md §2.3.

    Schema only: no generation/consumption logic exists yet.
    """
    __tablename__ = "mfa_recovery_codes"

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    code_hash = Column(String(64), nullable=False)  # sha256 hex, same shape as OAuthClient.client_secret_hash
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    used_at = Column(DateTime, nullable=True)  # NULL = unused

    user = relationship("User")


class MFAUsedTOTPStep(Base):
    """HIPAA Phase 3b (TOTP Replay / Consumed-Time-Step Protection). Not
    part of the original PR11.5.1 MFA foundation -- added specifically to
    close a gap that TOTP verification's own +-1 step tolerance window
    leaves open: without this table, the *same* valid code -- correct by
    construction for up to ~90s -- could be redeemed more than once
    against the same device, each redemption completing a separate,
    independent MFA challenge (a new challenge_token from a fresh login,
    since only a *successful* challenge_token's own jti is single-use,
    see MFAChallengeError's docstring in app/services/mfa_service.py) and
    minting its own new session. See
    docs/security-mfa-totp-replay-protection.md for the full threat model
    and why this is the correct place to close it (RFC 6238's own
    Security Considerations explicitly calls out not accepting one OTP
    value more than once).

    One row per *successfully verified* TOTP code, never per attempt --
    app/services/mfa_service.py only ever inserts a row here after
    independently confirming `code` is cryptographically valid for
    `time_step`; a wrong guess never reaches this table at all, so an
    attacker flooding failed attempts (already throttled by
    app/services/mfa_throttle_service.py, HIPAA Phase 3) cannot grow it.

    `(device_id, time_step)` is the UNIQUE pair that actually enforces
    single-use -- `time_step` is TOTP's own RFC 6238 counter
    (unix_time // 30), not a timestamp, so two different valid codes
    naturally get two different rows and never collide; the *same* code
    presented a second time (whether by an attacker who captured it, a
    legitimate user's retried request racing on two challenge_tokens, or
    two literally concurrent requests) always maps to the same
    `time_step` and is rejected by this constraint at INSERT time --
    correct and atomic across any number of horizontally-scaled
    `omnibioai-auth` instances sharing one database, without any Redis or
    in-process state (see app/services/mfa_service.py::_try_claim_totp_step).

    No explicit expiration/cleanup job: a stale row (from a time_step no
    device will ever present a code for again) is simply irrelevant
    forever after, never queried again by device+time_step, so leaving it
    in place is harmless -- the same unbounded-but-harmless-growth
    tradeoff `RevokedToken` above already makes for exactly the same
    reason (bounded by real successful-verification volume, not
    attacker-controlled).
    """
    __tablename__ = "mfa_used_totp_steps"
    __table_args__ = (
        UniqueConstraint("device_id", "time_step", name="uq_mfa_used_totp_step"),
    )

    id = Column(Integer, primary_key=True)
    device_id = Column(Integer, ForeignKey("mfa_devices.id"), nullable=False, index=True)
    time_step = Column(Integer, nullable=False)  # RFC 6238 counter: unix_time // period
    consumed_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class UserSession(Base):
    """Phase 4 PR-A (Session Foundation): the queryable, administrable
    shadow of one refresh-token *family* -- not a new authentication
    mechanism, not a session store the auth flow depends on to function.
    See docs/session-foundation-discovery.md for the full design.

    `session_id` deliberately stores the *same* string every
    `RefreshToken` row descended from one login already shares in its own
    `family_id` column (see that column's own comment above), rather than
    minting and tracking a second, independent identifier that could ever
    drift out of sync with it. `family_id` already survives every
    rotation -- see `auth_service.rotate_refresh_token` -- which is
    exactly the "stable identity across refresh" a session needs, so this
    table reuses it outright instead of duplicating it under a different
    name. There is intentionally no `refresh_token_family_id` column
    separate from `session_id`: they are the same value by construction,
    and storing it twice would only create a second copy that could go
    stale.

    Named `UserSession` (table `sessions`), not `Session` -- `Session` is
    already the name every file in this codebase imports for
    `sqlalchemy.orm.Session` (`db: Session = Depends(get_db)`); reusing it
    here would shadow that import in any module that needed both.

    No raw refresh token or any other secret is ever stored on this row --
    `session_id` is an opaque, non-secret family identifier (a `uuid4`),
    not a bearer credential; possessing it grants nothing on its own (see
    app/rbac.py -- every session route the API exposes still requires a
    valid, unrevoked access token to even reach this table, scoped to
    that caller's own `user_id`).

    `organization_id`/`org_role`/`auth_method`/`mfa_verified` are point-in-
    time snapshots of what `build_user_claims` resolved at *login* time --
    not live pointers -- so a session created while a user held a given
    org role keeps showing that role even if it's later changed, matching
    how the JWT itself already behaves for the lifetime of one access
    token. This is display/audit information only; every real
    authorization decision anywhere in this service still comes from the
    JWT/DB checks that already exist (`get_current_user`, `rbac.py`),
    completely unchanged by this table's existence.

    `status`/`expires_at` mirror the owning refresh-token family's own
    revoked/expiry state as of the last time this row was written (login,
    each rotation, or an explicit revoke) -- not a live join. EXPIRED is
    deliberately never written by a background sweep (no scheduler exists
    in this repo); see app/services/session_service.py's
    `effective_status` for how a merely-timed-out session is recognized
    at read time without one.
    """

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    session_id = Column(String(36), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    organization_id = Column(Integer, ForeignKey("organizations.id"), nullable=True)
    org_role = Column(JSON, nullable=True)
    auth_method = Column(String(20), nullable=True)
    mfa_verified = Column(Boolean, nullable=False, default=True)
    status = Column(String(20), nullable=False, default="active")  # active | expired | revoked
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_activity_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    revoked_at = Column(DateTime, nullable=True)
    revoked_reason = Column(String(255), nullable=True)
    # Best-effort operational metadata for the session owner's own "is
    # this me?" review (see routes_sessions.py) -- read directly from the
    # request at login (request.client.host / the User-Agent header), no
    # trusted-proxy header parsing (no X-Forwarded-For convention exists
    # anywhere else in this codebase either; inventing one here is out of
    # scope for this change). Never logged -- see auth_service/
    # session_service for where these are written.
    client_ip = Column(String(64), nullable=True)
    user_agent = Column(String(255), nullable=True)
    # PR11 (SLO): set only for a session created by a SAML login (see
    # auth_service.generate_tokens' new optional saml_name_id/
    # saml_session_index kwargs) -- this is what lets an IdP-initiated
    # LogoutRequest (which carries NameID + SessionIndex, never this
    # session's own family_id/refresh token) find the right local
    # session(s) to revoke. All three nullable and all three None for
    # every non-SAML session (password/OAuth/OIDC-SSO/license) and for
    # every session that predates this column.
    saml_name_id = Column(String(500), nullable=True, index=True)
    saml_session_index = Column(String(255), nullable=True)
    # Scopes the NameID lookup to one org's specific SAML IdP -- same
    # role OAuthAccount.organization_saml_config_id already plays for
    # SAML identity linking (PR6): without this, a NameID that happens to
    # match across two different orgs' IdPs could let one org's
    # LogoutRequest revoke another org's session for "the same" email.
    organization_saml_config_id = Column(Integer, ForeignKey("organization_saml_configs.id"), nullable=True)


class OrganizationMFAPolicy(Base):
    """PR11.5.5: org-level MFA requirement, deliberately a sibling table
    to Organization -- not columns on it -- mirroring
    OrganizationSSOConfig's own shape exactly (see
    docs/pr11-mfa-org-policy-discovery.md §1). One row per org
    (organization_id UNIQUE); absence of a row means "no policy
    configured," not "required=false enforced", same as
    OrganizationSSOConfig's own "no CRUD exists until explicitly
    configured" precedent.

    `required` is this table's analog of OrganizationSSOConfig.enforced.
    `override_active`/`override_reason`/`override_at`/
    `override_by_user_id` mirror sso_override_at/reason/by_user_id's
    "who/why/when for a privileged toggle" pattern -- suspends the
    *effect* of `required` without changing the org's own stated intent,
    set/cleared together as one unit. Unlike OrganizationSSOConfig,
    `override_active` is a distinct boolean (not merely `override_at is
    not None`) -- the explicit shape this PR's own task spec requires.

    `enabled_at`/`enabled_by_user_id` record the most recent time
    `required` flipped False->True (via POST or PATCH) -- left
    untouched by a later True->False flip, a permanent "when did this
    org last turn MFA on" marker (see discovery doc §1 for why this
    reading was chosen over clearing them on disable).

    No relationship to MFADevice/MFARecoveryCode -- this table only
    ever asks "does this org require MFA," never anything about a
    specific user's enrollment state.
    """
    __tablename__ = "organization_mfa_policies"

    id = Column(Integer, primary_key=True)
    organization_id = Column(Integer, ForeignKey("organizations.id"), unique=True, nullable=False)
    required = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=True)

    enabled_at = Column(DateTime, nullable=True)
    enabled_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

    override_active = Column(Boolean, nullable=False, default=False)
    override_reason = Column(String(500), nullable=True)
    override_at = Column(DateTime, nullable=True)
    override_by_user_id = Column(Integer, ForeignKey("users.id"), nullable=True)


class Interaction(Base):
    """PR-B2 (Interactions Foundation): durable ledger of meaningful
    platform/business activity -- "what did the user/service do"
    (RAG query, workflow submission, tool execution, ...), as opposed to
    AuditEvent's "what security/audit-relevant thing happened"
    (login/role/permission/MFA/SSO changes) or UserSession's "what login
    lineage is currently active." All three stay separate tables by
    design -- see docs/pr-b2-interactions-foundation-discovery.md.

    interaction_id is the canonical external identity (uuid4, minted once
    at creation by interaction_service.build_interaction_event -- never
    regenerated on retry/redelivery), analogous to AuditEvent's own
    identity being its surrogate `id`, but exposed/stable pre-persistence
    so a Redis-published copy of the same logical event carries the same
    identity as its DB row. UNIQUE + indexed for the idempotent-insert
    pattern interaction_service.create_interaction uses (IntegrityError
    on a duplicate interaction_id is caught and treated as success, the
    same convention omnibioai-security-audit's consumers/sink.py::
    Sink.write already established for its own event_id).

    organization_id/user_id/session_id/trace_id are deliberately plain
    columns, NOT foreign keys -- mirrors AuditEvent's own reasoning
    exactly (see that class's docstring above): a durable ledger row must
    keep its historical identifiers even if the referenced organization/
    user/session is later deleted, unlike UserSession.organization_id
    (a real FK) which has no such historical-preservation requirement.
    session_id stores the same session_id value UserSession.session_id
    does (a family_id uuid4 string, see UserSession's own docstring) --
    not a FK to sessions.id (a different, surrogate column) or
    sessions.session_id (would reintroduce the exact cross-table
    lifecycle coupling this design avoids). Nullable: many legitimate
    service/system interactions have no authenticated session at all.

    created_at uses this schema's universal naive-UTC convention
    (datetime.utcnow(), matching RefreshToken/User/Organization/
    UserSession/AuditEvent with zero exceptions anywhere in this file) --
    not a timezone-aware column, which would be the only one in the
    entire schema.

    event_metadata mirrors AuditEvent.event_metadata's exact naming
    workaround: the Python attribute can't be called `metadata` (reserved
    by SQLAlchemy's declarative Base), but the actual database column is
    still literally named `metadata`. Must never contain token/secret-
    shaped values -- see interaction_service.py's redaction discussion.
    """
    __tablename__ = "interactions"
    __table_args__ = (
        # Org-scoped listing, newest first -- the primary anticipated
        # query shape (a future org-scoped Control Center view, PR-B5+).
        Index("ix_interactions_org_id_created", "organization_id", "created_at"),
        # "My interactions" / "this session's interactions" -- self-service
        # equivalents of UserSession's own ix_sessions_user_id_status /
        # ix_sessions_org_id_status_created shape.
        Index("ix_interactions_user_id_created", "user_id", "created_at"),
        Index("ix_interactions_session_id_created", "session_id", "created_at"),
    )

    id = Column(Integer, primary_key=True)
    interaction_id = Column(String(36), unique=True, nullable=False, index=True)

    organization_id = Column(Integer, nullable=False)
    user_id = Column(Integer, nullable=True)
    session_id = Column(String(36), nullable=True)
    # Single-column, not paired with created_at -- a trace lookup is an
    # exact cross-service correlation match ("show me everything under
    # this trace_id"), not a date-range scan, unlike the three above.
    trace_id = Column(String(255), nullable=True, index=True)

    service = Column(String(100), nullable=False)
    interaction_type = Column(String(100), nullable=False)
    action = Column(String(255), nullable=False)

    resource_type = Column(String(100), nullable=True)
    resource_id = Column(String(255), nullable=True)

    status = Column(String(50), nullable=True)
    decision = Column(String(50), nullable=True)

    # Python attribute can't be named `metadata` -- see AuditEvent's own
    # identical comment above. DB column is still literally `metadata`.
    event_metadata = Column("metadata", JSON, nullable=True)

    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
