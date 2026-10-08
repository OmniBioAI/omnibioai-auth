"""Generic encrypted integration credentials and opaque references."""

from alembic import op
import sqlalchemy as sa

revision = "0031_integration_credentials"
down_revision = "0030_user_timezone"
branch_labels = None
depends_on = None


def _precreated_table_matches(
    table_name, *, columns, indexes, checks, foreign_keys
):
    """Accept only the exact table shape create_all() produces.

    Auth still invokes Base.metadata.create_all() at process startup. If new
    code starts before Alembic, these two additive tables can therefore exist
    while alembic_version remains at 0030. Treat that known ordering as safe
    only after verifying every security-relevant column and constraint; any
    partial or foreign schema fails closed rather than being stamped over.
    """
    inspector = sa.inspect(op.get_bind())
    if not inspector.has_table(table_name):
        return False
    actual_columns = {item["name"] for item in inspector.get_columns(table_name)}
    actual_indexes = {item["name"] for item in inspector.get_indexes(table_name)}
    actual_indexes.update(item["name"] for item in inspector.get_unique_constraints(table_name))
    actual_checks = {item["name"] for item in inspector.get_check_constraints(table_name)}
    actual_foreign_keys = {
        tuple(item["constrained_columns"]) for item in inspector.get_foreign_keys(table_name)
    }
    missing = {
        "columns": set(columns) - actual_columns,
        "indexes": set(indexes) - actual_indexes,
        "checks": set(checks) - actual_checks,
        "foreign_keys": {tuple(item) for item in foreign_keys} - actual_foreign_keys,
    }
    unexpected_columns = actual_columns - set(columns)
    if any(missing.values()) or unexpected_columns:
        raise RuntimeError(
            f"Refusing integration credential migration: pre-existing {table_name} "
            f"does not match the expected create_all schema (missing={missing}, "
            f"unexpected_columns={sorted(unexpected_columns)})."
        )
    return True


def upgrade():
    credentials_exist = _precreated_table_matches(
        "integration_credentials",
        columns={
            "id", "provider_id", "scope", "owner_key", "user_id", "organization_id",
            "encrypted_payload", "masked_hint", "display_metadata", "status", "version",
            "created_at", "updated_at", "revoked_at", "created_by_user_id", "updated_by_user_id",
        },
        indexes={
            "uq_integration_credential_owner", "ix_integration_credentials_provider_id",
            "ix_integration_credentials_user_provider", "ix_integration_credentials_org_provider",
        },
        checks={"ck_integration_credential_scope_owner", "ck_integration_credential_status"},
        foreign_keys={
            ("user_id",), ("organization_id",), ("created_by_user_id",), ("updated_by_user_id",),
        },
    )
    if not credentials_exist:
        op.create_table(
            "integration_credentials",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("provider_id", sa.String(64), nullable=False),
            sa.Column("scope", sa.String(20), nullable=False),
            sa.Column("owner_key", sa.String(128), nullable=False),
            sa.Column("user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=True),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=True),
            sa.Column("encrypted_payload", sa.Text(), nullable=True),
            sa.Column("masked_hint", sa.String(32), nullable=True),
            sa.Column("display_metadata", sa.JSON(), nullable=True),
            sa.Column("status", sa.String(20), nullable=False),
            sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("updated_at", sa.DateTime(), nullable=False),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.Column("created_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("updated_by_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.UniqueConstraint("provider_id", "scope", "owner_key", name="uq_integration_credential_owner"),
            sa.CheckConstraint(
                "(scope = 'user' AND user_id IS NOT NULL AND organization_id IS NULL) OR "
                "(scope = 'organization' AND user_id IS NULL AND organization_id IS NOT NULL) OR "
                "(scope = 'platform' AND user_id IS NULL AND organization_id IS NULL)",
                name="ck_integration_credential_scope_owner",
            ),
            sa.CheckConstraint("status IN ('active', 'revoked')", name="ck_integration_credential_status"),
        )
        op.create_index("ix_integration_credentials_provider_id", "integration_credentials", ["provider_id"])
        op.create_index("ix_integration_credentials_user_provider", "integration_credentials", ["user_id", "provider_id"])
        op.create_index("ix_integration_credentials_org_provider", "integration_credentials", ["organization_id", "provider_id"])

    references_exist = _precreated_table_matches(
        "integration_credential_references",
        columns={
            "id", "token_hash", "credential_id", "credential_version", "provider_id", "scope",
            "subject_user_id", "organization_id", "consumer", "purpose", "created_at",
            "expires_at", "revoked_at",
        },
        indexes={
            "ix_integration_credential_references_token_hash",
            "ix_integration_credential_references_credential_id",
            "ix_integration_credential_references_provider_id",
            "ix_integration_credential_references_subject_user_id",
            "ix_integration_credential_references_organization_id",
            "ix_integration_credential_references_expires_at",
        },
        checks={"ck_integration_reference_scope"},
        foreign_keys={("credential_id",), ("subject_user_id",), ("organization_id",)},
    )
    if not references_exist:
        op.create_table(
            "integration_credential_references",
            sa.Column("id", sa.Integer(), primary_key=True),
            sa.Column("token_hash", sa.String(64), nullable=False),
            sa.Column("credential_id", sa.Integer(), sa.ForeignKey("integration_credentials.id"), nullable=False),
            sa.Column("credential_version", sa.Integer(), nullable=False),
            sa.Column("provider_id", sa.String(64), nullable=False),
            sa.Column("scope", sa.String(20), nullable=False),
            sa.Column("subject_user_id", sa.Integer(), sa.ForeignKey("users.id"), nullable=False),
            sa.Column("organization_id", sa.Integer(), sa.ForeignKey("organizations.id"), nullable=True),
            sa.Column("consumer", sa.String(64), nullable=False),
            sa.Column("purpose", sa.String(64), nullable=False),
            sa.Column("created_at", sa.DateTime(), nullable=False),
            sa.Column("expires_at", sa.DateTime(), nullable=False),
            sa.Column("revoked_at", sa.DateTime(), nullable=True),
            sa.CheckConstraint("scope IN ('user', 'organization', 'platform')", name="ck_integration_reference_scope"),
        )
        op.create_index("ix_integration_credential_references_token_hash", "integration_credential_references", ["token_hash"], unique=True)
        op.create_index("ix_integration_credential_references_credential_id", "integration_credential_references", ["credential_id"])
        op.create_index("ix_integration_credential_references_provider_id", "integration_credential_references", ["provider_id"])
        op.create_index("ix_integration_credential_references_subject_user_id", "integration_credential_references", ["subject_user_id"])
        op.create_index("ix_integration_credential_references_organization_id", "integration_credential_references", ["organization_id"])
        op.create_index("ix_integration_credential_references_expires_at", "integration_credential_references", ["expires_at"])


def downgrade():
    op.drop_table("integration_credential_references")
    op.drop_table("integration_credentials")
