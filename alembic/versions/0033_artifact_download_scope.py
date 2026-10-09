"""Persist exact managed-input Artifact scope independently of promotion outputs."""
from alembic import op
import sqlalchemy as sa
revision = "0033_artifact_download_scope"
down_revision = "0032_artifact_delegation_scope"
branch_labels = None
depends_on = None

def upgrade():
    op.add_column("delegated_execution_grants", sa.Column("artifact_ids", sa.JSON(), nullable=True))

def downgrade():
    op.drop_column("delegated_execution_grants", "artifact_ids")
