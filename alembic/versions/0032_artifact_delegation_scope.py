"""Persist Artifact delegation project, run, and output scope.

Revision ID: 0032_artifact_delegation_scope
Revises: 0031_integration_credentials
"""
from typing import Union

from alembic import op
import sqlalchemy as sa

revision: str = "0032_artifact_delegation_scope"
down_revision: Union[str, None] = "0031_integration_credentials"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("delegated_execution_grants", sa.Column("project_id", sa.String(255), nullable=True))
    op.add_column("delegated_execution_grants", sa.Column("run_id", sa.String(255), nullable=True))
    op.add_column("delegated_execution_grants", sa.Column("output_ids", sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column("delegated_execution_grants", "output_ids")
    op.drop_column("delegated_execution_grants", "run_id")
    op.drop_column("delegated_execution_grants", "project_id")
