"""Personal time-zone preference; existing users retain device-local formatting."""
from alembic import op
import sqlalchemy as sa

revision = "0030_user_timezone"
down_revision = "0029_widen_api_key_prefix"
branch_labels = None
depends_on = None


def upgrade():
    op.add_column("users", sa.Column("preferred_timezone", sa.String(100), nullable=True))


def downgrade():
    op.drop_column("users", "preferred_timezone")
