"""HIPAA Phase 3b: MFA TOTP replay / consumed-time-step protection

Schema only -- creates one new table, `mfa_used_totp_steps`, closing a
gap TOTP verification's own +-1 step clock-skew window leaves open: the
same valid code could otherwise be redeemed more than once (each
redemption completing a separate, independent MFA challenge and minting
its own new session), since only a *successful* challenge_token's own
jti is single-use, not the underlying TOTP code/time-step itself. See
docs/security-mfa-totp-replay-protection.md and
app/db/models.py::MFAUsedTOTPStep for the full design.

One row per successfully-verified TOTP code (never per attempt -- a
wrong guess never reaches this table). `UNIQUE(device_id, time_step)`
is what actually enforces single-use, atomically and correctly across
any number of horizontally-scaled instances sharing this database, via
a plain INSERT + UNIQUE-constraint-violation catch
(app/services/mfa_service.py::_try_claim_totp_step) -- no new Redis
state, no in-process cache.

No existing table's constraints, indexes, or data are altered. Nothing
in this migration is read by any login path until the corresponding
app/services/mfa_service.py change ships alongside it -- safe to
`alembic upgrade head` on any environment already at 0023_saml_slo.

Revision ID: 0024_mfa_totp_replay_protection
Revises: 0023_saml_slo
Create Date: 2026-08-13

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

revision: str = "0024_mfa_totp_replay_protection"
down_revision: Union[str, None] = "0023_saml_slo"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "mfa_used_totp_steps",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("device_id", sa.Integer(), sa.ForeignKey("mfa_devices.id"), nullable=False),
        sa.Column("time_step", sa.Integer(), nullable=False),
        sa.Column("consumed_at", sa.DateTime(), nullable=False),
        sa.UniqueConstraint("device_id", "time_step", name="uq_mfa_used_totp_step"),
    )
    op.create_index("ix_mfa_used_totp_steps_device_id", "mfa_used_totp_steps", ["device_id"])


def downgrade() -> None:
    # No explicit drop_index before drop_table -- same MySQL FK-backed-
    # index ordering reasoning 0013_mfa_foundation's own downgrade()
    # already documents: drop_table removes the table and every index on
    # it (FK-backing or not) in one DDL statement.
    op.drop_table("mfa_used_totp_steps")
