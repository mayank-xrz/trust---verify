"""Part 3 schema: gapless commit_seq_counter, rate_limits, and stale-node tracking.

Revision ID: 0003_part3_revocation_reenroll
Revises: 0002_part2_key_lifecycle
Create Date: 2026-11-26
"""

from __future__ import annotations

from alembic import op
import sqlalchemy as sa

revision = "0003_part3_revocation_reenroll"
down_revision = "0002_part2_key_lifecycle"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "commit_seq_counter",
        sa.Column("counter_name", sa.String(32), primary_key=True),
        sa.Column("last_seq", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.execute("INSERT INTO commit_seq_counter (counter_name, last_seq) VALUES ('revocations', 0)")

    op.create_table(
        "rate_limits",
        sa.Column("scope_key", sa.String(128), primary_key=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("failures", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("window_start", sa.DateTime(timezone=True), nullable=False),
        sa.Column("backoff_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("locked_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    with op.batch_alter_table("node_sync_state") as batch_op:
        batch_op.add_column(sa.Column("stale", sa.Boolean(), nullable=False, server_default=sa.false()))
        batch_op.add_column(sa.Column("last_error", sa.Text(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("node_sync_state") as batch_op:
        batch_op.drop_column("last_error")
        batch_op.drop_column("stale")

    op.drop_table("rate_limits")
    op.drop_table("commit_seq_counter")
