"""Part 4 schema: monotonic trust_anchor table for backup rollback protection.

Revision ID: 0004_part4_trust_anchor
Revises: 0003_part3_revocation_reenroll
Create Date: 2026-11-26
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0004_part4_trust_anchor"
down_revision = "0003_part3_revocation_reenroll"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "trust_anchor",
        sa.Column("anchor_id", sa.String(32), primary_key=True),
        sa.Column("revocation_commit_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("revocation_head_hash", sa.String(64), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("trust_anchor")
