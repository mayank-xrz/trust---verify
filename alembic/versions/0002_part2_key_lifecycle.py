"""Part 2 schema: key_sets table, envelope encryption columns on resources, destroyed_at on key_versions.

Revision ID: 0002_part2_key_lifecycle
Revises: 0001_initial_schema
Create Date: 2026-11-26
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0002_part2_key_lifecycle"
down_revision = "0001_initial_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "key_sets",
        sa.Column("key_set_id", sa.String(64), primary_key=True),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("active_key_version_id", sa.String(36), nullable=True),
        sa.Column("current_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )

    with op.batch_alter_table("key_versions") as batch_op:
        batch_op.add_column(sa.Column("destroyed_at", sa.DateTime(timezone=True), nullable=True))

    with op.batch_alter_table("resources") as batch_op:
        batch_op.add_column(sa.Column("wrapped_dek", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("dek_nonce", sa.LargeBinary(), nullable=True))
        batch_op.add_column(sa.Column("dek_aad", sa.LargeBinary(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table("resources") as batch_op:
        batch_op.drop_column("dek_aad")
        batch_op.drop_column("dek_nonce")
        batch_op.drop_column("wrapped_dek")

    with op.batch_alter_table("key_versions") as batch_op:
        batch_op.drop_column("destroyed_at")

    op.drop_table("key_sets")
