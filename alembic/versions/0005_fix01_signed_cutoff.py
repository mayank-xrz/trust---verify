"""FIX-01: signed rotation cutoffs and per-node clock high-water marks.

Revision ID: 0005_fix01_signed_cutoff
Revises: 0004_part4_trust_anchor
Create Date: 2026-11-27
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

revision = "0005_fix01_signed_cutoff"
down_revision = "0004_part4_trust_anchor"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "rotation_cutoffs",
        sa.Column("cutoff_id", sa.String(36), primary_key=True),
        sa.Column("key_set_id", sa.String(64), nullable=False),
        sa.Column("key_version_id", sa.String(36), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(16), nullable=False),
        sa.Column("grace_until", sa.DateTime(timezone=True), nullable=False),
        sa.Column("signed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("key_authority_id", sa.String(64), nullable=False),
        sa.Column("signer_key_id", sa.String(64), nullable=False),
        sa.Column("body_json", sa.Text(), nullable=False),
        sa.Column("signature", sa.LargeBinary(), nullable=False),
        sa.ForeignKeyConstraint(
            ["key_version_id"],
            ["key_versions.key_version_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("key_version_id", name="uq_rotation_cutoffs_key_version"),
    )
    op.create_table(
        "clock_high_water",
        sa.Column("node_id", sa.String(64), primary_key=True),
        sa.Column("wall_high_water", sa.DateTime(timezone=True), nullable=False),
        sa.Column("monotonic_high_water", sa.BigInteger(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def downgrade() -> None:
    op.drop_table("clock_high_water")
    op.drop_table("rotation_cutoffs")
