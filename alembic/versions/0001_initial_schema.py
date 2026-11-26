"""Initial schema for identity_keys (core + reserved tables + DB triggers).

Revision ID: 0001_initial_schema
Revises:
Create Date: 2026-11-26
"""

from __future__ import annotations

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision = "0001_initial_schema"
down_revision = None
branch_labels = None
depends_on = None


def _json_type() -> sa.JSON:
    return sa.JSON().with_variant(postgresql.JSONB(astext_type=sa.Text()), "postgresql")


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("user_id", sa.String(36), primary_key=True),
        sa.Column("handle", sa.String(128), nullable=False, unique=True),
        sa.Column(
            "status",
            sa.Enum("active", "disabled", name="user_status_enum"),
            nullable=False,
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "enrollments",
        sa.Column("enrollment_id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("device_id", sa.String(36), nullable=True),
        sa.Column(
            "kind",
            sa.Enum("first", "re_enroll", name="enrollment_kind_enum"),
            nullable=False,
        ),
        sa.Column("status", sa.String(32), nullable=False),
        sa.Column("nonce", sa.String(128), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "devices",
        sa.Column("device_id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("label", sa.String(255), nullable=False),
        sa.Column(
            "status",
            sa.Enum("pending", "enrolled", "revoked", name="device_status_enum"),
            nullable=False,
        ),
        sa.Column("public_key", sa.LargeBinary(), nullable=False),
        sa.Column("public_key_alg", sa.String(64), nullable=False),
        sa.Column("public_key_fingerprint", sa.String(64), nullable=False, unique=True),
        sa.Column("enrolled_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_reason", sa.String(255), nullable=True),
        sa.Column(
            "replaced_by_device_id",
            sa.String(36),
            sa.ForeignKey("devices.device_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column(
            "enrollment_id",
            sa.String(36),
            sa.ForeignKey("enrollments.enrollment_id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.CheckConstraint(
            "status != 'revoked' OR revoked_at IS NOT NULL",
            name="ck_devices_revoked_requires_revoked_at",
        ),
    )

    op.create_table(
        "roles",
        sa.Column("role_id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
    )

    op.create_table(
        "permissions",
        sa.Column("permission_id", sa.String(36), primary_key=True),
        sa.Column("name", sa.String(64), nullable=False, unique=True),
    )

    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            sa.String(36),
            sa.ForeignKey("roles.role_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "permission_id",
            sa.String(36),
            sa.ForeignKey("permissions.permission_id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    op.create_table(
        "user_roles",
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column(
            "role_id",
            sa.String(36),
            sa.ForeignKey("roles.role_id", ondelete="CASCADE"),
            primary_key=True,
        ),
    )

    op.create_table(
        "rotations",
        sa.Column("rotation_id", sa.String(36), primary_key=True),
        sa.Column("key_set_id", sa.String(64), nullable=False),
        sa.Column("from_version", sa.Integer(), nullable=False),
        sa.Column("to_version", sa.Integer(), nullable=False),
        sa.Column(
            "status",
            sa.Enum(
                "STARTED",
                "PENDING_PERSISTED",
                "VERIFIED",
                "COMMITTED",
                "NOTIFIED",
                "SYNCED",
                "ABORTED",
                name="rotation_status_enum",
            ),
            nullable=False,
        ),
        sa.Column("idempotency_key", sa.String(128), nullable=False, unique=True),
        sa.Column("grace_seconds", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("committed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_error", sa.Text(), nullable=True),
    )

    op.create_table(
        "key_versions",
        sa.Column("key_version_id", sa.String(36), primary_key=True),
        sa.Column(
            "scope",
            sa.Enum("auth", "data", name="key_scope_enum"),
            nullable=False,
        ),
        sa.Column("key_set_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column(
            "state",
            sa.Enum("PENDING", "ACTIVE", "GRACE", "RETIRED", "REVOKED", name="key_state_enum"),
            nullable=False,
        ),
        sa.Column("public_material", sa.LargeBinary(), nullable=True),
        sa.Column("wrapped_private_material", sa.LargeBinary(), nullable=True),
        sa.Column("wrap_nonce", sa.LargeBinary(), nullable=True),
        sa.Column("wrap_aad", sa.LargeBinary(), nullable=True),
        sa.Column("wrap_key_ref", sa.String(128), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("grace_until", sa.DateTime(timezone=True), nullable=True),
        sa.Column("retired_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("revoke_reason", sa.String(255), nullable=True),
        sa.Column(
            "rotation_id",
            sa.String(36),
            sa.ForeignKey("rotations.rotation_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.UniqueConstraint("key_set_id", "version", name="uq_key_versions_set_version"),
    )

    op.create_index(
        "uq_key_versions_one_active_per_set",
        "key_versions",
        ["key_set_id"],
        unique=True,
        sqlite_where=sa.text("state = 'ACTIVE'"),
        postgresql_where=sa.text("state = 'ACTIVE'"),
    )

    op.create_table(
        "resources",
        sa.Column("resource_id", sa.String(64), primary_key=True),
        sa.Column(
            "owner_user_id",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kind", sa.String(64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "key_version_id",
            sa.String(36),
            sa.ForeignKey("key_versions.key_version_id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("content_ciphertext", sa.LargeBinary(), nullable=True),
        sa.Column("content_nonce", sa.LargeBinary(), nullable=True),
    )

    op.create_table(
        "resource_grants",
        sa.Column("grant_id", sa.String(36), primary_key=True),
        sa.Column(
            "resource_id",
            sa.String(64),
            sa.ForeignKey("resources.resource_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "grantee_user_id",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("permission", sa.String(64), nullable=False),
        sa.Column(
            "granted_by",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("granted_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=True),
        sa.UniqueConstraint(
            "resource_id", "grantee_user_id", "permission", name="uq_resource_grant_tuple"
        ),
    )

    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.create_table(
            "revocations",
            sa.Column("revocation_id", sa.String(36), primary_key=True),
            sa.Column(
                "target_type",
                sa.Enum("device", "key_version", "permission", name="revocation_target_enum"),
                nullable=False,
            ),
            sa.Column("target_id", sa.String(64), nullable=False),
            sa.Column("user_id", sa.String(36), nullable=True),
            sa.Column("revoked_by_actor", sa.String(128), nullable=False),
            sa.Column("reason_code", sa.String(128), nullable=False),
            sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("commit_seq", sa.BigInteger(), sa.Identity(always=False), unique=True, nullable=False),
        )
    else:
        op.create_table(
            "revocations",
            sa.Column("revocation_id", sa.String(36), nullable=False),
            sa.Column(
                "target_type",
                sa.Enum("device", "key_version", "permission", name="revocation_target_enum"),
                nullable=False,
            ),
            sa.Column("target_id", sa.String(64), nullable=False),
            sa.Column("user_id", sa.String(36), nullable=True),
            sa.Column("revoked_by_actor", sa.String(128), nullable=False),
            sa.Column("reason_code", sa.String(128), nullable=False),
            sa.Column("committed_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("commit_seq", sa.Integer(), primary_key=True, autoincrement=True),
            sa.UniqueConstraint("revocation_id", name="uq_revocations_id"),
        )

    op.create_table(
        "outbox",
        sa.Column("outbox_id", sa.String(36), primary_key=True),
        sa.Column("topic", sa.String(128), nullable=False),
        sa.Column("payload", _json_type(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("attempts", sa.Integer(), nullable=False, server_default="0"),
    )

    op.create_table(
        "node_sync_state",
        sa.Column("node_id", sa.String(64), primary_key=True),
        sa.Column("last_applied_commit_seq", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
    )

    op.create_table(
        "audit_outbox",
        sa.Column("event_id", sa.String(36), primary_key=True),
        sa.Column("payload", _json_type(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("delivered_at", sa.DateTime(timezone=True), nullable=True),
    )

    op.create_table(
        "recovery_credentials",
        sa.Column("credential_id", sa.String(36), primary_key=True),
        sa.Column(
            "user_id",
            sa.String(36),
            sa.ForeignKey("users.user_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("kdf_params", _json_type(), nullable=False),
        sa.Column("verifier", sa.LargeBinary(), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    op.create_table(
        "backups",
        sa.Column("backup_id", sa.String(36), primary_key=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("schema_version", sa.String(32), nullable=False),
        sa.Column("manifest", sa.LargeBinary(), nullable=False),
        sa.Column("status", sa.String(32), nullable=False),
    )

    op.create_table(
        "auth_challenges",
        sa.Column("challenge_id", sa.String(36), primary_key=True),
        sa.Column(
            "device_id",
            sa.String(36),
            sa.ForeignKey("devices.device_id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("challenge", sa.String(128), nullable=False, unique=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )

    # DB-level triggers enforcing monotonic device revocation and append-only revocations
    if dialect == "postgresql":
        op.execute(
            """
            CREATE OR REPLACE FUNCTION prevent_device_unrevoke() RETURNS trigger AS $$
            BEGIN
                IF OLD.status = 'revoked' AND NEW.status <> 'revoked' THEN
                    RAISE EXCEPTION 'Revoked device row cannot transition away from revoked';
                END IF;
                RETURN NEW;
            END;
            $$ LANGUAGE plpgsql;
            CREATE TRIGGER trg_devices_no_unrevoke
                BEFORE UPDATE ON devices
                FOR EACH ROW EXECUTE FUNCTION prevent_device_unrevoke();

            CREATE OR REPLACE FUNCTION prevent_revocations_mutation() RETURNS trigger AS $$
            BEGIN
                RAISE EXCEPTION 'revocations table is append-only';
            END;
            $$ LANGUAGE plpgsql;
            CREATE TRIGGER trg_revocations_append_only
                BEFORE UPDATE OR DELETE ON revocations
                FOR EACH ROW EXECUTE FUNCTION prevent_revocations_mutation();
            """
        )
    else:
        op.execute(
            """
            CREATE TRIGGER trg_devices_no_unrevoke
            BEFORE UPDATE ON devices
            FOR EACH ROW
            WHEN OLD.status = 'revoked' AND NEW.status != 'revoked'
            BEGIN
                SELECT RAISE(ABORT, 'Revoked device row cannot transition away from revoked');
            END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER trg_revocations_no_update
            BEFORE UPDATE ON revocations
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'revocations table is append-only');
            END;
            """
        )
        op.execute(
            """
            CREATE TRIGGER trg_revocations_no_delete
            BEFORE DELETE ON revocations
            FOR EACH ROW
            BEGIN
                SELECT RAISE(ABORT, 'revocations table is append-only');
            END;
            """
        )


def downgrade() -> None:
    dialect = op.get_bind().dialect.name
    if dialect == "postgresql":
        op.execute("DROP TRIGGER IF EXISTS trg_revocations_append_only ON revocations;")
        op.execute("DROP FUNCTION IF EXISTS prevent_revocations_mutation();")
        op.execute("DROP TRIGGER IF EXISTS trg_devices_no_unrevoke ON devices;")
        op.execute("DROP FUNCTION IF EXISTS prevent_device_unrevoke();")
    else:
        op.execute("DROP TRIGGER IF EXISTS trg_revocations_no_delete;")
        op.execute("DROP TRIGGER IF EXISTS trg_revocations_no_update;")
        op.execute("DROP TRIGGER IF EXISTS trg_devices_no_unrevoke;")

    for table in (
        "auth_challenges",
        "backups",
        "recovery_credentials",
        "audit_outbox",
        "node_sync_state",
        "outbox",
        "revocations",
        "resource_grants",
        "resources",
        "key_versions",
        "rotations",
        "user_roles",
        "role_permissions",
        "permissions",
        "roles",
        "devices",
        "enrollments",
        "users",
    ):
        op.drop_table(table)

    if dialect == "postgresql":
        for enum_name in (
            "revocation_target_enum",
            "key_state_enum",
            "key_scope_enum",
            "rotation_status_enum",
            "device_status_enum",
            "enrollment_kind_enum",
            "user_status_enum",
        ):
            op.execute(f"DROP TYPE IF EXISTS {enum_name};")
