"""SQLAlchemy 2.x ORM models for identity_keys (Phase 1 core + reserved tables)."""

from datetime import datetime
from typing import Any, Dict, Optional

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    Enum,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from .db import Base

JSON_TYPE = JSON().with_variant(JSONB(), "postgresql")
BIGINT_PK_TYPE = BigInteger().with_variant(Integer(), "sqlite")


class User(Base):
    __tablename__ = "users"

    user_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    handle: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    status: Mapped[str] = mapped_column(
        Enum("active", "disabled", name="user_status_enum"),
        nullable=False,
        default="active",
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Enrollment(Base):
    __tablename__ = "enrollments"

    enrollment_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    device_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    kind: Mapped[str] = mapped_column(
        Enum("first", "re_enroll", name="enrollment_kind_enum"),
        nullable=False,
    )
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    nonce: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Device(Base):
    __tablename__ = "devices"
    __table_args__ = (
        CheckConstraint(
            "status != 'revoked' OR revoked_at IS NOT NULL",
            name="ck_devices_revoked_requires_revoked_at",
        ),
    )

    device_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    label: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(
        Enum("pending", "enrolled", "revoked", name="device_status_enum"),
        nullable=False,
    )
    public_key: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    public_key_alg: Mapped[str] = mapped_column(String(64), nullable=False)
    public_key_fingerprint: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    enrolled_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    replaced_by_device_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("devices.device_id", ondelete="SET NULL"), nullable=True
    )
    enrollment_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("enrollments.enrollment_id", ondelete="RESTRICT"), nullable=False
    )


class Role(Base):
    __tablename__ = "roles"

    role_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class Permission(Base):
    __tablename__ = "permissions"

    permission_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)


class RolePermission(Base):
    __tablename__ = "role_permissions"

    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.role_id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("permissions.permission_id", ondelete="CASCADE"), primary_key=True
    )


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("roles.role_id", ondelete="CASCADE"), primary_key=True
    )


class Rotation(Base):
    __tablename__ = "rotations"

    rotation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    key_set_id: Mapped[str] = mapped_column(String(64), nullable=False)
    from_version: Mapped[int] = mapped_column(Integer, nullable=False)
    to_version: Mapped[int] = mapped_column(Integer, nullable=False)
    status: Mapped[str] = mapped_column(
        Enum(
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
    )
    idempotency_key: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    grace_seconds: Mapped[int] = mapped_column(Integer, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    committed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class KeySet(Base):
    __tablename__ = "key_sets"

    key_set_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    active_key_version_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    current_version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KeyVersion(Base):
    __tablename__ = "key_versions"
    __table_args__ = (
        UniqueConstraint("key_set_id", "version", name="uq_key_versions_set_version"),
        Index(
            "uq_key_versions_one_active_per_set",
            "key_set_id",
            unique=True,
            sqlite_where=text("state = 'ACTIVE'"),
            postgresql_where=text("state = 'ACTIVE'"),
        ),
    )

    key_version_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scope: Mapped[str] = mapped_column(Enum("auth", "data", name="key_scope_enum"), nullable=False)
    key_set_id: Mapped[str] = mapped_column(String(64), nullable=False)
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    state: Mapped[str] = mapped_column(
        Enum("PENDING", "ACTIVE", "GRACE", "RETIRED", "REVOKED", name="key_state_enum"),
        nullable=False,
    )
    public_material: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    wrapped_private_material: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    wrap_nonce: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    wrap_aad: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    wrap_key_ref: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    grace_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    retired_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revoke_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    destroyed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("rotations.rotation_id", ondelete="SET NULL"), nullable=True
    )


class Resource(Base):
    __tablename__ = "resources"

    resource_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    owner_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    kind: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_version_id: Mapped[Optional[str]] = mapped_column(
        String(36), ForeignKey("key_versions.key_version_id", ondelete="SET NULL"), nullable=True
    )
    content_ciphertext: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    content_nonce: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    wrapped_dek: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    dek_nonce: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    dek_aad: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)


class ResourceGrant(Base):
    __tablename__ = "resource_grants"
    __table_args__ = (
        UniqueConstraint(
            "resource_id", "grantee_user_id", "permission", name="uq_resource_grant_tuple"
        ),
    )

    grant_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    resource_id: Mapped[str] = mapped_column(
        String(64), ForeignKey("resources.resource_id", ondelete="CASCADE"), nullable=False
    )
    grantee_user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    permission: Mapped[str] = mapped_column(String(64), nullable=False)
    granted_by: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    granted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class Revocation(Base):
    __tablename__ = "revocations"

    revocation_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target_type: Mapped[str] = mapped_column(
        Enum("device", "key_version", "permission", name="revocation_target_enum"),
        nullable=False,
    )
    target_id: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    revoked_by_actor: Mapped[str] = mapped_column(String(128), nullable=False)
    reason_code: Mapped[str] = mapped_column(String(128), nullable=False)
    committed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    commit_seq: Mapped[int] = mapped_column(
        BIGINT_PK_TYPE, unique=True, autoincrement=True, nullable=False
    )


class Outbox(Base):
    __tablename__ = "outbox"

    outbox_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    topic: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class NodeSyncState(Base):
    __tablename__ = "node_sync_state"

    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    last_applied_commit_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    stale: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class CommitSeqCounter(Base):
    __tablename__ = "commit_seq_counter"

    counter_name: Mapped[str] = mapped_column(String(32), primary_key=True)
    last_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)


class RateLimit(Base):
    __tablename__ = "rate_limits"

    scope_key: Mapped[str] = mapped_column(String(128), primary_key=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failures: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    window_start: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    backoff_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AuditOutbox(Base):
    __tablename__ = "audit_outbox"

    event_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    payload: Mapped[Dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    delivered_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class RecoveryCredential(Base):
    __tablename__ = "recovery_credentials"

    credential_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.user_id", ondelete="CASCADE"), nullable=False
    )
    kdf_params: Mapped[Dict[str, Any]] = mapped_column(JSON_TYPE, nullable=False)
    verifier: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Backup(Base):
    __tablename__ = "backups"

    backup_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(32), nullable=False)
    manifest: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False)


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"

    challenge_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    device_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("devices.device_id", ondelete="CASCADE"), nullable=False
    )
    challenge: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class TrustAnchor(Base):
    __tablename__ = "trust_anchor"

    anchor_id: Mapped[str] = mapped_column(String(32), primary_key=True)
    revocation_commit_seq: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    revocation_head_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class RotationCutoff(Base):
    """ML-DSA-65 signed grace cutoff for a rotated key version."""

    __tablename__ = "rotation_cutoffs"

    cutoff_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    key_set_id: Mapped[str] = mapped_column(String(64), nullable=False)
    key_version_id: Mapped[str] = mapped_column(
        String(36),
        ForeignKey("key_versions.key_version_id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )
    version: Mapped[int] = mapped_column(Integer, nullable=False)
    scope: Mapped[str] = mapped_column(String(16), nullable=False)
    grace_until: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    signed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    key_authority_id: Mapped[str] = mapped_column(String(64), nullable=False)
    signer_key_id: Mapped[str] = mapped_column(String(64), nullable=False)
    body_json: Mapped[str] = mapped_column(Text, nullable=False)
    signature: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)


class ClockHighWater(Base):
    """Per-node authoritative wall/monotonic clock high-water mark."""

    __tablename__ = "clock_high_water"

    node_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    wall_high_water: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    monotonic_high_water: Mapped[int] = mapped_column(BigInteger, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
