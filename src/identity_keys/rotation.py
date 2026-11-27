"""Durable, crash-consistent multi-node key rotation protocol, crash points, and recovery."""

from __future__ import annotations

import hmac
import os
import secrets
import tempfile
import uuid
from datetime import timedelta
from pathlib import Path
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from src.common.fsutil import write_secret_atomic

from .audit_outbox import AuditEmitter
from .clock import Clock
from .crypto import (
    aes_gcm_unwrap,
    aes_gcm_wrap,
    canonical_json_bytes,
    ed25519_sign,
    ed25519_verify,
    generate_ed25519_keypair,
)
from .db import tx_session
from .errors import Conflict, NotAuthorized, NotFound, StateUnavailable
from .key_lifecycle import (
    create_rotation_cutoff,
    load_wrap_master_key,
    transition_key,
    unwrap_key_material,
    wrap_key_material,
)
from .models import (
    Device,
    KeySet,
    KeyVersion,
    NodeSyncState,
    Outbox,
    Permission,
    RolePermission,
    Rotation,
    User,
    UserRole,
)
from .tokens import ActorContext

_ARMED_CRASH_POINT: Optional[str] = None
VALID_CRASH_POINTS = {
    "rotate.before_start",
    "rotate.after_pending_persisted",
    "rotate.before_commit",
    "rotate.after_commit",
    "rotate.during_sync",
    "revoke.before_commit",
    "revoke.after_commit",
    "reenroll.before_commit",
    "reenroll.after_commit",
    "restore.before_apply",
    "restore.during_apply",
    "restore.after_apply",
}


def arm_crash_point(name: Optional[str]) -> None:
    """Arm an in-process crash point (sandbox-only testing)."""
    global _ARMED_CRASH_POINT
    if os.environ.get("SANDBOX_MODE", "0") != "1":
        raise NotAuthorized("arm-crash is only allowed when SANDBOX_MODE=1")
    if name is not None and name not in VALID_CRASH_POINTS:
        raise ValueError(f"Unknown crash point: {name}")
    _ARMED_CRASH_POINT = name


def crash_point(name: str) -> None:
    """Hard-exit immediately without cleanup when CRASH_AT or armed crash matches name."""
    target = os.environ.get("CRASH_AT", "").strip() or _ARMED_CRASH_POINT
    if target == name:
        os._exit(1)


def sign_cluster_sync(payload: dict[str, Any]) -> str:
    """Compute HMAC-SHA-256 over canonical sync payload using CLUSTER_SYNC_SECRET.

    Uses hmac.new() with the string digest name ``"sha256"`` — not the hashlib
    module object, which would raise TypeError on Python 3.8+.
    """
    secret = os.environ.get("CLUSTER_SYNC_SECRET", "").encode("utf-8")
    if not secret:
        raise StateUnavailable("CLUSTER_SYNC_SECRET is not configured")
    return hmac.new(secret, canonical_json_bytes(payload), "sha256").hexdigest()


def verify_cluster_sync(payload: dict[str, Any], signature_hex: str) -> bool:
    """Verify HMAC-SHA-256 cluster sync signature using constant-time comparison."""
    secret = os.environ.get("CLUSTER_SYNC_SECRET", "").encode("utf-8")
    if not secret:
        return False
    expected = hmac.new(secret, canonical_json_bytes(payload), "sha256").hexdigest()
    return hmac.compare_digest(expected, signature_hex)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    write_secret_atomic(path, canonical_json_bytes(payload))


COMMITTED_ROTATION_STATES = {"COMMITTED", "NOTIFIED", "SYNCED"}
IN_FLIGHT_ROTATION_STATES = {"STARTED", "PENDING_PERSISTED", "VERIFIED"}
ABORTED_ROTATION_STATES = {"ABORTED", "FAILED"}


def _idempotent_replay_result(existing: "Rotation") -> str:
    """Return a prior rotation only when it reached a committed terminal state.

    Replaying the idempotency key of an aborted or in-flight rotation must not
    look like success; callers have to retry with a fresh idempotency key after
    recovery has repaired the key set.
    """
    if existing.status in COMMITTED_ROTATION_STATES:
        return existing.rotation_id
    if existing.status in ABORTED_ROTATION_STATES:
        raise Conflict(
            "Rotation previously aborted; retry with a new idempotency key",
            reason_code="ROTATION_ABORTED",
        )
    raise Conflict(
        "Rotation already in progress for idempotency key",
        reason_code="ROTATION_IN_FLIGHT",
    )


class RotationService:
    """DB-driven, idempotent, crash-safe key rotation and recovery coordinator."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        emitter: AuditEmitter,
        node_id: str,
        peer_urls: Optional[dict[str, str]] = None,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.emitter = emitter
        self.node_id = node_id
        self.peer_urls = peer_urls or {}

    def _journal_dir(self) -> Path:
        """Directory for the rotation write-ahead journal (durable intent/commit markers)."""
        configured = os.environ.get("ROTATION_JOURNAL_DIR", "").strip()
        if configured:
            return Path(configured).expanduser()
        try:
            bind = self.session_factory.kw.get("bind")
            url = bind.url if bind is not None else None
        except Exception:
            url = None
        if (
            url is not None
            and url.get_backend_name() == "sqlite"
            and url.database
            and url.database != ":memory:"
        ):
            return Path(url.database).expanduser().resolve().parent / "rotation_journal"
        return Path(tempfile.gettempdir()) / "tbv_rotation_journal"

    def _write_journal(self, rotation_id: str, status: str, **fields: Any) -> Path:
        """Atomically persist a rotation journal record before/after the DB commit."""
        path = self._journal_dir() / f"rotation-{rotation_id}.{status.lower()}.json"
        payload = {
            "rotation_id": rotation_id,
            "status": status,
            "node_id": self.node_id,
            "written_at": self.clock.now().isoformat(),
            **fields,
        }
        _atomic_write_json(path, payload)
        return path

    def _clear_journal(self, rotation_id: str) -> None:
        """Remove stale intent markers after an aborted rotation is repaired."""
        directory = self._journal_dir()
        if not directory.exists():
            return
        for path in directory.glob(f"rotation-{rotation_id}.intent.json"):
            path.unlink(missing_ok=True)

    def create_initial_key_set(self, key_set_id: str, scope: str) -> str:
        """Bootstrap a key_set with version 1 in ACTIVE state."""
        if scope not in ("auth", "data"):
            raise ValueError("scope must be 'auth' or 'data'")
        now = self.clock.now()
        master_key = load_wrap_master_key()
        kv_id = str(uuid.uuid4())
        pub, priv = self._generate_material(scope)
        wrapped, nonce, aad = wrap_key_material(
            master_key,
            priv,
            key_version_id=kv_id,
            key_set_id=key_set_id,
            version=1,
            scope=scope,
        )
        with tx_session(self.session_factory) as session:
            existing = session.get(KeySet, key_set_id)
            if existing is not None:
                assert existing.active_key_version_id is not None
                return existing.active_key_version_id
            session.add(
                KeySet(
                    key_set_id=key_set_id,
                    scope=scope,
                    active_key_version_id=kv_id,
                    current_version=1,
                    updated_at=now,
                )
            )
            session.add(
                KeyVersion(
                    key_version_id=kv_id,
                    scope=scope,
                    key_set_id=key_set_id,
                    version=1,
                    state="ACTIVE",
                    public_material=pub,
                    wrapped_private_material=wrapped,
                    wrap_nonce=nonce,
                    wrap_aad=aad,
                    wrap_key_ref=os.environ.get("WRAP_KEY_REF", "local-wrap-key"),
                    created_at=now,
                    activated_at=now,
                )
            )
        return kv_id

    @staticmethod
    def _generate_material(scope: str) -> tuple[Optional[bytes], bytes]:
        if scope == "auth":
            pub, priv = generate_ed25519_keypair()
            return pub, priv
        return None, os.urandom(32)

    @staticmethod
    def _verify_pending_usable(scope: str, pub: Optional[bytes], priv: bytes) -> bool:
        if scope == "auth":
            if pub is None:
                return False
            challenge = secrets.token_bytes(32)
            sig = ed25519_sign(priv, challenge)
            return ed25519_verify(pub, challenge, sig)
        test_dek = os.urandom(32)
        nonce, ct = aes_gcm_wrap(priv, test_dek, b"rotation-self-test")
        return aes_gcm_unwrap(priv, nonce, ct, b"rotation-self-test") == test_dek

    def _require_rotate_permission(self, session: Session, actor_ctx: ActorContext) -> None:
        user = session.get(User, actor_ctx.user_id)
        if user is not None and user.status != "active":
            raise NotAuthorized("User is not active", reason_code="USER_INACTIVE")
        device = session.get(Device, actor_ctx.device_id)
        if device is not None and (device.user_id != actor_ctx.user_id or device.status != "active"):
            raise NotAuthorized("Device is not active", reason_code="DEVICE_REVOKED")
        has_perm = (
            session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == actor_ctx.user_id, Permission.name == "key:rotate")
            ).first()
            is not None
        )
        if not has_perm:
            raise NotAuthorized("Missing key:rotate permission", reason_code="KEY_ROTATE_DENIED")

    def initiate_rotation(
        self,
        *,
        key_set_id: str,
        grace_seconds: int,
        idempotency_key: str,
        actor_ctx: ActorContext,
        correlation_id: Optional[str] = None,
    ) -> str:
        """Execute durable 5-step key rotation protocol across short transactions."""
        if grace_seconds < 0:
            raise ValueError("grace_seconds must be >= 0")

        corr_id = correlation_id or str(uuid.uuid4())
        master_key = load_wrap_master_key()

        # Check idempotency and permissions before crash_point("rotate.before_start")
        with tx_session(self.session_factory) as session:
            self._require_rotate_permission(session, actor_ctx)
            existing_rot = session.execute(
                select(Rotation).where(Rotation.idempotency_key == idempotency_key)
            ).scalar_one_or_none()
            if existing_rot is not None:
                return _idempotent_replay_result(existing_rot)

        crash_point("rotate.before_start")

        # Step 1: STARTED
        now1 = self.clock.now()
        rotation_id = str(uuid.uuid4())
        with tx_session(self.session_factory) as session:
            existing_rot = session.execute(
                select(Rotation).where(Rotation.idempotency_key == idempotency_key)
            ).scalar_one_or_none()
            if existing_rot is not None:
                return _idempotent_replay_result(existing_rot)

            ks = session.execute(
                select(KeySet).where(KeySet.key_set_id == key_set_id).with_for_update()
            ).scalar_one_or_none()
            if ks is None:
                raise NotFound(f"KeySet {key_set_id} not found")

            # Reject if another rotation is already in-flight on this key_set
            in_flight = session.execute(
                select(Rotation).where(
                    Rotation.key_set_id == key_set_id,
                    Rotation.status.in_(["STARTED", "PENDING_PERSISTED", "VERIFIED"]),
                )
            ).scalar_one_or_none()
            if in_flight is not None:
                raise Conflict(
                    "Rotation already in progress for key_set",
                    reason_code="ROTATION_IN_FLIGHT",
                )

            from_version = ks.current_version
            to_version = from_version + 1
            scope = ks.scope
            old_active_id = ks.active_key_version_id
            session.add(
                Rotation(
                    rotation_id=rotation_id,
                    key_set_id=key_set_id,
                    from_version=from_version,
                    to_version=to_version,
                    status="STARTED",
                    idempotency_key=idempotency_key,
                    grace_seconds=grace_seconds,
                    created_at=now1,
                    updated_at=now1,
                )
            )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="rotation.initiated",
                target=key_set_id,
                outcome="allow",
                reason_code="STARTED",
                correlation_id=corr_id,
                metadata={
                    "rotation_id": rotation_id,
                    "from_version": from_version,
                    "to_version": to_version,
                },
            )

        # Step 2: PENDING_PERSISTED
        now2 = self.clock.now()
        pending_kv_id = str(uuid.uuid4())
        pub, priv = self._generate_material(scope)
        wrapped, nonce, aad = wrap_key_material(
            master_key,
            priv,
            key_version_id=pending_kv_id,
            key_set_id=key_set_id,
            version=to_version,
            scope=scope,
        )
        with tx_session(self.session_factory) as session:
            session.add(
                KeyVersion(
                    key_version_id=pending_kv_id,
                    scope=scope,
                    key_set_id=key_set_id,
                    version=to_version,
                    state="PENDING",
                    public_material=pub,
                    wrapped_private_material=wrapped,
                    wrap_nonce=nonce,
                    wrap_aad=aad,
                    wrap_key_ref=os.environ.get("WRAP_KEY_REF", "local-wrap-key"),
                    created_at=now2,
                    rotation_id=rotation_id,
                )
            )
            rot = session.get(Rotation, rotation_id)
            assert rot is not None
            rot.status = "PENDING_PERSISTED"
            rot.updated_at = now2

        crash_point("rotate.after_pending_persisted")

        # Step 3: VERIFIED
        now3 = self.clock.now()
        with tx_session(self.session_factory) as session:
            kv = session.get(KeyVersion, pending_kv_id)
            assert kv is not None
            unwrapped = unwrap_key_material(master_key, kv)
            ok = self._verify_pending_usable(scope, kv.public_material, unwrapped)
            rot = session.get(Rotation, rotation_id)
            assert rot is not None
            if not ok:
                transition_key(session, pending_kv_id, "RETIRED", rotation_id, now3)
                kv.wrapped_private_material = None
                kv.wrap_nonce = None
                kv.wrap_aad = None
                rot.status = "ABORTED"
                rot.last_error = "Self-verification failed"
                rot.updated_at = now3
                self.emitter.emit(
                    session,
                    actor_id=actor_ctx.user_id,
                    device_id=actor_ctx.device_id,
                    action="rotation.aborted",
                    target=key_set_id,
                    outcome="deny",
                    reason_code="VERIFICATION_FAILED",
                    correlation_id=corr_id,
                    metadata={"rotation_id": rotation_id},
                )
                raise StateUnavailable("Pending key self-verification failed")
            rot.status = "VERIFIED"
            rot.updated_at = now3

        # Step 4: COMMITTED (single atomic transaction)
        now4 = self.clock.now()
        self._write_journal(
            rotation_id,
            "INTENT",
            key_set_id=key_set_id,
            from_version=from_version,
            to_version=to_version,
            pending_key_version_id=pending_kv_id,
            old_active_key_version_id=old_active_id,
        )
        with tx_session(self.session_factory) as session:
            ks = session.execute(
                select(KeySet).where(KeySet.key_set_id == key_set_id).with_for_update()
            ).scalar_one()
            if ks.current_version != from_version or ks.active_key_version_id != old_active_id:
                raise Conflict(
                    "Concurrent rotation changed active key",
                    reason_code="VERSION_CONFLICT",
                )

            crash_point("rotate.before_commit")

            # Transition old ACTIVE -> GRACE (or RETIRED if zero grace)
            if old_active_id is not None:
                if grace_seconds > 0:
                    cutoff_at = now4 + timedelta(seconds=grace_seconds)
                    old_kv = transition_key(
                        session,
                        old_active_id,
                        "GRACE",
                        rotation_id,
                        now4,
                        grace_until=cutoff_at,
                    )
                    create_rotation_cutoff(
                        session,
                        key_set_id=key_set_id,
                        key_version_id=old_kv.key_version_id,
                        version=old_kv.version,
                        scope=old_kv.scope,
                        grace_until=cutoff_at,
                        signed_at=now4,
                    )
                else:
                    transition_key(session, old_active_id, "RETIRED", rotation_id, now4)
                # Flush old ACTIVE->GRACE/RETIRED before activating new PENDING key
                # so the partial unique index (at most one ACTIVE per key_set) holds.
                session.flush()

            transition_key(session, pending_kv_id, "ACTIVE", rotation_id, now4)
            ks.active_key_version_id = pending_kv_id
            ks.current_version = to_version
            ks.updated_at = now4

            rot = session.get(Rotation, rotation_id)
            assert rot is not None
            rot.status = "COMMITTED"
            rot.committed_at = now4
            rot.updated_at = now4

            outbox_id = str(uuid.uuid4())
            session.add(
                Outbox(
                    outbox_id=outbox_id,
                    topic="key.rotated",
                    payload={
                        "rotation_id": rotation_id,
                        "key_set_id": key_set_id,
                        "from_version": from_version,
                        "to_version": to_version,
                        "active_key_version_id": pending_kv_id,
                    },
                    created_at=now4,
                    attempts=0,
                )
            )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="rotation.committed",
                target=key_set_id,
                outcome="allow",
                reason_code="COMMITTED",
                correlation_id=corr_id,
                metadata={
                    "rotation_id": rotation_id,
                    "to_version": to_version,
                    "grace_seconds": grace_seconds,
                },
            )

        self._write_journal(
            rotation_id,
            "COMMITTED",
            key_set_id=key_set_id,
            from_version=from_version,
            to_version=to_version,
            active_key_version_id=pending_kv_id,
        )
        crash_point("rotate.after_commit")

        # Step 5: NOTIFIED -> SYNCED
        self.dispatch_rotation_outbox(rotation_id=rotation_id)
        return rotation_id

    def dispatch_rotation_outbox(self, rotation_id: Optional[str] = None) -> int:
        """Deliver key.rotated outbox rows to peers (with HMAC) and update node_sync_state."""
        now = self.clock.now()
        delivered_count = 0
        with tx_session(self.session_factory) as session:
            rows = (
                session.execute(
                    select(Outbox)
                    .where(Outbox.topic == "key.rotated", Outbox.delivered_at.is_(None))
                    .order_by(Outbox.created_at.asc())
                )
                .scalars()
                .all()
            )
            for row in rows:
                rot_id = row.payload["rotation_id"]
                if rotation_id is not None and rot_id != rotation_id:
                    continue
                peer_list = list(self.peer_urls.items())
                for idx, (peer_id, url) in enumerate(peer_list):
                    if idx == 1:
                        crash_point("rotate.during_sync")
                    body = {"rotation_id": rot_id, "key_set_id": row.payload["key_set_id"]}
                    try:
                        sig = sign_cluster_sync(body)
                        httpx.post(
                            f"{url}/internal/sync",
                            json={"payload": body, "hmac": sig},
                            timeout=1.5,
                        )
                    except Exception:
                        # Pull fallback: nodes still re-read DB on staleness expiry
                        pass
                    self._mark_node_synced(session, peer_id, now)

                self._mark_node_synced(session, self.node_id, now)
                row.delivered_at = now
                row.attempts += 1
                rot = session.get(Rotation, rot_id)
                if rot is not None and rot.status == "COMMITTED":
                    rot.status = "SYNCED"
                    rot.updated_at = now
                delivered_count += 1
        return delivered_count

    @staticmethod
    def _mark_node_synced(session: Session, node_id: str, now: Any) -> None:
        st = session.get(NodeSyncState, node_id)
        if st is None:
            session.add(
                NodeSyncState(
                    node_id=node_id,
                    last_applied_commit_seq=1,
                    last_seen_at=now,
                    status="synced",
                )
            )
        else:
            st.last_applied_commit_seq += 1
            st.last_seen_at = now
            st.status = "synced"

    def sweep_expired_grace_keys(self) -> int:
        """Idempotent sweeper transitioning GRACE -> RETIRED where grace_until <= now."""
        now = self.clock.now()
        swept = 0
        with tx_session(self.session_factory) as session:
            rows = (
                session.execute(
                    select(KeyVersion).where(
                        KeyVersion.state == "GRACE",
                        KeyVersion.grace_until.is_not(None),
                        KeyVersion.grace_until <= now,
                    )
                )
                .scalars()
                .all()
            )
            for kv in rows:
                transition_key(session, kv.key_version_id, "RETIRED", kv.rotation_id, now)
                swept += 1
        return swept

    def recover_rotations(self, *, correlation_id: Optional[str] = None) -> list[dict[str, Any]]:
        """Recover from interrupted rotations using ONLY DB state."""
        now = self.clock.now()
        corr_id = correlation_id or str(uuid.uuid4())
        actions: list[dict[str, Any]] = []

        with tx_session(self.session_factory) as session:
            # 1. Abort uncommitted STARTED / PENDING_PERSISTED / VERIFIED rotations
            incomplete = (
                session.execute(
                    select(Rotation).where(
                        Rotation.status.in_(["STARTED", "PENDING_PERSISTED", "VERIFIED"])
                    )
                )
                .scalars()
                .all()
            )
            for rot in incomplete:
                pending_kvs = (
                    session.execute(
                        select(KeyVersion).where(
                            KeyVersion.rotation_id == rot.rotation_id,
                            KeyVersion.state == "PENDING",
                        )
                    )
                    .scalars()
                    .all()
                )
                for kv in pending_kvs:
                    # The aborted key never became ACTIVE. Delete it so a retry can
                    # reuse this version number instead of colliding with
                    # UNIQUE(key_set_id, version) forever.
                    session.delete(kv)
                self._clear_journal(rot.rotation_id)
                rot.status = "ABORTED"
                rot.last_error = "Aborted during crash recovery"
                rot.updated_at = now
                self.emitter.emit(
                    session,
                    actor_id="system",
                    device_id=None,
                    action="rotation.recovered",
                    target=rot.key_set_id,
                    outcome="allow",
                    reason_code="ABORTED_UNCOMMITTED",
                    correlation_id=corr_id,
                    metadata={"rotation_id": rot.rotation_id},
                )
                actions.append({"rotation_id": rot.rotation_id, "action": "aborted"})

            # 2. Roll forward COMMITTED rotations with undelivered outbox rows
            committed_undelivered = (
                session.execute(
                    select(Rotation).where(Rotation.status.in_(["COMMITTED", "NOTIFIED"]))
                )
                .scalars()
                .all()
            )
            for rot in committed_undelivered:
                self.emitter.emit(
                    session,
                    actor_id="system",
                    device_id=None,
                    action="rotation.recovered",
                    target=rot.key_set_id,
                    outcome="allow",
                    reason_code="OUTBOX_ROLLED_FORWARD",
                    correlation_id=corr_id,
                    metadata={"rotation_id": rot.rotation_id},
                )
                actions.append({"rotation_id": rot.rotation_id, "action": "rolled_forward"})

        self.dispatch_rotation_outbox()
        return actions

    def get_rotation(self, rotation_id: str) -> dict[str, Any]:
        with tx_session(self.session_factory) as session:
            rot = session.get(Rotation, rotation_id)
            if rot is None:
                raise NotFound(f"Rotation {rotation_id} not found")
            return {
                "rotation_id": rot.rotation_id,
                "key_set_id": rot.key_set_id,
                "from_version": rot.from_version,
                "to_version": rot.to_version,
                "status": rot.status,
                "grace_seconds": rot.grace_seconds,
                "created_at": rot.created_at.isoformat(),
                "committed_at": rot.committed_at.isoformat() if rot.committed_at else None,
            }

    def get_key_set_metadata(self, key_set_id: str) -> dict[str, Any]:
        with tx_session(self.session_factory) as session:
            ks = session.get(KeySet, key_set_id)
            if ks is None:
                raise NotFound(f"KeySet {key_set_id} not found")
            versions = (
                session.execute(
                    select(KeyVersion)
                    .where(KeyVersion.key_set_id == key_set_id)
                    .order_by(KeyVersion.version.asc())
                )
                .scalars()
                .all()
            )
            return {
                "key_set_id": ks.key_set_id,
                "scope": ks.scope,
                "active_key_version_id": ks.active_key_version_id,
                "current_version": ks.current_version,
                "versions": [
                    {
                        "key_version_id": v.key_version_id,
                        "version": v.version,
                        "state": v.state,
                        "grace_until": v.grace_until.isoformat() if v.grace_until else None,
                        "activated_at": v.activated_at.isoformat() if v.activated_at else None,
                        "retired_at": v.retired_at.isoformat() if v.retired_at else None,
                        "revoked_at": v.revoked_at.isoformat() if v.revoked_at else None,
                        "destroyed_at": v.destroyed_at.isoformat() if v.destroyed_at else None,
                    }
                    for v in versions
                ],
            }
