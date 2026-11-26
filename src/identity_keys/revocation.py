"""Durable revocation service, emergency rotation, and per-node watermark sync."""

from __future__ import annotations

import enum
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .audit_outbox import AuditEmitter
from .clock import Clock
from .db import tx_session
from .errors import Conflict, NotAuthorized, NotFound, StateUnavailable
from .key_lifecycle import (
    load_wrap_master_key,
    transition_key,
    unwrap_key_material,
    wrap_key_material,
)
from .models import (
    CommitSeqCounter,
    Device,
    KeySet,
    KeyVersion,
    NodeSyncState,
    Outbox,
    Permission,
    ResourceGrant,
    Revocation,
    RolePermission,
    Rotation,
    UserRole,
)
from .rotation import RotationService, crash_point, sign_cluster_sync
from .services import transition_device_status
from .tokens import ActorContext


class RevocationReason(str, enum.Enum):
    DEVICE_LOST = "DEVICE_LOST"
    DEVICE_COMPROMISED = "DEVICE_COMPROMISED"
    KEY_COMPROMISED = "KEY_COMPROMISED"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    ADMIN_REVOKED = "ADMIN_REVOKED"
    RE_ENROLLMENT = "RE_ENROLLMENT"


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def next_commit_seq(session: Session) -> int:
    """Assign a strictly gapless monotonic commit_seq inside the active DB transaction."""
    row = session.execute(
        select(CommitSeqCounter)
        .where(CommitSeqCounter.counter_name == "revocations")
        .with_for_update()
    ).scalar_one_or_none()
    if row is None:
        row = CommitSeqCounter(counter_name="revocations", last_seq=0)
        session.add(row)
        session.flush()
    row.last_seq += 1
    return row.last_seq


class RevocationService:
    """Authenticated, durable, idempotent revocation across devices, keys, and grants."""

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

    @staticmethod
    def _has_perm(session: Session, user_id: str, perm_name: str) -> bool:
        return (
            session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user_id, Permission.name == perm_name)
            ).first()
            is not None
        )

    def revoke_device(
        self,
        actor_ctx: ActorContext,
        device_id: str,
        reason_code: RevocationReason | str,
        *,
        correlation_id: Optional[str] = None,
        push_sync: bool = True,
    ) -> dict[str, Any]:
        """Revoke a device atomically in one transaction (idempotent)."""
        reason = RevocationReason(reason_code)
        now = self.clock.now()
        corr_id = correlation_id or str(uuid.uuid4())

        with tx_session(self.session_factory) as session:
            dev = session.get(Device, device_id)
            if dev is None:
                raise NotFound(f"Device {device_id} not found")

            is_admin = self._has_perm(session, actor_ctx.user_id, "device:revoke")
            is_owner = dev.user_id == actor_ctx.user_id
            if not is_admin and not is_owner:
                raise NotAuthorized("Not permitted to revoke this device", reason_code="FORBIDDEN")
            # Lower-privileged actor cannot revoke a higher-privileged admin's device
            if not is_admin and self._has_perm(session, dev.user_id, "key:rotate") and not is_owner:
                raise NotAuthorized(
                    "Cannot revoke higher-privileged device", reason_code="FORBIDDEN"
                )

            if dev.status == "revoked":
                existing = session.execute(
                    select(Revocation).where(
                        Revocation.target_type == "device",
                        Revocation.target_id == device_id,
                    )
                ).scalar_one()
                return {
                    "revocation_id": existing.revocation_id,
                    "target_type": "device",
                    "target_id": device_id,
                    "commit_seq": existing.commit_seq,
                    "idempotent_replay": True,
                }

            crash_point("revoke.before_commit")
            seq = next_commit_seq(session)
            rev_id = str(uuid.uuid4())
            transition_device_status(dev, "revoked", now, reason.value)
            session.add(
                Revocation(
                    revocation_id=rev_id,
                    target_type="device",
                    target_id=device_id,
                    user_id=dev.user_id,
                    revoked_by_actor=actor_ctx.user_id,
                    reason_code=reason.value,
                    committed_at=now,
                    commit_seq=seq,
                )
            )
            session.add(
                Outbox(
                    outbox_id=str(uuid.uuid4()),
                    topic="revocation.committed",
                    payload={"revocation_id": rev_id, "commit_seq": seq, "target_id": device_id},
                    created_at=now,
                    attempts=0,
                )
            )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="revocation.device",
                target=device_id,
                outcome="allow",
                reason_code=reason.value,
                correlation_id=corr_id,
                metadata={"revocation_id": rev_id, "commit_seq": seq},
            )

        crash_point("revoke.after_commit")
        if push_sync:
            self._push_sync_hint(seq)
        return {
            "revocation_id": rev_id,
            "target_type": "device",
            "target_id": device_id,
            "commit_seq": seq,
            "idempotent_replay": False,
        }

    def revoke_key_version(
        self,
        actor_ctx: ActorContext,
        key_version_id: str,
        reason_code: RevocationReason | str,
        *,
        correlation_id: Optional[str] = None,
        push_sync: bool = True,
    ) -> dict[str, Any]:
        """Revoke a single key_version atomically (idempotent)."""
        reason = RevocationReason(reason_code)
        now = self.clock.now()
        corr_id = correlation_id or str(uuid.uuid4())

        with tx_session(self.session_factory) as session:
            if not (
                self._has_perm(session, actor_ctx.user_id, "key:rotate")
                or self._has_perm(session, actor_ctx.user_id, "device:revoke")
            ):
                raise NotAuthorized(
                    "Missing permission to revoke key version", reason_code="FORBIDDEN"
                )

            kv = session.get(KeyVersion, key_version_id)
            if kv is None:
                raise NotFound(f"KeyVersion {key_version_id} not found")

            if kv.state == "REVOKED":
                existing = session.execute(
                    select(Revocation).where(
                        Revocation.target_type == "key_version",
                        Revocation.target_id == key_version_id,
                    )
                ).scalar_one()
                return {
                    "revocation_id": existing.revocation_id,
                    "target_type": "key_version",
                    "target_id": key_version_id,
                    "commit_seq": existing.commit_seq,
                    "idempotent_replay": True,
                }

            seq = next_commit_seq(session)
            rev_id = str(uuid.uuid4())
            transition_key(
                session, key_version_id, "REVOKED", None, now, revoke_reason=reason.value
            )
            session.add(
                Revocation(
                    revocation_id=rev_id,
                    target_type="key_version",
                    target_id=key_version_id,
                    user_id=None,
                    revoked_by_actor=actor_ctx.user_id,
                    reason_code=reason.value,
                    committed_at=now,
                    commit_seq=seq,
                )
            )
            session.add(
                Outbox(
                    outbox_id=str(uuid.uuid4()),
                    topic="revocation.committed",
                    payload={
                        "revocation_id": rev_id,
                        "commit_seq": seq,
                        "target_id": key_version_id,
                    },
                    created_at=now,
                    attempts=0,
                )
            )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="revocation.key_version",
                target=key_version_id,
                outcome="allow",
                reason_code=reason.value,
                correlation_id=corr_id,
                metadata={"revocation_id": rev_id, "commit_seq": seq},
            )

        if push_sync:
            self._push_sync_hint(seq)
        return {
            "revocation_id": rev_id,
            "target_type": "key_version",
            "target_id": key_version_id,
            "commit_seq": seq,
            "idempotent_replay": False,
        }

    def revoke_permission(
        self,
        actor_ctx: ActorContext,
        user_id: str,
        grant_id_or_perm: str,
        reason_code: RevocationReason | str,
        *,
        correlation_id: Optional[str] = None,
        push_sync: bool = True,
    ) -> dict[str, Any]:
        """Revoke a user's ResourceGrant atomically (idempotent)."""
        reason = RevocationReason(reason_code)
        now = self.clock.now()
        corr_id = correlation_id or str(uuid.uuid4())

        with tx_session(self.session_factory) as session:
            if not self._has_perm(session, actor_ctx.user_id, "device:revoke"):
                raise NotAuthorized("Missing permission to revoke grants", reason_code="FORBIDDEN")

            grant = session.get(ResourceGrant, grant_id_or_perm)
            if grant is None:
                grant = session.execute(
                    select(ResourceGrant).where(
                        ResourceGrant.grantee_user_id == user_id,
                        ResourceGrant.permission == grant_id_or_perm,
                    )
                ).scalar_one_or_none()
            if grant is None:
                raise NotFound("ResourceGrant not found")

            if grant.revoked_at is not None:
                existing = session.execute(
                    select(Revocation).where(
                        Revocation.target_type == "permission",
                        Revocation.target_id == grant.grant_id,
                    )
                ).scalar_one()
                return {
                    "revocation_id": existing.revocation_id,
                    "target_type": "permission",
                    "target_id": grant.grant_id,
                    "commit_seq": existing.commit_seq,
                    "idempotent_replay": True,
                }

            seq = next_commit_seq(session)
            rev_id = str(uuid.uuid4())
            grant.revoked_at = now
            session.add(
                Revocation(
                    revocation_id=rev_id,
                    target_type="permission",
                    target_id=grant.grant_id,
                    user_id=user_id,
                    revoked_by_actor=actor_ctx.user_id,
                    reason_code=reason.value,
                    committed_at=now,
                    commit_seq=seq,
                )
            )
            session.add(
                Outbox(
                    outbox_id=str(uuid.uuid4()),
                    topic="revocation.committed",
                    payload={
                        "revocation_id": rev_id,
                        "commit_seq": seq,
                        "target_id": grant.grant_id,
                    },
                    created_at=now,
                    attempts=0,
                )
            )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="revocation.permission",
                target=grant.grant_id,
                outcome="allow",
                reason_code=reason.value,
                correlation_id=corr_id,
                metadata={"revocation_id": rev_id, "commit_seq": seq, "user_id": user_id},
            )

        if push_sync:
            self._push_sync_hint(seq)
        return {
            "revocation_id": rev_id,
            "target_type": "permission",
            "target_id": grant.grant_id,
            "commit_seq": seq,
            "idempotent_replay": False,
        }

    def emergency_rotate(
        self,
        *,
        key_set_id: str,
        idempotency_key: str,
        actor_ctx: ActorContext,
    ) -> dict[str, Any]:
        """Zero-grace emergency rotation: old ACTIVE transitions directly to REVOKED."""
        rot_svc = RotationService(
            self.session_factory, self.clock, self.emitter, self.node_id, self.peer_urls
        )
        master_key = load_wrap_master_key()
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            rot_svc._require_rotate_permission(session, actor_ctx)
            existing = session.execute(
                select(Rotation).where(Rotation.idempotency_key == idempotency_key)
            ).scalar_one_or_none()
            if existing is not None:
                return {"rotation_id": existing.rotation_id, "emergency": True}

            ks = session.execute(
                select(KeySet).where(KeySet.key_set_id == key_set_id).with_for_update()
            ).scalar_one_or_none()
            if ks is None:
                raise NotFound(f"KeySet {key_set_id} not found")

            old_active_id = ks.active_key_version_id
            from_v = ks.current_version
            to_v = from_v + 1
            rot_id = str(uuid.uuid4())
            new_kv_id = str(uuid.uuid4())
            pub, priv = rot_svc._generate_material(ks.scope)
            wrapped, nonce, aad = wrap_key_material(
                master_key,
                priv,
                key_version_id=new_kv_id,
                key_set_id=key_set_id,
                version=to_v,
                scope=ks.scope,
            )
            session.add(
                Rotation(
                    rotation_id=rot_id,
                    key_set_id=key_set_id,
                    from_version=from_v,
                    to_version=to_v,
                    status="STARTED",
                    idempotency_key=idempotency_key,
                    grace_seconds=0,
                    created_at=now,
                    updated_at=now,
                )
            )
            session.flush()
            new_kv = KeyVersion(
                key_version_id=new_kv_id,
                scope=ks.scope,
                key_set_id=key_set_id,
                version=to_v,
                state="PENDING",
                public_material=pub,
                wrapped_private_material=wrapped,
                wrap_nonce=nonce,
                wrap_aad=aad,
                wrap_key_ref=os.environ.get("WRAP_KEY_REF", "local-wrap-key"),
                created_at=now,
                rotation_id=rot_id,
            )
            session.add(new_kv)
            session.flush()
            if not rot_svc._verify_pending_usable(
                ks.scope, pub, unwrap_key_material(master_key, new_kv)
            ):
                raise Conflict("Emergency key verification failed")

            seq = next_commit_seq(session)
            if old_active_id is not None:
                transition_key(
                    session, old_active_id, "REVOKED", rot_id, now, revoke_reason="EMERGENCY_ROTATE"
                )
                session.add(
                    Revocation(
                        revocation_id=str(uuid.uuid4()),
                        target_type="key_version",
                        target_id=old_active_id,
                        user_id=None,
                        revoked_by_actor=actor_ctx.user_id,
                        reason_code=RevocationReason.KEY_COMPROMISED.value,
                        committed_at=now,
                        commit_seq=seq,
                    )
                )
                session.flush()

            transition_key(session, new_kv_id, "ACTIVE", rot_id, now)
            ks.active_key_version_id = new_kv_id
            ks.current_version = to_v
            ks.updated_at = now
            rot = session.get(Rotation, rot_id)
            assert rot is not None
            rot.status = "COMMITTED"
            rot.committed_at = now
            rot.updated_at = now
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="rotation.emergency",
                target=key_set_id,
                outcome="allow",
                reason_code="EMERGENCY_ROTATED",
                metadata={"rotation_id": rot_id, "revoked_key_version_id": old_active_id},
            )
        self._push_sync_hint(seq)
        return {"rotation_id": rot_id, "active_key_version_id": new_kv_id, "emergency": True}

    def _push_sync_hint(self, commit_seq: int) -> None:
        body = {"commit_seq": commit_seq, "topic": "revocation.committed"}
        try:
            sig = sign_cluster_sync(body)
        except StateUnavailable:
            return
        for url in self.peer_urls.values():
            try:
                httpx.post(f"{url}/internal/sync", json={"payload": body, "hmac": sig}, timeout=1.0)
            except Exception:
                pass


class NodeSyncManager:
    """Tracks per-node revocation watermark, pull sync, and stale-node fail-closed checks."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        node_id: str,
        stale_after_ms: int = 2000,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.node_id = node_id
        self.stale_after_ms = stale_after_ms
        self.watermark: int = 0
        self.last_sync_at: datetime | None = None
        self.db_reachable: bool = True
        self.revoked_devices: set[str] = set()
        self.revoked_keys: set[str] = set()

    def pull_revocations(self) -> int:
        """Pull revocations > watermark ordered by commit_seq and advance watermark."""
        now = self.clock.now()
        try:
            with tx_session(self.session_factory) as session:
                rows = (
                    session.execute(
                        select(Revocation)
                        .where(Revocation.commit_seq > self.watermark)
                        .order_by(Revocation.commit_seq.asc())
                    )
                    .scalars()
                    .all()
                )
                for row in rows:
                    if row.commit_seq != self.watermark + 1 and self.watermark > 0:
                        # Contiguous range check; gapless Counter ensures +1
                        break
                    if row.target_type == "device":
                        self.revoked_devices.add(row.target_id)
                    elif row.target_type == "key_version":
                        self.revoked_keys.add(row.target_id)
                    self.watermark = row.commit_seq

                st = session.get(NodeSyncState, self.node_id)
                if st is None:
                    session.add(
                        NodeSyncState(
                            node_id=self.node_id,
                            last_applied_commit_seq=self.watermark,
                            last_seen_at=now,
                            status="synced",
                            stale=False,
                        )
                    )
                else:
                    st.last_applied_commit_seq = self.watermark
                    st.last_seen_at = now
                    st.status = "synced"
                    st.stale = False
                    st.last_error = None

                self.last_sync_at = now
                self.db_reachable = True
                return self.watermark
        except Exception:
            self.db_reachable = False
            return self.watermark

    def is_stale(self) -> bool:
        """True if node has never synced or last sync is older than stale_after_ms."""
        if not self.db_reachable or self.last_sync_at is None:
            return True
        elapsed_ms = (self.clock.now() - _as_utc(self.last_sync_at)).total_seconds() * 1000.0
        return elapsed_ms > self.stale_after_ms

    def sync_status(self) -> dict[str, Any]:
        """Return node sync watermark, reachability, staleness, and lag."""
        lag = 0
        try:
            with tx_session(self.session_factory) as session:
                counter = session.get(CommitSeqCounter, "revocations")
                head_seq = counter.last_seq if counter else 0
                lag = max(0, head_seq - self.watermark)
                self.db_reachable = True
        except Exception:
            self.db_reachable = False

        return {
            "node_id": self.node_id,
            "watermark": self.watermark,
            "db_reachable": self.db_reachable,
            "stale": self.is_stale(),
            "last_sync_at": self.last_sync_at.isoformat() if self.last_sync_at else None,
            "lag_commit_seq": lag,
        }
