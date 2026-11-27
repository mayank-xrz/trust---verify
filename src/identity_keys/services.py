"""Service layer for enrollment, verification, fail-closed authz, and key metadata."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from .audit_outbox import AuditEmitter
from .clock import Clock
from .crypto import b64d, ed25519_verify, public_key_fingerprint
from .db import tx_session
from .errors import Conflict, IllegalTransition, NotAuthorized, NotFound, Revoked, StateUnavailable
from .key_lifecycle import is_key_acceptable, verify_rotation_cutoff
from .models import (
    AuthChallenge,
    ClockHighWater,
    Device,
    Enrollment,
    KeyVersion,
    Permission,
    RateLimit,
    Resource,
    ResourceGrant,
    RolePermission,
    User,
    UserRole,
)
from .tokens import ActorContext, TokenAuthority


@dataclass(frozen=True)
class AuthzDecision:
    allowed: bool
    reason_code: str
    key_version_id: str | None
    decision_id: str


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


CLOCK_ROLLBACK_REASON = "CLOCK_ROLLBACK_DETECTED"

# Authentication rate limits are per device and per fixed window.  These are
# intentionally generous for a human login flow but stop unbounded challenge
# minting / signature guessing.
AUTH_RATE_WINDOW_SECONDS = 60
AUTH_CHALLENGE_LIMIT_PER_WINDOW = 30
AUTH_VERIFY_LIMIT_PER_WINDOW = 60
CHALLENGE_RETENTION_SECONDS = 3600


def _enforce_rate_limit(
    session: Session,
    scope_key: str,
    limit: int,
    now: datetime,
    *,
    window_seconds: int = AUTH_RATE_WINDOW_SECONDS,
    emitter: AuditEmitter | None = None,
    actor_id: str = "unknown",
) -> None:
    """Increment a fixed-window counter and fail closed once ``limit`` is hit."""
    rl = session.get(RateLimit, scope_key)
    if rl is None:
        rl = RateLimit(
            scope_key=scope_key,
            attempts=0,
            failures=0,
            window_start=now,
            updated_at=now,
        )
        session.add(rl)
        session.flush()
    if (now - _as_utc(rl.window_start)).total_seconds() >= window_seconds:
        rl.attempts = 0
        rl.window_start = now
        rl.locked_until = None
    if rl.attempts >= limit:
        rl.locked_until = now + timedelta(seconds=window_seconds)
        rl.updated_at = now
        if emitter is not None:
            emitter.emit(
                session,
                actor_id=actor_id,
                device_id=None,
                action="ALERT.auth_rate_limit",
                target=scope_key,
                outcome="deny",
                reason_code="ALERT_LOCKOUT",
            )
        session.commit()
        raise NotAuthorized("Rate limit exceeded", reason_code="RATE_LIMITED")
    rl.attempts += 1
    rl.updated_at = now



def check_and_advance_clock_high_water(
    session: Session, node_id: str, now: datetime, monotonic_ns: int
) -> bool:
    """Detect a wall-clock rewind against the persisted per-node high-water mark.

    Returns ``False`` (fail closed) when ``now`` is earlier than the highest
    timestamp this node has already observed.  On success the high-water mark is
    advanced and persisted in the caller's transaction.
    """
    row = session.get(ClockHighWater, node_id)
    if row is not None and _as_utc(now) < _as_utc(row.wall_high_water):
        return False
    if row is None:
        session.add(
            ClockHighWater(
                node_id=node_id,
                wall_high_water=now,
                monotonic_high_water=monotonic_ns,
                updated_at=now,
            )
        )
        return True
    if _as_utc(now) > _as_utc(row.wall_high_water):
        row.wall_high_water = now
    if monotonic_ns > row.monotonic_high_water:
        row.monotonic_high_water = monotonic_ns
    row.updated_at = now
    return True


def transition_device_status(
    device: Device, new_status: str, now: datetime, reason: str | None = None
) -> None:
    """Single legal state-transition function for Device rows."""
    allowed_map = {
        "pending": {"enrolled", "revoked"},
        "enrolled": {"revoked"},
        "revoked": set(),
    }
    if new_status not in allowed_map.get(device.status, set()):
        raise IllegalTransition(f"Illegal device transition: {device.status} -> {new_status}")
    device.status = new_status
    if new_status == "enrolled":
        device.enrolled_at = now
    elif new_status == "revoked":
        device.revoked_at = now
        device.revoked_reason = reason or "revoked"


class IdentityService:
    """Authenticated device enrollment and challenge-response identity verification."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        emitter: AuditEmitter,
        token_authority: TokenAuthority,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.emitter = emitter
        self.token_authority = token_authority

    @staticmethod
    def _sweep_expired_challenges(session: Session, now: datetime) -> int:
        """Delete auth challenges older than the retention window.

        Expired and consumed challenges are already rejected at verification
        time; this only bounds table growth.  The retention window keeps recent
        rows available for forensic review.
        """
        cutoff = now - timedelta(seconds=CHALLENGE_RETENTION_SECONDS)
        result = session.execute(delete(AuthChallenge).where(AuthChallenge.expires_at < cutoff))
        return int(getattr(result, "rowcount", 0) or 0)

    def sweep_expired_challenges(self, now: datetime | None = None) -> int:
        """Public, idempotent challenge sweeper for schedulers and operators."""
        moment = now or self.clock.now()
        with tx_session(self.session_factory) as session:
            return self._sweep_expired_challenges(session, moment)

    def get_enrollment_target(self, enrollment_id: str) -> tuple[str, str]:
        """Return the immutable ``(user_id, kind)`` target of an enrollment.

        Authorization must resolve the target before the single-use nonce is
        consumed, so this read is deliberately separate from ``enroll_device``.
        """
        with self.session_factory() as session:
            enrollment = session.get(Enrollment, enrollment_id)
            if not enrollment:
                raise NotFound("Enrollment not found")
            return str(enrollment.user_id), str(enrollment.kind)

    def start_enrollment(
        self,
        user_id: str,
        kind: str = "first",
        ttl_seconds: int = 300,
        initiated_by: str | None = None,
        initiated_by_admin: bool = False,
    ) -> dict[str, str]:
        """Issue a single-use expiring enrollment nonce for an active user."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            user = session.get(User, user_id)
            if not user:
                raise NotFound(f"User {user_id} not found")
            if user.status != "active":
                raise Revoked("User is disabled", reason_code="USER_DISABLED")

            enrollment_id = str(uuid.uuid4())
            nonce = secrets.token_hex(32)
            session.add(
                Enrollment(
                    enrollment_id=enrollment_id,
                    user_id=user_id,
                    kind=kind,
                    status="pending",
                    nonce=nonce,
                    expires_at=now + timedelta(seconds=ttl_seconds),
                    created_at=now,
                )
            )
            self.emitter.emit(
                session,
                actor_id=initiated_by or user_id,
                device_id=None,
                action="enrollment.started",
                target=enrollment_id,
                outcome="allow",
                reason_code="ENROLLMENT_STARTED",
                metadata={
                    "kind": kind,
                    "target_user_id": user_id,
                    "actor_is_admin": initiated_by_admin,
                },
            )
            return {"enrollment_id": enrollment_id, "nonce": nonce}

    def enroll_device(
        self,
        *,
        enrollment_id: str,
        nonce: str,
        label: str,
        public_key_b64: str,
        proof_of_possession_b64: str,
        public_key_alg: str = "Ed25519",
        initiated_by: str | None = None,
    ) -> dict[str, Any]:
        """Verify nonce + PoP signature, reject duplicates/revoked fingerprints, and enroll."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            enrollment = session.get(Enrollment, enrollment_id)
            if not enrollment:
                raise NotFound("Enrollment not found")

            def _reject(exc: Exception, reason_code: str) -> NoReturn:
                self.emitter.emit(
                    session,
                    actor_id=initiated_by or enrollment.user_id,
                    device_id=None,
                    action="device.enroll.rejected",
                    target=enrollment_id,
                    outcome="deny",
                    reason_code=reason_code,
                    metadata={"label": label, "target_user_id": enrollment.user_id},
                )
                session.commit()
                raise exc

            if enrollment.status != "pending" or enrollment.nonce != nonce:
                _reject(
                    NotAuthorized("Enrollment nonce invalid or already used", "NONCE_REPLAYED"),
                    "NONCE_REPLAYED",
                )
            if now >= _as_utc(enrollment.expires_at):
                _reject(NotAuthorized("Enrollment nonce expired", "NONCE_EXPIRED"), "NONCE_EXPIRED")

            user = session.get(User, enrollment.user_id)
            if not user or user.status != "active":
                _reject(Revoked("User disabled", "USER_DISABLED"), "USER_DISABLED")

            pub_bytes = b64d(public_key_b64)
            sig_bytes = b64d(proof_of_possession_b64)
            if not ed25519_verify(pub_bytes, nonce.encode("utf-8"), sig_bytes):
                _reject(
                    NotAuthorized("Invalid proof-of-possession signature", "INVALID_POP"),
                    "INVALID_POP",
                )

            fp = public_key_fingerprint(pub_bytes)
            existing = session.execute(
                select(Device).where(Device.public_key_fingerprint == fp)
            ).scalar_one_or_none()
            if existing is not None:
                if existing.status == "revoked":
                    _reject(
                        Revoked(
                            "Public key fingerprint belongs to a revoked device",
                            "REVOKED_KEY_REUSE",
                        ),
                        "REVOKED_KEY_REUSE",
                    )
                _reject(
                    Conflict("Duplicate public key", "DUPLICATE_PUBLIC_KEY"), "DUPLICATE_PUBLIC_KEY"
                )

            device_id = str(uuid.uuid4())
            device = Device(
                device_id=device_id,
                user_id=user.user_id,
                label=label,
                status="pending",
                public_key=pub_bytes,
                public_key_alg=public_key_alg,
                public_key_fingerprint=fp,
                enrollment_id=enrollment.enrollment_id,
            )
            transition_device_status(device, "enrolled", now)
            enrollment.status = "completed"
            enrollment.device_id = device_id
            enrollment.completed_at = now
            session.add(device)

            self.emitter.emit(
                session,
                actor_id=initiated_by or user.user_id,
                device_id=device_id,
                action="device.enrolled",
                target=device_id,
                outcome="allow",
                reason_code="ENROLLED",
                metadata={"label": label, "fingerprint": fp, "target_user_id": user.user_id},
            )
            return {
                "device_id": device_id,
                "user_id": user.user_id,
                "status": device.status,
                "public_key_fingerprint": fp,
            }

    def issue_challenge(self, device_id: str, ttl_seconds: int = 120) -> dict[str, str]:
        """Issue a single-use short-lived authentication challenge for a device."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            device = session.get(Device, device_id)
            if not device:
                raise NotFound("Device not found")
            _enforce_rate_limit(
                session,
                f"auth-challenge:{device_id}",
                AUTH_CHALLENGE_LIMIT_PER_WINDOW,
                now,
                emitter=self.emitter,
                actor_id=device.user_id,
            )
            self._sweep_expired_challenges(session, now)
            challenge = secrets.token_hex(32)
            challenge_id = str(uuid.uuid4())
            session.add(
                AuthChallenge(
                    challenge_id=challenge_id,
                    device_id=device_id,
                    challenge=challenge,
                    expires_at=now + timedelta(seconds=ttl_seconds),
                    created_at=now,
                )
            )
            return {"challenge_id": challenge_id, "challenge": challenge}

    def verify_identity(
        self,
        *,
        device_id: str,
        challenge: str,
        signature_b64: str,
        key_version_id: str | None = None,
    ) -> dict[str, Any]:
        """Verify device challenge signature, active user, enrolled device, and auth key."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            _enforce_rate_limit(
                session,
                f"auth-verify:{device_id}",
                AUTH_VERIFY_LIMIT_PER_WINDOW,
                now,
                emitter=self.emitter,
                actor_id=device_id,
            )
            if not check_and_advance_clock_high_water(
                session, self.emitter.node_id, now, self.clock.monotonic_ns()
            ):
                self.emitter.emit(
                    session,
                    actor_id="system",
                    device_id=device_id,
                    action="clock.rollback_detected",
                    target=self.emitter.node_id,
                    outcome="deny",
                    reason_code=CLOCK_ROLLBACK_REASON,
                )
                session.commit()
                raise NotAuthorized(
                    "Clock rollback detected", reason_code=CLOCK_ROLLBACK_REASON
                )
            if key_version_id is not None:
                kv = session.get(KeyVersion, key_version_id)
                if kv is None:
                    raise NotAuthorized("Unknown auth key version", reason_code="KEY_RETIRED")
                ok, k_reason = is_key_acceptable(kv, now, purpose="auth")
                if not ok:
                    self.emitter.emit(
                        session,
                        actor_id="system",
                        device_id=device_id,
                        action="key.rejected_after_cutoff",
                        target=key_version_id,
                        outcome="deny",
                        reason_code=k_reason,
                    )
                    session.commit()
                    raise NotAuthorized(f"Auth key rejected: {k_reason}", reason_code=k_reason)
                if k_reason == "KEY_GRACE_VALID":
                    cutoff_ok, cutoff_reason = verify_rotation_cutoff(session, kv)
                    if not cutoff_ok:
                        self.emitter.emit(
                            session,
                            actor_id="system",
                            device_id=device_id,
                            action="key.rejected_after_cutoff",
                            target=key_version_id,
                            outcome="deny",
                            reason_code=cutoff_reason,
                        )
                        session.commit()
                        raise NotAuthorized(
                            f"Auth key rejected: {cutoff_reason}", reason_code=cutoff_reason
                        )
                    self.emitter.emit(
                        session,
                        actor_id="system",
                        device_id=device_id,
                        action="key.grace_used",
                        target=key_version_id,
                        outcome="allow",
                        reason_code=k_reason,
                    )

            ch = session.execute(
                select(AuthChallenge).where(
                    AuthChallenge.device_id == device_id,
                    AuthChallenge.challenge == challenge,
                )
            ).scalar_one_or_none()
            if not ch:
                raise NotAuthorized("Challenge not found", reason_code="INVALID_CHALLENGE")
            if ch.used_at is not None:
                raise NotAuthorized("Challenge already used", reason_code="CHALLENGE_REPLAYED")
            if now >= _as_utc(ch.expires_at):
                raise NotAuthorized("Challenge expired", reason_code="CHALLENGE_EXPIRED")

            # Mark single-use challenge consumed before signature/status checks
            ch.used_at = now

            device = session.get(Device, device_id)
            if not device or device.status != "enrolled":
                raise Revoked("Device is not enrolled or is revoked", reason_code="DEVICE_REVOKED")

            user = session.get(User, device.user_id)
            if not user or user.status != "active":
                raise Revoked("User is disabled", reason_code="USER_DISABLED")

            sig_bytes = b64d(signature_b64)
            if not ed25519_verify(device.public_key, challenge.encode("utf-8"), sig_bytes):
                raise NotAuthorized("Invalid challenge signature", reason_code="BAD_SIGNATURE")

            token = self.token_authority.issue(user.user_id, device.device_id)
            return {
                "verified": True,
                "user_id": user.user_id,
                "device_id": device.device_id,
                "access_token": token,
            }


class AuthzService:
    """Fail-closed authorization service deriving actor strictly from ActorContext."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        emitter: AuditEmitter,
        node_id: str,
        max_cache_staleness_ms: int = 500,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.emitter = emitter
        self.node_id = node_id
        self.max_cache_staleness_ms = max_cache_staleness_ms
        self._last_authoritative_mono_ns: int | None = None

    def authorize(
        self,
        actor_context: ActorContext,
        resource_id: str,
        permission: str,
        *,
        key_version_id: str | None = None,
        correlation_id: str | None = None,
    ) -> AuthzDecision:
        """Evaluate user, device, auth key state, role perms, and grants. Fail closed."""
        decision_id = str(uuid.uuid4())
        now = self.clock.now()
        try:
            with tx_session(self.session_factory) as session:
                if not check_and_advance_clock_high_water(
                    session, self.node_id, now, self.clock.monotonic_ns()
                ):
                    self.emitter.emit(
                        session,
                        actor_id=actor_context.user_id,
                        device_id=actor_context.device_id,
                        action="clock.rollback_detected",
                        target=self.node_id,
                        outcome="deny",
                        reason_code=CLOCK_ROLLBACK_REASON,
                        correlation_id=correlation_id,
                    )
                    return AuthzDecision(
                        False, CLOCK_ROLLBACK_REASON, key_version_id, decision_id
                    )
                if key_version_id is not None:
                    kv = session.get(KeyVersion, key_version_id)
                    if kv is None:
                        self.emitter.emit(
                            session,
                            actor_id=actor_context.user_id,
                            device_id=actor_context.device_id,
                            action="key.rejected_after_cutoff",
                            target=key_version_id,
                            outcome="deny",
                            reason_code="KEY_RETIRED",
                            correlation_id=correlation_id,
                        )
                        return AuthzDecision(False, "KEY_RETIRED", key_version_id, decision_id)
                    ok, k_reason = is_key_acceptable(kv, now, purpose="auth")
                    if not ok:
                        self.emitter.emit(
                            session,
                            actor_id=actor_context.user_id,
                            device_id=actor_context.device_id,
                            action="key.rejected_after_cutoff",
                            target=key_version_id,
                            outcome="deny",
                            reason_code=k_reason,
                            correlation_id=correlation_id,
                        )
                        return AuthzDecision(False, k_reason, key_version_id, decision_id)
                    if k_reason == "KEY_GRACE_VALID":
                        cutoff_ok, cutoff_reason = verify_rotation_cutoff(session, kv)
                        if not cutoff_ok:
                            self.emitter.emit(
                                session,
                                actor_id=actor_context.user_id,
                                device_id=actor_context.device_id,
                                action="key.rejected_after_cutoff",
                                target=key_version_id,
                                outcome="deny",
                                reason_code=cutoff_reason,
                                correlation_id=correlation_id,
                            )
                            return AuthzDecision(
                                False, cutoff_reason, key_version_id, decision_id
                            )
                        self.emitter.emit(
                            session,
                            actor_id=actor_context.user_id,
                            device_id=actor_context.device_id,
                            action="key.grace_used",
                            target=key_version_id,
                            outcome="allow",
                            reason_code=k_reason,
                            correlation_id=correlation_id,
                        )

                user = session.get(User, actor_context.user_id)
                device = session.get(Device, actor_context.device_id)
                resource = session.get(Resource, resource_id)

                allowed, reason_code, res_kv_id = self._evaluate(
                    session, user, device, resource, actor_context, permission
                )
                self._last_authoritative_mono_ns = self.clock.monotonic_ns()
                bound_key_version = key_version_id or res_kv_id
                self.emitter.emit(
                    session,
                    actor_id=actor_context.user_id,
                    device_id=actor_context.device_id,
                    action=f"authz.{permission}",
                    target=resource_id,
                    outcome="allow" if allowed else "deny",
                    reason_code=reason_code,
                    correlation_id=correlation_id,
                    metadata={
                        "decision_id": decision_id,
                        "key_version": bound_key_version,
                        "key_version_id": bound_key_version,
                    },
                )
                return AuthzDecision(
                    allowed=allowed,
                    reason_code=reason_code,
                    key_version_id=bound_key_version,
                    decision_id=decision_id,
                )
        except Exception:
            # Fail closed on ANY database/state unavailability error
            return AuthzDecision(
                allowed=False,
                reason_code="STATE_UNAVAILABLE",
                key_version_id=None,
                decision_id=decision_id,
            )

    def _evaluate(
        self,
        session: Session,
        user: User | None,
        device: Device | None,
        resource: Resource | None,
        actor_context: ActorContext,
        permission: str,
    ) -> tuple[bool, str, str | None]:
        if not user or user.status != "active":
            return False, "USER_DISABLED", None
        if not device or device.user_id != actor_context.user_id or device.status != "enrolled":
            return False, "DEVICE_REVOKED", None
        if not resource:
            return False, "RESOURCE_NOT_FOUND", None

        # Check key_version state if resource is bound to one
        if resource.key_version_id:
            kv = session.get(KeyVersion, resource.key_version_id)
            if not kv or kv.state in ("REVOKED", "RETIRED"):
                return False, "KEY_VERSION_UNAVAILABLE", resource.key_version_id

        # Check role permissions for the user
        has_role_perm = (
            session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user.user_id, Permission.name == permission)
            ).first()
            is not None
        )
        if not has_role_perm:
            return False, "ROLE_PERMISSION_DENIED", resource.key_version_id

        # Owner always has access if role permits
        if resource.owner_user_id == user.user_id:
            return True, "OWNER_ALLOWED", resource.key_version_id

        # Otherwise require an active non-revoked resource grant
        grant = session.execute(
            select(ResourceGrant).where(
                ResourceGrant.resource_id == resource.resource_id,
                ResourceGrant.grantee_user_id == user.user_id,
                ResourceGrant.permission == permission,
                ResourceGrant.revoked_at.is_(None),
            )
        ).scalar_one_or_none()
        if grant is not None:
            return True, "GRANT_ALLOWED", resource.key_version_id

        return False, "NOT_OWNER_OR_GRANTED", resource.key_version_id


class KeyMetadataService:
    """Returns permitted public key metadata; never private material."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self.session_factory = session_factory

    def get_public_key_metadata(
        self, requester: ActorContext, target_user_id: str
    ) -> list[dict[str, Any]]:
        try:
            with tx_session(self.session_factory) as session:
                req_user = session.get(User, requester.user_id)
                req_dev = session.get(Device, requester.device_id)
                if (
                    not req_user
                    or req_user.status != "active"
                    or not req_dev
                    or req_dev.status != "enrolled"
                ):
                    raise NotAuthorized("Requester is not active/enrolled")

                # Only self or admin role can query target user's device public keys
                is_admin = (
                    session.execute(
                        select(Permission.name)
                        .join(
                            RolePermission, RolePermission.permission_id == Permission.permission_id
                        )
                        .join(UserRole, UserRole.role_id == RolePermission.role_id)
                        .where(
                            UserRole.user_id == requester.user_id, Permission.name == "key:rotate"
                        )
                    ).first()
                    is not None
                )
                if requester.user_id != target_user_id and not is_admin:
                    raise NotAuthorized("Not permitted to view target key metadata")

                devices = (
                    session.execute(select(Device).where(Device.user_id == target_user_id))
                    .scalars()
                    .all()
                )
                return [
                    {
                        "device_id": d.device_id,
                        "label": d.label,
                        "status": d.status,
                        "public_key_alg": d.public_key_alg,
                        "public_key_fingerprint": d.public_key_fingerprint,
                        "enrolled_at": d.enrolled_at.isoformat() if d.enrolled_at else None,
                    }
                    for d in devices
                ]
        except NotAuthorized:
            raise
        except Exception as exc:
            raise StateUnavailable("Database unavailable") from exc
