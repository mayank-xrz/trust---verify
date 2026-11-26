"""Service layer for identity enrollment, verification, fail-closed authorization, and key metadata."""

from __future__ import annotations

import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .audit_outbox import AuditEmitter
from .clock import Clock
from .crypto import b64d, ed25519_verify, public_key_fingerprint
from .db import tx_session
from .errors import Conflict, IllegalTransition, NotAuthorized, NotFound, Revoked, StateUnavailable
from .models import (
    AuthChallenge,
    Device,
    Enrollment,
    KeyVersion,
    Permission,
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


def transition_device_status(device: Device, new_status: str, now: datetime, reason: str | None = None) -> None:
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

    def start_enrollment(
        self, user_id: str, kind: str = "first", ttl_seconds: int = 300
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
    ) -> dict[str, Any]:
        """Verify nonce + PoP signature, reject duplicates/revoked fingerprints, and enroll."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            enrollment = session.get(Enrollment, enrollment_id)
            if not enrollment:
                raise NotFound("Enrollment not found")

            def _reject(exc: Exception, reason_code: str) -> None:
                self.emitter.emit(
                    session,
                    actor_id=enrollment.user_id,
                    device_id=None,
                    action="device.enroll.rejected",
                    target=enrollment_id,
                    outcome="deny",
                    reason_code=reason_code,
                    metadata={"label": label},
                )
                session.commit()
                raise exc

            if enrollment.status != "pending" or enrollment.nonce != nonce:
                _reject(NotAuthorized("Enrollment nonce invalid or already used", "NONCE_REPLAYED"), "NONCE_REPLAYED")
            if now >= _as_utc(enrollment.expires_at):
                _reject(NotAuthorized("Enrollment nonce expired", "NONCE_EXPIRED"), "NONCE_EXPIRED")

            user = session.get(User, enrollment.user_id)
            if not user or user.status != "active":
                _reject(Revoked("User disabled", "USER_DISABLED"), "USER_DISABLED")

            pub_bytes = b64d(public_key_b64)
            sig_bytes = b64d(proof_of_possession_b64)
            if not ed25519_verify(pub_bytes, nonce.encode("utf-8"), sig_bytes):
                _reject(NotAuthorized("Invalid proof-of-possession signature", "INVALID_POP"), "INVALID_POP")

            fp = public_key_fingerprint(pub_bytes)
            existing = session.execute(
                select(Device).where(Device.public_key_fingerprint == fp)
            ).scalar_one_or_none()
            if existing is not None:
                if existing.status == "revoked":
                    _reject(
                        Revoked("Public key fingerprint belongs to a revoked device", "REVOKED_KEY_REUSE"),
                        "REVOKED_KEY_REUSE",
                    )
                _reject(Conflict("Duplicate public key", "DUPLICATE_PUBLIC_KEY"), "DUPLICATE_PUBLIC_KEY")

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
                actor_id=user.user_id,
                device_id=device_id,
                action="device.enrolled",
                target=device_id,
                outcome="allow",
                reason_code="ENROLLED",
                metadata={"label": label, "fingerprint": fp},
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
        self, *, device_id: str, challenge: str, signature_b64: str
    ) -> dict[str, Any]:
        """Verify device challenge signature, active user & enrolled device; issue bearer token."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
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
        max_cache_staleness_ms: int = 5000,
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
        correlation_id: str | None = None,
    ) -> AuthzDecision:
        """Evaluate user, device, role permissions, ownership/grants, and key state. Fail closed."""
        decision_id = str(uuid.uuid4())
        try:
            with tx_session(self.session_factory) as session:
                user = session.get(User, actor_context.user_id)
                device = session.get(Device, actor_context.device_id)
                resource = session.get(Resource, resource_id)

                allowed, reason_code, key_version_id = self._evaluate(
                    session, user, device, resource, actor_context, permission
                )
                self._last_authoritative_mono_ns = self.clock.monotonic_ns()
                self.emitter.emit(
                    session,
                    actor_id=actor_context.user_id,
                    device_id=actor_context.device_id,
                    action=f"authz.{permission}",
                    target=resource_id,
                    outcome="allow" if allowed else "deny",
                    reason_code=reason_code,
                    correlation_id=correlation_id,
                    metadata={"decision_id": decision_id},
                )
                return AuthzDecision(
                    allowed=allowed,
                    reason_code=reason_code,
                    key_version_id=key_version_id,
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
                if not req_user or req_user.status != "active" or not req_dev or req_dev.status != "enrolled":
                    raise NotAuthorized("Requester is not active/enrolled")

                # Only self or admin role can query target user's device public keys
                is_admin = (
                    session.execute(
                        select(Permission.name)
                        .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                        .join(UserRole, UserRole.role_id == RolePermission.role_id)
                        .where(UserRole.user_id == requester.user_id, Permission.name == "key:rotate")
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
