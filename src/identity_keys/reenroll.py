"""Secure device re-enrollment with scrypt recovery codes, admin approvals, and rate limits."""

from __future__ import annotations

import hashlib
import hmac
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, NoReturn, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .audit_outbox import AuditEmitter
from .clock import Clock
from .crypto import (
    b64d,
    b64e,
    canonical_json_bytes,
    ed25519_sign,
    ed25519_verify,
    public_key_fingerprint,
)
from .db import tx_session
from .errors import Conflict, NotAuthorized, NotFound, Revoked
from .models import (
    Device,
    Enrollment,
    Outbox,
    Permission,
    RateLimit,
    RecoveryCredential,
    Revocation,
    RolePermission,
    User,
    UserRole,
)
from .revocation import RevocationReason, next_commit_seq
from .rotation import crash_point
from .services import transition_device_status
from .tokens import ActorContext, load_token_signing_keypair

_DUMMY_SALT = b"tbv-dummy-salt-16"
_SCRYPT_N = 16384
_SCRYPT_R = 8
_SCRYPT_P = 1


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def _scrypt_derive(code: str, salt: bytes) -> bytes:
    return hashlib.scrypt(
        code.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P, dklen=32
    )


class ReenrollmentService:
    """Handles lost-device re-enrollment, scrypt codes, admin approvals, and rate limits."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        emitter: AuditEmitter,
        *,
        max_active_devices: int = 5,
        cooldown_seconds: int = 0,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.emitter = emitter
        self.max_active_devices = max_active_devices
        self.cooldown_seconds = cooldown_seconds
        self._approval_pub, self._approval_priv = load_token_signing_keypair()

    def generate_recovery_codes(self, user_id: str, count: int = 10) -> list[str]:
        """Generate 10 128-bit one-time recovery codes, storing only salted scrypt verifiers."""
        now = self.clock.now()
        plaintext_codes: list[str] = []
        with tx_session(self.session_factory) as session:
            user = session.get(User, user_id)
            if not user:
                raise NotFound(f"User {user_id} not found")
            for _ in range(count):
                code = secrets.token_hex(16)
                salt = os.urandom(16)
                verifier = _scrypt_derive(code, salt)
                session.add(
                    RecoveryCredential(
                        credential_id=str(uuid.uuid4()),
                        user_id=user_id,
                        kdf_params={
                            "alg": "scrypt",
                            "n": _SCRYPT_N,
                            "r": _SCRYPT_R,
                            "p": _SCRYPT_P,
                            "salt_b64": b64e(salt),
                        },
                        verifier=verifier,
                        created_at=now,
                    )
                )
                plaintext_codes.append(code)
        return plaintext_codes

    def create_admin_approval(
        self,
        admin_ctx: ActorContext,
        *,
        user_id: str,
        new_pk_fingerprint: str,
        enrollment_id: str,
        ttl_seconds: int = 600,
    ) -> dict[str, Any]:
        """Admin with device:approve_reenroll signs a single-use bound approval."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            has_perm = (
                session.execute(
                    select(Permission.name)
                    .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                    .join(UserRole, UserRole.role_id == RolePermission.role_id)
                    .where(
                        UserRole.user_id == admin_ctx.user_id,
                        Permission.name == "device:approve_reenroll",
                    )
                ).first()
                is not None
            )
            if not has_perm:
                raise NotAuthorized(
                    "Missing device:approve_reenroll permission", reason_code="FORBIDDEN"
                )

        payload = {
            "user_id": user_id,
            "new_device_public_key_fingerprint": new_pk_fingerprint,
            "enrollment_id": enrollment_id,
            "expires_at": int((now + timedelta(seconds=ttl_seconds)).timestamp()),
            "approved_by": admin_ctx.user_id,
        }
        sig = ed25519_sign(self._approval_priv, canonical_json_bytes(payload))
        return {"payload": payload, "signature_b64": b64e(sig)}

    def begin_reenrollment(self, user_id: str) -> dict[str, str]:
        """Create a re_enroll enrollment record (10-min expiry, single-use nonce)."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            user = session.get(User, user_id)
            if not user:
                raise NotFound(f"User {user_id} not found")
            if user.status != "active":
                raise Revoked("User is disabled", reason_code="USER_DISABLED")

            eid = str(uuid.uuid4())
            nonce = secrets.token_hex(32)
            session.add(
                Enrollment(
                    enrollment_id=eid,
                    user_id=user_id,
                    kind="re_enroll",
                    status="pending",
                    nonce=nonce,
                    expires_at=now + timedelta(minutes=10),
                    created_at=now,
                )
            )
            self.emitter.emit(
                session,
                actor_id=user_id,
                device_id=None,
                action="reenroll.initiated",
                target=eid,
                outcome="allow",
                reason_code="STARTED",
            )
            return {"enrollment_id": eid, "nonce": nonce}

    def _check_and_record_attempt(
        self,
        session: Session,
        scope_key: str,
        limit_per_hour: int,
        now: datetime,
        *,
        is_failure: bool = False,
        actor_id: str = "unknown",
    ) -> None:
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

        if (now - _as_utc(rl.window_start)).total_seconds() >= 3600:
            rl.attempts = 0
            rl.failures = 0
            rl.window_start = now
            rl.backoff_until = None
            rl.locked_until = None

        if rl.locked_until and now < _as_utc(rl.locked_until):
            raise NotAuthorized("Rate limit lockout active", reason_code="RATE_LIMITED")
        if rl.backoff_until and now < _as_utc(rl.backoff_until):
            raise NotAuthorized("Exponential backoff active", reason_code="RATE_LIMITED")

        if not is_failure:
            if rl.attempts >= limit_per_hour:
                rl.locked_until = now + timedelta(minutes=15)
                self.emitter.emit(
                    session,
                    actor_id=actor_id,
                    device_id=None,
                    action="ALERT.reenroll_rate_limit",
                    target=scope_key,
                    outcome="deny",
                    reason_code="ALERT_LOCKOUT",
                )
                session.commit()
                raise NotAuthorized("Rate limit exceeded", reason_code="RATE_LIMITED")
            rl.attempts += 1
            rl.updated_at = now
        else:
            rl.failures += 1
            rl.updated_at = now
            if rl.failures >= 10:
                rl.locked_until = now + timedelta(minutes=30)
                self.emitter.emit(
                    session,
                    actor_id=actor_id,
                    device_id=None,
                    action="ALERT.reenroll_lockout",
                    target=scope_key,
                    outcome="deny",
                    reason_code="ALERT_LOCKOUT",
                    metadata={"failures": rl.failures},
                )
            elif rl.failures >= 3:
                backoff_s = min(300, 2 ** (rl.failures - 3))
                rl.backoff_until = now + timedelta(seconds=backoff_s)

    def complete_reenrollment(
        self,
        *,
        enrollment_id: str,
        nonce: str,
        label: str,
        new_public_key_b64: str,
        pop_signature_b64: str,
        old_device_ids: Optional[list[str]] = None,
        recovery_code: Optional[str] = None,
        admin_approval: Optional[dict[str, Any]] = None,
        source_id: str = "127.0.0.1",
        correlation_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Atomically revoke old device(s), burn recovery proof, and enroll new device."""
        now = self.clock.now()
        corr_id = correlation_id or str(uuid.uuid4())
        pub_bytes = b64d(new_public_key_b64)
        sig_bytes = b64d(pop_signature_b64)
        fp = public_key_fingerprint(pub_bytes)

        with tx_session(self.session_factory) as session:
            self._check_and_record_attempt(session, f"src:{source_id}", 20, now)
            enrollment = session.get(Enrollment, enrollment_id)
            if enrollment is None:
                # Constant-work dummy KDF to prevent user/enrollment enumeration
                _scrypt_derive(recovery_code or "dummy-code", _DUMMY_SALT)
                self._check_and_record_attempt(
                    session, f"src:{source_id}", 20, now, is_failure=True
                )
                session.commit()
                raise NotAuthorized("Invalid recovery proof", reason_code="INVALID_RECOVERY_PROOF")

            self._check_and_record_attempt(
                session, f"usr:{enrollment.user_id}", 5, now, actor_id=enrollment.user_id
            )

            def _fail(msg: str, code: str) -> NoReturn:
                self._check_and_record_attempt(
                    session,
                    f"src:{source_id}",
                    20,
                    now,
                    is_failure=True,
                    actor_id=enrollment.user_id,
                )
                self._check_and_record_attempt(
                    session,
                    f"usr:{enrollment.user_id}",
                    5,
                    now,
                    is_failure=True,
                    actor_id=enrollment.user_id,
                )
                self.emitter.emit(
                    session,
                    actor_id=enrollment.user_id,
                    device_id=None,
                    action="reenroll.rejected",
                    target=enrollment_id,
                    outcome="deny",
                    reason_code=code,
                    correlation_id=corr_id,
                )
                session.commit()
                raise NotAuthorized(msg, reason_code=code)

            if enrollment.status != "pending" or enrollment.nonce != nonce:
                _fail("Invalid or replayed enrollment", "INVALID_ENROLLMENT")
            if now >= _as_utc(enrollment.expires_at):
                _fail("Enrollment expired", "ENROLLMENT_EXPIRED")

            user = session.get(User, enrollment.user_id)
            if not user or user.status != "active":
                _fail("User disabled", "USER_DISABLED")

            if not ed25519_verify(pub_bytes, nonce.encode("utf-8"), sig_bytes):
                _fail("Invalid proof of possession", "INVALID_POP")

            # Verify recovery proof (either one-time scrypt code OR signed admin approval)
            if recovery_code is not None:
                creds = (
                    session.execute(
                        select(RecoveryCredential).where(
                            RecoveryCredential.user_id == user.user_id,
                            RecoveryCredential.used_at.is_(None),
                        )
                    )
                    .scalars()
                    .all()
                )
                matched_cred: Optional[RecoveryCredential] = None
                for cred in creds:
                    salt = b64d(cred.kdf_params["salt_b64"])
                    candidate = _scrypt_derive(recovery_code, salt)
                    if hmac.compare_digest(candidate, cred.verifier):
                        matched_cred = cred
                        break
                if matched_cred is None:
                    if not creds:
                        _scrypt_derive(recovery_code, _DUMMY_SALT)
                    _fail("Invalid recovery proof", "INVALID_RECOVERY_PROOF")
                assert matched_cred is not None
                matched_cred.used_at = now
            elif admin_approval is not None:
                payload = admin_approval.get("payload", {})
                app_sig = b64d(admin_approval.get("signature_b64", ""))
                if not ed25519_verify(self._approval_pub, canonical_json_bytes(payload), app_sig):
                    _fail("Invalid admin approval signature", "INVALID_RECOVERY_PROOF")
                if (
                    payload.get("user_id") != user.user_id
                    or payload.get("new_device_public_key_fingerprint") != fp
                    or payload.get("enrollment_id") != enrollment_id
                    or int(now.timestamp()) >= int(payload.get("expires_at", 0))
                ):
                    _fail("Admin approval binding mismatch or expired", "INVALID_RECOVERY_PROOF")
            else:
                _fail("Missing recovery proof", "INVALID_RECOVERY_PROOF")

            # Permanently reject revoked or duplicate fingerprints
            existing_dev = session.execute(
                select(Device).where(Device.public_key_fingerprint == fp)
            ).scalar_one_or_none()
            if existing_dev is not None:
                if existing_dev.status == "revoked":
                    raise Revoked(
                        "Cannot re-register revoked public key", reason_code="REVOKED_KEY_REUSE"
                    )
                raise Conflict("Duplicate public key", reason_code="DUPLICATE_PUBLIC_KEY")

            new_dev_id = str(uuid.uuid4())
            crash_point("reenroll.before_commit")

            new_dev = Device(
                device_id=new_dev_id,
                user_id=user.user_id,
                label=label,
                status="pending",
                public_key=pub_bytes,
                public_key_alg="Ed25519",
                public_key_fingerprint=fp,
                enrollment_id=enrollment_id,
            )
            transition_device_status(new_dev, "enrolled", now)
            enrollment.status = "completed"
            enrollment.device_id = new_dev_id
            enrollment.completed_at = now
            session.add(new_dev)
            session.flush()

            # Revoke old device(s) and link replaced_by_device_id
            revoked_ids: list[str] = []
            for old_id in old_device_ids or []:
                old_dev = session.get(Device, old_id)
                if old_dev and old_dev.user_id == user.user_id and old_dev.status != "revoked":
                    seq = next_commit_seq(session)
                    transition_device_status(
                        old_dev, "revoked", now, RevocationReason.RE_ENROLLMENT.value
                    )
                    old_dev.replaced_by_device_id = new_dev_id
                    session.add(
                        Revocation(
                            revocation_id=str(uuid.uuid4()),
                            target_type="device",
                            target_id=old_id,
                            user_id=user.user_id,
                            revoked_by_actor=user.user_id,
                            reason_code=RevocationReason.RE_ENROLLMENT.value,
                            committed_at=now,
                            commit_seq=seq,
                        )
                    )
                    revoked_ids.append(old_id)
            session.add(
                Outbox(
                    outbox_id=str(uuid.uuid4()),
                    topic="device.reenrolled",
                    payload={
                        "user_id": user.user_id,
                        "new_device_id": new_dev_id,
                        "revoked": revoked_ids,
                    },
                    created_at=now,
                    attempts=0,
                )
            )
            self.emitter.emit(
                session,
                actor_id=user.user_id,
                device_id=new_dev_id,
                action="reenroll.completed",
                target=new_dev_id,
                outcome="allow",
                reason_code="REENROLLED",
                correlation_id=corr_id,
                metadata={"revoked_devices": revoked_ids},
            )

        crash_point("reenroll.after_commit")
        return {
            "device_id": new_dev_id,
            "user_id": user.user_id,
            "revoked_devices": revoked_ids,
            "public_key_fingerprint": fp,
        }
