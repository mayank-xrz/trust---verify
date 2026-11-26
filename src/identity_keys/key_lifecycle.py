"""Key state machine, AES-256-GCM key wrapping, and envelope encryption for resources."""

from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from .audit_outbox import AuditEmitter
from .authority import KeyAuthority
from .clock import Clock
from .crypto import aes_gcm_unwrap, aes_gcm_wrap, b64d, canonical_json_bytes
from .db import tx_session
from .errors import (
    Conflict,
    IllegalTransition,
    NotAuthorized,
    NotFound,
    Revoked,
    StateUnavailable,
)
from .errors import (
    IntegrityError as DomainIntegrityError,
)
from .models import KeyVersion, Permission, Resource, RolePermission, RotationCutoff, UserRole
from .tokens import ActorContext

_LEGAL_TRANSITIONS: dict[str, set[str]] = {
    "PENDING": {"ACTIVE", "RETIRED", "REVOKED"},
    "ACTIVE": {"GRACE", "RETIRED", "REVOKED"},
    "GRACE": {"RETIRED", "REVOKED"},
    "RETIRED": {"REVOKED"},
    "REVOKED": set(),
}

_IDEMPOTENT_STATES = {"ACTIVE", "GRACE", "RETIRED"}


def _as_utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def load_wrap_master_key() -> bytes:
    """Load 32-byte wrap master key from WRAP_MASTER_KEY_B64 or WRAP_MASTER_KEY_FILE."""
    b64_val = os.environ.get("WRAP_MASTER_KEY_B64", "").strip()
    if b64_val:
        raw = b64d(b64_val)
        if len(raw) != 32:
            raise StateUnavailable("WRAP_MASTER_KEY_B64 must decode to 32 bytes")
        return raw
    file_path = os.environ.get("WRAP_MASTER_KEY_FILE", "").strip()
    if file_path:
        raw = b64d(Path(file_path).read_text(encoding="utf-8").strip())
        if len(raw) != 32:
            raise StateUnavailable("WRAP_MASTER_KEY_FILE must decode to 32 bytes")
        return raw
    raise StateUnavailable("WRAP_MASTER_KEY_B64 or WRAP_MASTER_KEY_FILE must be configured")


def build_key_wrap_aad(key_version_id: str, key_set_id: str, version: int, scope: str) -> bytes:
    """Construct canonical AAD binding wrapped private material to its exact DB row."""
    return f"{key_version_id}|{key_set_id}|{version}|{scope}".encode("utf-8")


def wrap_key_material(
    master_key: bytes,
    plaintext: bytes,
    *,
    key_version_id: str,
    key_set_id: str,
    version: int,
    scope: str,
) -> tuple[bytes, bytes, bytes]:
    """Wrap key material with AES-256-GCM -> (wrapped, nonce, aad)."""
    aad = build_key_wrap_aad(key_version_id, key_set_id, version, scope)
    nonce, wrapped = aes_gcm_wrap(master_key, plaintext, aad)
    return wrapped, nonce, aad


def unwrap_key_material(master_key: bytes, kv: KeyVersion) -> bytes:
    """Unwrap private key material using row-bound AAD. Never return this via API."""
    if not kv.wrapped_private_material or not kv.wrap_nonce:
        raise StateUnavailable("Key version has no wrapped private material")
    expected_aad = build_key_wrap_aad(kv.key_version_id, kv.key_set_id, kv.version, kv.scope)
    try:
        return aes_gcm_unwrap(master_key, kv.wrap_nonce, kv.wrapped_private_material, expected_aad)
    except Exception as exc:
        raise DomainIntegrityError("Key material AAD/GCM verification failed") from exc


def transition_key(
    session: Session,
    key_version_id: str,
    new_state: str,
    rotation_id: Optional[str],
    now: datetime,
    *,
    grace_until: Optional[datetime] = None,
    revoke_reason: Optional[str] = None,
) -> KeyVersion:
    """Single enforcing writer of key_versions.state."""
    kv = session.get(KeyVersion, key_version_id)
    if kv is None:
        raise NotFound(f"KeyVersion {key_version_id} not found")

    if kv.state == "REVOKED":
        raise IllegalTransition("REVOKED is terminal; even self-transition is forbidden")

    # Idempotent same-state replay ONLY for ACTIVE, GRACE, RETIRED driven by same rotation_id
    if kv.state == new_state:
        if (
            new_state in _IDEMPOTENT_STATES
            and rotation_id is not None
            and kv.rotation_id == rotation_id
        ):
            return kv
        raise IllegalTransition(f"Illegal same-state transition {kv.state} -> {new_state}")

    if new_state not in _LEGAL_TRANSITIONS.get(kv.state, set()):
        raise IllegalTransition(f"Illegal key state transition: {kv.state} -> {new_state}")

    kv.state = new_state
    if rotation_id is not None:
        kv.rotation_id = rotation_id

    if new_state == "ACTIVE":
        kv.activated_at = now
    elif new_state == "GRACE":
        kv.grace_until = grace_until
    elif new_state == "RETIRED":
        kv.retired_at = now
        if kv.scope == "auth":
            # Wipe wrapped private material of retired auth keys; keep public key
            kv.wrapped_private_material = None
            kv.wrap_nonce = None
            kv.wrap_aad = None
    elif new_state == "REVOKED":
        kv.revoked_at = now
        kv.revoke_reason = revoke_reason or "revoked"
        if kv.scope == "auth":
            kv.wrapped_private_material = None
            kv.wrap_nonce = None
            kv.wrap_aad = None

    return kv


def is_key_acceptable(
    key_version: KeyVersion, now: datetime, purpose: str = "auth"
) -> tuple[bool, str]:
    """Single authoritative key acceptance check.

    - auth: ACTIVE accepted; GRACE accepted strictly while now < grace_until;
      PENDING, RETIRED, REVOKED rejected.
    - data_wrap: only ACTIVE accepted.
    - data_decrypt: ACTIVE, GRACE, RETIRED accepted (REVOKED requires admin recovery path).
    """
    if key_version.state == "REVOKED":
        return False, "KEY_REVOKED"
    if key_version.state == "PENDING":
        return False, "KEY_PENDING"

    if purpose == "auth":
        if key_version.state == "ACTIVE":
            return True, "KEY_ACTIVE"
        if key_version.state == "GRACE":
            if key_version.grace_until is not None and _as_utc(now) < _as_utc(
                key_version.grace_until
            ):
                return True, "KEY_GRACE_VALID"
            return False, "KEY_RETIRED"
        return False, "KEY_RETIRED"

    if purpose == "data_wrap":
        if key_version.state == "ACTIVE":
            return True, "KEY_ACTIVE"
        return False, "KEY_NOT_ACTIVE_FOR_WRAP"

    if purpose == "data_decrypt":
        if key_version.state in ("ACTIVE", "GRACE", "RETIRED"):
            return True, "KEY_DECRYPT_ALLOWED"
        return False, "KEY_UNAVAILABLE"

    return False, "UNKNOWN_KEY_PURPOSE"


def build_rotation_cutoff_body(
    *,
    key_set_id: str,
    key_version_id: str,
    version: int,
    scope: str,
    grace_until: datetime,
    signed_at: datetime,
    key_authority_id: str,
) -> dict[str, str | int]:
    """Canonical signed body for a rotation grace cutoff."""
    return {
        "key_set_id": key_set_id,
        "key_version_id": key_version_id,
        "version": int(version),
        "scope": scope,
        "grace_until": _as_utc(grace_until).isoformat(),
        "signed_at": _as_utc(signed_at).isoformat(),
        "key_authority_id": key_authority_id,
    }


def create_rotation_cutoff(
    session: Session,
    *,
    key_set_id: str,
    key_version_id: str,
    version: int,
    scope: str,
    grace_until: datetime,
    signed_at: datetime,
) -> RotationCutoff:
    """Sign and persist the authoritative grace cutoff for a key version."""
    authority = KeyAuthority()
    body = build_rotation_cutoff_body(
        key_set_id=key_set_id,
        key_version_id=key_version_id,
        version=version,
        scope=scope,
        grace_until=grace_until,
        signed_at=signed_at,
        key_authority_id="primary",
    )
    body_json = canonical_json_bytes(body)
    signature, signer_key_id = authority.sign(body_json)
    cutoff = RotationCutoff(
        cutoff_id=str(uuid.uuid4()),
        key_set_id=key_set_id,
        key_version_id=key_version_id,
        version=int(version),
        scope=scope,
        grace_until=grace_until,
        signed_at=signed_at,
        key_authority_id="primary",
        signer_key_id=signer_key_id,
        body_json=body_json.decode("utf-8"),
        signature=signature,
    )
    session.add(cutoff)
    return cutoff


def verify_rotation_cutoff(session: Session, key_version: KeyVersion) -> tuple[bool, str]:
    """Verify the signed cutoff before accepting a GRACE key. Fail closed."""
    cutoff = session.execute(
        select(RotationCutoff).where(RotationCutoff.key_version_id == key_version.key_version_id)
    ).scalar_one_or_none()
    if cutoff is None:
        return False, "KEY_CUTOFF_UNSIGNED"
    try:
        authority = KeyAuthority()
        if not authority.verify(
            cutoff.body_json.encode("utf-8"), cutoff.signature, cutoff.signer_key_id
        ):
            return False, "KEY_CUTOFF_INVALID"
        body = json.loads(cutoff.body_json)
        expected = build_rotation_cutoff_body(
            key_set_id=key_version.key_set_id,
            key_version_id=key_version.key_version_id,
            version=key_version.version,
            scope=key_version.scope,
            grace_until=cutoff.grace_until,
            signed_at=cutoff.signed_at,
            key_authority_id=cutoff.key_authority_id,
        )
        if body != expected:
            return False, "KEY_CUTOFF_MISMATCH"
        if key_version.grace_until is None or _as_utc(cutoff.grace_until) != _as_utc(
            key_version.grace_until
        ):
            return False, "KEY_CUTOFF_MISMATCH"
    except Exception:
        return False, "KEY_CUTOFF_INVALID"
    return True, "KEY_CUTOFF_VALID"



class EnvelopeEncryptionService:
    """Envelope encryption for protected resources (DEK wrapped by data KEK)."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        emitter: AuditEmitter,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.emitter = emitter

    def _active_data_kek(self, session: Session, key_set_id: str) -> KeyVersion:
        kv = session.execute(
            select(KeyVersion).where(
                KeyVersion.key_set_id == key_set_id,
                KeyVersion.scope == "data",
                KeyVersion.state == "ACTIVE",
            )
        ).scalar_one_or_none()
        if kv is None:
            raise StateUnavailable(f"No ACTIVE data key for key_set {key_set_id}")
        return kv

    def encrypt_resource(
        self,
        *,
        resource_id: str,
        owner_user_id: str,
        plaintext: bytes,
        key_set_id: str,
        kind: str = "document",
    ) -> str:
        """Encrypt resource with a fresh random DEK wrapped under the ACTIVE data KEK."""
        now = self.clock.now()
        master_key = load_wrap_master_key()
        with tx_session(self.session_factory) as session:
            kek_row = self._active_data_kek(session, key_set_id)
            kek_bytes = unwrap_key_material(master_key, kek_row)

            dek = os.urandom(32)
            aad = resource_id.encode("utf-8")
            content_nonce, content_ct = aes_gcm_wrap(dek, plaintext, aad)
            dek_nonce, wrapped_dek = aes_gcm_wrap(kek_bytes, dek, aad)

            existing = session.get(Resource, resource_id)
            if existing is None:
                session.add(
                    Resource(
                        resource_id=resource_id,
                        owner_user_id=owner_user_id,
                        kind=kind,
                        created_at=now,
                        key_version_id=kek_row.key_version_id,
                        content_ciphertext=content_ct,
                        content_nonce=content_nonce,
                        wrapped_dek=wrapped_dek,
                        dek_nonce=dek_nonce,
                        dek_aad=aad,
                    )
                )
            else:
                existing.key_version_id = kek_row.key_version_id
                existing.content_ciphertext = content_ct
                existing.content_nonce = content_nonce
                existing.wrapped_dek = wrapped_dek
                existing.dek_nonce = dek_nonce
                existing.dek_aad = aad
            return kek_row.key_version_id

    def decrypt_resource(
        self,
        resource_id: str,
        *,
        allow_compromised_recovery: bool = False,
    ) -> bytes:
        """Decrypt resource using its wrapping_key_version_id (RETIRED is decrypt-only)."""
        master_key = load_wrap_master_key()
        with tx_session(self.session_factory) as session:
            res = session.get(Resource, resource_id)
            if res is None or not res.key_version_id:
                raise NotFound(f"Resource {resource_id} not found or not encrypted")
            kek_row = session.get(KeyVersion, res.key_version_id)
            if kek_row is None or kek_row.destroyed_at is not None:
                raise StateUnavailable("Wrapping key version unavailable")

            ok, reason = is_key_acceptable(kek_row, self.clock.now(), purpose="data_decrypt")
            if not ok and not (allow_compromised_recovery and kek_row.state == "REVOKED"):
                raise Revoked(f"Key version cannot decrypt: {reason}", reason_code=reason)

            kek_bytes = unwrap_key_material(master_key, kek_row)
            aad = res.dek_aad or resource_id.encode("utf-8")
            assert (
                res.dek_nonce and res.wrapped_dek and res.content_nonce and res.content_ciphertext
            )
            dek = aes_gcm_unwrap(kek_bytes, res.dek_nonce, res.wrapped_dek, aad)
            return aes_gcm_unwrap(dek, res.content_nonce, res.content_ciphertext, aad)

    def rewrap_resource(self, resource_id: str, actor_ctx: ActorContext) -> dict[str, str]:
        """Re-wrap resource DEK under the current ACTIVE data key version transactionally."""
        master_key = load_wrap_master_key()
        with tx_session(self.session_factory) as session:
            res = session.get(Resource, resource_id)
            if res is None or not res.key_version_id:
                raise NotFound(f"Resource {resource_id} not found")
            old_kek_row = session.get(KeyVersion, res.key_version_id)
            if old_kek_row is None:
                raise StateUnavailable("Original wrapping key version missing")

            # Authorize owner or admin recovery (required if old key is REVOKED/compromised)
            is_admin = (
                session.execute(
                    select(Permission.name)
                    .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                    .join(UserRole, UserRole.role_id == RolePermission.role_id)
                    .where(UserRole.user_id == actor_ctx.user_id, Permission.name == "key:rotate")
                ).first()
                is not None
            )
            if old_kek_row.state == "REVOKED" and not is_admin:
                raise NotAuthorized("Admin recovery permission required for compromised key rewrap")
            if res.owner_user_id != actor_ctx.user_id and not is_admin:
                raise NotAuthorized("Not authorized to rewrap resource")

            new_kek_row = self._active_data_kek(session, old_kek_row.key_set_id)
            old_kek_bytes = unwrap_key_material(master_key, old_kek_row)
            new_kek_bytes = unwrap_key_material(master_key, new_kek_row)
            aad = res.dek_aad or resource_id.encode("utf-8")
            assert res.dek_nonce and res.wrapped_dek
            dek = aes_gcm_unwrap(old_kek_bytes, res.dek_nonce, res.wrapped_dek, aad)
            new_nonce, new_wrapped = aes_gcm_wrap(new_kek_bytes, dek, aad)

            old_kv_id = res.key_version_id
            res.key_version_id = new_kek_row.key_version_id
            res.wrapped_dek = new_wrapped
            res.dek_nonce = new_nonce

            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="resource.rewrap",
                target=resource_id,
                outcome="allow",
                reason_code="REWRAPPED",
                metadata={
                    "from_key_version_id": old_kv_id,
                    "to_key_version_id": new_kek_row.key_version_id,
                },
            )
            return {
                "resource_id": resource_id,
                "from_key_version_id": old_kv_id,
                "to_key_version_id": new_kek_row.key_version_id,
            }

    def destroy_key_version(self, key_version_id: str, actor_ctx: ActorContext) -> dict[str, str]:
        """Destroy an old data key ONLY after all DEKs referencing it have been re-wrapped."""
        now = self.clock.now()
        with tx_session(self.session_factory) as session:
            kv = session.get(KeyVersion, key_version_id)
            if kv is None:
                raise NotFound(f"KeyVersion {key_version_id} not found")
            if kv.state not in ("RETIRED", "REVOKED"):
                raise IllegalTransition("Can only destroy RETIRED or REVOKED key versions")

            ref = session.execute(
                select(Resource.resource_id)
                .where(Resource.key_version_id == key_version_id)
                .limit(1)
            ).first()
            if ref is not None:
                raise Conflict(
                    f"Cannot destroy key_version {key_version_id}: resources still wrapped by it",
                    reason_code="KEY_IN_USE",
                )

            kv.wrapped_private_material = None
            kv.wrap_nonce = None
            kv.wrap_aad = None
            kv.destroyed_at = now
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="key.destroyed",
                target=key_version_id,
                outcome="allow",
                reason_code="DESTROYED",
            )
            return {"key_version_id": key_version_id, "destroyed_at": now.isoformat()}
