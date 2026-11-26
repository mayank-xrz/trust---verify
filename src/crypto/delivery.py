"""Chunked Authenticated Delivery Layer (handles loss, reordering, duplicates, and corruption).

Design choices:
- `chunk_hash` is SHA-256 over the chunk's ciphertext (verified before AEAD decryption).
- `whole_message_hash` is SHA-256 over the reassembled plaintext (verified after all chunks decrypt).
- Nonce derivation: `HKDF-SHA256(ikm=session_key, salt=message_id, info=b"track4/v1/chunk-nonce/" + chunk_index.to_bytes(4, "big"), length=12)`.
  Because each (session_key, message_id, chunk_index) tuple is unique, nonces are never reused under the same key.
- Duplicate chunks (same message_id + chunk_index) are ignored consistently and logged once as `chunk_duplicate_ignored`.
- Any invalid/corrupt chunk discards the entire buffered message and logs `delivery_failed_invalid`.
- Incomplete messages after `timeout_seconds` are discarded and logged as `delivery_failed_incomplete` with missing indices.
"""

from __future__ import annotations
import base64
import hashlib
import math
import time
import uuid
from typing import Any, Callable, Dict, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.audit.logger import AuditLogger
from .envelope import AEADFailedError, EnvelopeError, open_envelope, seal_envelope
from .events import emit_crypto_event
from .replay_cache import PersistentReplayCache


DEFAULT_DELIVERY_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_ACTIVE_MESSAGES = 64


class DeliveryError(Exception):
    """Base error for chunked delivery."""


class DeliveryInvalidError(DeliveryError):
    """Raised when a chunk or reassembled message fails integrity verification."""


def derive_chunk_nonce(session_key: bytes, message_id: str, chunk_index: int) -> bytes:
    """Derive a deterministic 12-byte AES-GCM nonce from (session_key, message_id, chunk_index)."""
    if len(session_key) < 32:
        raise ValueError("session_key must be at least 32 bytes")
    if chunk_index < 0:
        raise ValueError("chunk_index must be >= 0")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=12,
        salt=message_id.encode("utf-8"),
        info=b"track4/v1/chunk-nonce/" + chunk_index.to_bytes(4, "big"),
    ).derive(session_key[:32])


def chunk_and_seal(
    *,
    sender_identity: str,
    sender_device: str,
    recipient_identity: str,
    recipient_device: str,
    session_id: str,
    session_key: bytes,
    signing_secret_key: bytes,
    plaintext: bytes,
    start_counter: int = 0,
    epoch: int = 1,
    chunk_size: int = 1024,
    message_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Split plaintext into chunks, derive unique per-chunk nonces, and seal envelopes."""
    if chunk_size < 1:
        raise ValueError("chunk_size must be >= 1")
    msg_id = message_id or str(uuid.uuid4())
    whole_hash = hashlib.sha256(plaintext).hexdigest()
    chunk_count = max(1, math.ceil(len(plaintext) / chunk_size))
    envelopes: List[Dict[str, Any]] = []

    for idx in range(chunk_count):
        chunk_bytes = plaintext[idx * chunk_size : (idx + 1) * chunk_size]
        nonce = derive_chunk_nonce(session_key, msg_id, idx)
        env = seal_envelope(
            sender_identity=sender_identity,
            sender_device=sender_device,
            recipient_identity=recipient_identity,
            recipient_device=recipient_device,
            session_id=session_id,
            session_key=session_key,
            signing_secret_key=signing_secret_key,
            plaintext=chunk_bytes,
            counter=start_counter + idx,
            epoch=epoch,
            message_id=msg_id,
            chunk_index=idx,
            chunk_count=chunk_count,
            nonce=nonce,
            whole_message_hash=whole_hash,
        )
        envelopes.append(env)
    return envelopes


class ChunkReceiver:
    """Buffers out-of-order chunks, verifies integrity, and reports incomplete/invalid deliveries."""

    def __init__(
        self,
        *,
        local_identity: str,
        local_device: str,
        replay_cache: Optional[PersistentReplayCache] = None,
        audit_logger: Optional[AuditLogger] = None,
        timeout_seconds: float = DEFAULT_DELIVERY_TIMEOUT_SECONDS,
        max_active_messages: int = DEFAULT_MAX_ACTIVE_MESSAGES,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.local_identity = local_identity
        self.local_device = local_device
        self.replay_cache = replay_cache
        self.audit_logger = audit_logger
        self.timeout_seconds = timeout_seconds
        self.max_active_messages = max_active_messages
        self.clock = clock
        self._buffers: Dict[str, Dict[str, Any]] = {}
        self.failure_reports: List[Dict[str, Any]] = []

    def _record_failure(self, report: Dict[str, Any]) -> None:
        self.failure_reports.append(report)

    def ingest_chunk(
        self,
        envelope: Dict[str, Any],
        *,
        session_key: bytes,
        sender_public_key: bytes,
    ) -> Optional[bytes]:
        """Buffer a chunk envelope. Returns reassembled plaintext when all chunks arrive and verify."""
        msg_id = str(envelope.get("message_id", ""))
        sender_id = str(envelope.get("sender_identity", ""))
        session_id = str(envelope.get("session_id", ""))
        chunk_index = int(envelope.get("chunk_index", -1))
        chunk_count = int(envelope.get("chunk_count", 0))

        if chunk_count < 1 or not (0 <= chunk_index < chunk_count):
            emit_crypto_event(
                self.audit_logger,
                actor=sender_id or "unknown",
                source_service=sender_id or "unknown",
                target_service=f"{self.local_identity}/{self.local_device}",
                action="delivery_failed_invalid",
                outcome="failed",
                session_id=session_id,
                message_id=msg_id,
                reason="invalid_chunk_bounds",
                extra={"chunk_index": chunk_index},
            )
            self._buffers.pop(msg_id, None)
            raise DeliveryInvalidError("Invalid chunk index or count")

        buf = self._buffers.get(msg_id)
        if buf is None:
            if len(self._buffers) >= self.max_active_messages:
                oldest_mid = min(self._buffers, key=lambda k: self._buffers[k]["created_at"])
                evicted = self._buffers.pop(oldest_mid)
                missing = sorted(set(range(evicted["chunk_count"])) - set(evicted["chunks"].keys()))
                emit_crypto_event(
                    self.audit_logger,
                    actor=evicted["sender_identity"],
                    source_service=evicted["sender_identity"],
                    target_service=f"{self.local_identity}/{self.local_device}",
                    action="delivery_failed_incomplete",
                    outcome="failed",
                    session_id=evicted["session_id"],
                    message_id=oldest_mid,
                    reason="buffer_capacity_evicted",
                    extra={"missing_chunks": ",".join(str(x) for x in missing)},
                )
                self._record_failure(
                    {
                        "action": "delivery_failed_incomplete",
                        "message_id": oldest_mid,
                        "missing_chunks": missing,
                        "reason": "buffer_capacity_evicted",
                    }
                )
            buf = {
                "created_at": self.clock(),
                "sender_identity": sender_id,
                "session_id": session_id,
                "chunk_count": chunk_count,
                "whole_message_hash": envelope.get("whole_message_hash", ""),
                "chunks": {},
                "duplicates_logged": set(),
            }
            self._buffers[msg_id] = buf

        if chunk_index in buf["chunks"]:
            if chunk_index not in buf["duplicates_logged"]:
                buf["duplicates_logged"].add(chunk_index)
                emit_crypto_event(
                    self.audit_logger,
                    actor=sender_id,
                    source_service=sender_id,
                    target_service=f"{self.local_identity}/{self.local_device}",
                    action="message_rejected",
                    outcome="rejected",
                    session_id=session_id,
                    message_id=msg_id,
                    reason="duplicate_chunk",
                    extra={"chunk_index": chunk_index},
                )
            return None

        buf["chunks"][chunk_index] = envelope

        if len(buf["chunks"]) < buf["chunk_count"]:
            return None

        # All chunks present: verify chunk_hash, AEAD-decrypt (verifying AAD & sig), reassemble, verify whole hash
        plaintext_parts: List[bytes] = []
        for idx in range(buf["chunk_count"]):
            chunk_env = buf["chunks"][idx]
            try:
                raw_ct = base64.b64decode(chunk_env["ciphertext"], validate=True)
                actual_chunk_hash = hashlib.sha256(raw_ct).hexdigest()
                if actual_chunk_hash != chunk_env.get("chunk_hash"):
                    raise DeliveryInvalidError(f"chunk_hash mismatch at index {idx}")

                part = open_envelope(
                    chunk_env,
                    local_identity=self.local_identity,
                    local_device=self.local_device,
                    session_key=session_key,
                    sender_public_key=sender_public_key,
                    replay_cache=self.replay_cache,
                    audit_logger=self.audit_logger,
                )
                plaintext_parts.append(part)
            except (DeliveryInvalidError, EnvelopeError, Exception) as exc:
                self._buffers.pop(msg_id, None)
                reason = getattr(exc, "reason", "chunk_verification_failed")
                emit_crypto_event(
                    self.audit_logger,
                    actor=sender_id,
                    source_service=sender_id,
                    target_service=f"{self.local_identity}/{self.local_device}",
                    action="delivery_failed_invalid",
                    outcome="failed",
                    session_id=session_id,
                    message_id=msg_id,
                    reason=str(reason),
                    extra={"chunk_index": idx},
                )
                self._record_failure(
                    {
                        "action": "delivery_failed_invalid",
                        "message_id": msg_id,
                        "chunk_index": idx,
                        "reason": str(reason),
                    }
                )
                raise DeliveryInvalidError(f"Delivery failed at chunk {idx}: {reason}") from exc

        reassembled = b"".join(plaintext_parts)
        expected_whole = buf["whole_message_hash"]
        if hashlib.sha256(reassembled).hexdigest() != expected_whole:
            self._buffers.pop(msg_id, None)
            emit_crypto_event(
                self.audit_logger,
                actor=sender_id,
                source_service=sender_id,
                target_service=f"{self.local_identity}/{self.local_device}",
                action="delivery_failed_invalid",
                outcome="failed",
                session_id=session_id,
                message_id=msg_id,
                reason="whole_message_hash_mismatch",
                extra={"chunk_index": -1},
            )
            self._record_failure(
                {
                    "action": "delivery_failed_invalid",
                    "message_id": msg_id,
                    "chunk_index": -1,
                    "reason": "whole_message_hash_mismatch",
                }
            )
            raise DeliveryInvalidError("Whole-message SHA-256 mismatch")

        self._buffers.pop(msg_id, None)
        return reassembled

    def check_timeouts(self) -> List[Dict[str, Any]]:
        """Expire incomplete buffered messages older than timeout_seconds and emit events."""
        now = self.clock()
        expired_ids = [
            mid for mid, buf in self._buffers.items() if (now - buf["created_at"]) >= self.timeout_seconds
        ]
        reports: List[Dict[str, Any]] = []
        for mid in expired_ids:
            buf = self._buffers.pop(mid)
            missing = sorted(set(range(buf["chunk_count"])) - set(buf["chunks"].keys()))
            emit_crypto_event(
                self.audit_logger,
                actor=buf["sender_identity"],
                source_service=buf["sender_identity"],
                target_service=f"{self.local_identity}/{self.local_device}",
                action="delivery_failed_incomplete",
                outcome="failed",
                session_id=buf["session_id"],
                message_id=mid,
                reason="delivery_timeout",
                extra={"missing_chunks": ",".join(str(x) for x in missing)},
            )
            report = {
                "action": "delivery_failed_incomplete",
                "message_id": mid,
                "missing_chunks": missing,
                "reason": "delivery_timeout",
            }
            self._record_failure(report)
            reports.append(report)
        return reports
