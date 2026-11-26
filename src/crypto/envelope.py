"""Authenticated Envelope with Recipient/Device Binding, AEAD, and ML-DSA-65 Signatures.

Uses vetted primitives only:
- AES-256-GCM via `cryptography.hazmat.primitives.ciphers.aead.AESGCM`
- ML-DSA-65 via `pqcrypto.sign.ml_dsa_65`
"""

from __future__ import annotations
import base64
import hashlib
import json
import secrets
import uuid
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pqcrypto.sign import ml_dsa_65

from src.audit.logger import AuditLogger
from .events import emit_crypto_event
from .replay_cache import (
    CounterOutOfWindowError,
    PersistentReplayCache,
    ReplayRejectedError,
)


class EnvelopeError(Exception):
    """Base error for envelope sealing/opening."""
    reason = "envelope_error"


class RecipientMismatchError(EnvelopeError):
    reason = "recipient_mismatch"


class SignatureInvalidError(EnvelopeError):
    reason = "signature_invalid"


class AEADFailedError(EnvelopeError):
    reason = "aead_failed"


def build_aad(
    *,
    sender_identity: str,
    sender_device: str,
    recipient_identity: str,
    recipient_device: str,
    session_id: str,
    message_id: str,
    counter: int,
    epoch: int,
    chunk_index: int = 0,
    chunk_count: int = 1,
) -> bytes:
    """Build deterministic canonical AAD bytes binding all required metadata."""
    aad_obj = {
        "sender_identity": sender_identity,
        "sender_device": sender_device,
        "recipient_identity": recipient_identity,
        "recipient_device": recipient_device,
        "session_id": session_id,
        "message_id": message_id,
        "counter": counter,
        "epoch": epoch,
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
    }
    return json.dumps(aad_obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _canonical_signature_input(envelope: Dict[str, Any]) -> bytes:
    fields = [
        envelope["version"],
        envelope["sender_identity"],
        envelope["sender_device"],
        envelope["recipient_identity"],
        envelope["recipient_device"],
        envelope["session_id"],
        envelope["message_id"],
        str(envelope["counter"]),
        str(envelope["epoch"]),
        str(envelope["chunk_index"]),
        str(envelope["chunk_count"]),
        envelope["nonce"],
        envelope["ciphertext"],
        envelope["aad"],
        envelope.get("chunk_hash", ""),
        envelope.get("whole_message_hash", ""),
    ]
    return b"track4/v1/envelope\x00" + b"|".join(f.encode("utf-8") for f in fields)


def seal_envelope(
    *,
    sender_identity: str,
    sender_device: str,
    recipient_identity: str,
    recipient_device: str,
    session_id: str,
    session_key: bytes,
    signing_secret_key: bytes,
    plaintext: bytes,
    counter: int,
    epoch: int = 1,
    message_id: Optional[str] = None,
    chunk_index: int = 0,
    chunk_count: int = 1,
    nonce: Optional[bytes] = None,
    whole_message_hash: Optional[str] = None,
) -> Dict[str, Any]:
    """Encrypt plaintext with AES-256-GCM and sign the envelope with ML-DSA-65."""
    if len(session_key) < 32:
        raise ValueError("session_key must be at least 32 bytes")
    msg_id = message_id or str(uuid.uuid4())
    iv = nonce if nonce is not None else secrets.token_bytes(12)
    if len(iv) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")

    aad_bytes = build_aad(
        sender_identity=sender_identity,
        sender_device=sender_device,
        recipient_identity=recipient_identity,
        recipient_device=recipient_device,
        session_id=session_id,
        message_id=msg_id,
        counter=counter,
        epoch=epoch,
        chunk_index=chunk_index,
        chunk_count=chunk_count,
    )

    ciphertext = AESGCM(session_key[:32]).encrypt(iv, plaintext, aad_bytes)
    chunk_hash = hashlib.sha256(ciphertext).hexdigest()

    envelope: Dict[str, Any] = {
        "version": "1.0.0",
        "sender_identity": sender_identity,
        "sender_device": sender_device,
        "recipient_identity": recipient_identity,
        "recipient_device": recipient_device,
        "session_id": session_id,
        "message_id": msg_id,
        "counter": counter,
        "epoch": epoch,
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
        "chunk_hash": chunk_hash,
        "whole_message_hash": whole_message_hash or hashlib.sha256(plaintext).hexdigest(),
        "nonce": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "aad": base64.b64encode(aad_bytes).decode("ascii"),
    }

    sig_input = _canonical_signature_input(envelope)
    sig_bytes = ml_dsa_65.sign(signing_secret_key, sig_input)
    envelope["signature"] = base64.b64encode(sig_bytes).decode("ascii")
    return envelope


def open_envelope(
    envelope: Dict[str, Any],
    *,
    local_identity: str,
    local_device: str,
    session_key: bytes,
    sender_public_key: bytes,
    replay_cache: Optional[PersistentReplayCache] = None,
    audit_logger: Optional[AuditLogger] = None,
    check_replay: bool = True,
) -> bytes:
    """Verify recipient binding (before decrypt), signature, replay cache, and AEAD tag."""
    sender_id = str(envelope.get("sender_identity", ""))
    recipient_id = str(envelope.get("recipient_identity", ""))
    recipient_dev = str(envelope.get("recipient_device", ""))
    session_id = str(envelope.get("session_id", ""))
    message_id = str(envelope.get("message_id", ""))

    # 1. Recipient & device binding BEFORE decryption
    if recipient_id != local_identity or recipient_dev != local_device:
        emit_crypto_event(
            audit_logger,
            actor=sender_id or "unknown",
            source_service=sender_id or "unknown",
            target_service=f"{local_identity}/{local_device}",
            action="message_rejected",
            outcome="rejected",
            session_id=session_id,
            message_id=message_id,
            reason="recipient_mismatch",
            extra={"expected_recipient": f"{local_identity}/{local_device}", "got_recipient": f"{recipient_id}/{recipient_dev}"},
        )
        raise RecipientMismatchError(
            f"Recipient mismatch: expected {local_identity}/{local_device}, got {recipient_id}/{recipient_dev}"
        )

    # Verify AAD matches outer envelope fields before decryption
    try:
        aad_bytes = base64.b64decode(envelope["aad"], validate=True)
        aad_obj = json.loads(aad_bytes.decode("utf-8"))
        expected_aad = build_aad(
            sender_identity=sender_id,
            sender_device=str(envelope["sender_device"]),
            recipient_identity=recipient_id,
            recipient_device=recipient_dev,
            session_id=session_id,
            message_id=message_id,
            counter=int(envelope["counter"]),
            epoch=int(envelope["epoch"]),
            chunk_index=int(envelope.get("chunk_index", 0)),
            chunk_count=int(envelope.get("chunk_count", 1)),
        )
    except Exception as exc:
        emit_crypto_event(
            audit_logger,
            actor=sender_id,
            source_service=sender_id,
            target_service=f"{local_identity}/{local_device}",
            action="aead_failed",
            outcome="rejected",
            session_id=session_id,
            message_id=message_id,
            reason="aead_failed",
        )
        raise AEADFailedError("Malformed AAD") from exc

    if aad_obj.get("recipient_identity") != local_identity or aad_obj.get("recipient_device") != local_device:
        emit_crypto_event(
            audit_logger,
            actor=sender_id,
            source_service=sender_id,
            target_service=f"{local_identity}/{local_device}",
            action="message_rejected",
            outcome="rejected",
            session_id=session_id,
            message_id=message_id,
            reason="recipient_mismatch",
        )
        raise RecipientMismatchError("AAD recipient/device mismatch")

    # 2. ML-DSA-65 signature verification
    try:
        sig_bytes = base64.b64decode(envelope["signature"], validate=True)
        sig_input = _canonical_signature_input(envelope)
        res = ml_dsa_65.verify(sender_public_key, sig_input, sig_bytes)
        valid_sig = res is not False
    except Exception:
        valid_sig = False

    if not valid_sig:
        emit_crypto_event(
            audit_logger,
            actor=sender_id,
            source_service=sender_id,
            target_service=f"{local_identity}/{local_device}",
            action="signature_invalid",
            outcome="rejected",
            session_id=session_id,
            message_id=message_id,
            reason="signature_invalid",
        )
        raise SignatureInvalidError("ML-DSA-65 signature verification failed")

    # 3. Replay & sliding counter window check
    if check_replay and replay_cache is not None:
        try:
            replay_cache.check_and_record(
                sender_identity=sender_id,
                recipient_identity=recipient_id,
                session_id=session_id,
                message_id=message_id,
                counter=int(envelope["counter"]),
            )
        except CounterOutOfWindowError as exc:
            emit_crypto_event(
                audit_logger,
                actor=sender_id,
                source_service=sender_id,
                target_service=f"{local_identity}/{local_device}",
                action="counter_out_of_window",
                outcome="rejected",
                session_id=session_id,
                message_id=message_id,
                reason="counter_out_of_window",
            )
            raise
        except ReplayRejectedError as exc:
            emit_crypto_event(
                audit_logger,
                actor=sender_id,
                source_service=sender_id,
                target_service=f"{local_identity}/{local_device}",
                action="replay_rejected",
                outcome="rejected",
                session_id=session_id,
                message_id=message_id,
                reason="replay_rejected",
            )
            raise

    # 4. AEAD decryption (must use exact aad_bytes from envelope so any AAD tamper fails tag)
    if aad_bytes != expected_aad:
        # Still try AESGCM.decrypt to fail tag or reject directly as aead_failed
        emit_crypto_event(
            audit_logger,
            actor=sender_id,
            source_service=sender_id,
            target_service=f"{local_identity}/{local_device}",
            action="aead_failed",
            outcome="rejected",
            session_id=session_id,
            message_id=message_id,
            reason="aead_failed",
        )
        raise AEADFailedError("AAD does not match envelope header")

    try:
        nonce = base64.b64decode(envelope["nonce"], validate=True)
        ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)
        plaintext = AESGCM(session_key[:32]).decrypt(nonce, ciphertext, aad_bytes)
    except Exception as exc:
        emit_crypto_event(
            audit_logger,
            actor=sender_id,
            source_service=sender_id,
            target_service=f"{local_identity}/{local_device}",
            action="aead_failed",
            outcome="rejected",
            session_id=session_id,
            message_id=message_id,
            reason="aead_failed",
        )
        raise AEADFailedError("AES-256-GCM decryption failed") from exc

    emit_crypto_event(
        audit_logger,
        actor=sender_id,
        source_service=sender_id,
        target_service=f"{local_identity}/{local_device}",
        action="message_accepted",
        outcome="accepted",
        session_id=session_id,
        message_id=message_id,
        reason="ok",
    )
    return plaintext
