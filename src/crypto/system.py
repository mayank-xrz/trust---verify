"""Unified Post-Quantum Encryption & Decryption System.

Merges the full Track 4 crypto lifecycle into one cohesive endpoint interface:
1. Forward-secret hybrid handshake (ephemeral X25519 + ML-KEM-768 + ML-DSA-65).
2. Single-envelope and chunked authenticated encryption (`encrypt` / `encrypt_chunked`)
   with Key-Committing AEAD and optional ISO 7816-4 bucket padding.
3. Recipient-bound, replay-protected, AEAD-verified decryption (`decrypt` / `decrypt_chunk`).
4. Asymmetric epoch rekeying (`create_rekey_hello` / `initiate_rekey` / `accept_rekey`)
   for Post-Compromise Security (PCS) with 0-grace epoch cutoff.
5. Peer-bound, single-use session resumption (`issue_resumption_ticket` / `resume_session`).
6. Hash-chained audit logging via `AuditLogger`.
"""

from __future__ import annotations
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.sign import ml_dsa_65

from src.audit.logger import AuditLogger
from ._pqcrypto_compat import sig_keygen
from .delivery import ChunkReceiver, DEFAULT_DELIVERY_TIMEOUT_SECONDS, chunk_and_seal
from .envelope import EnvelopeError, open_envelope, seal_envelope
from .events import emit_crypto_event
from .handshake import EphemeralHandshakeSession, SessionKeys
from .policy import (
    DevicePolicyError,
    FilePolicyError,
    MAX_FILE_SIZE_BYTES,
    SingleDeviceRegistry,
    validate_shared_file,
)
from .replay_cache import PersistentReplayCache
from .resumption import PersistentResumptionStore


class SecureCryptoSystem:
    """Unified endpoint combining PQC handshake, encryption, decryption, rekeying, and resumption."""

    def __init__(
        self,
        *,
        identity: str,
        device: str,
        state_dir: str | Path,
        signing_public_key: Optional[bytes] = None,
        signing_secret_key: Optional[bytes] = None,
        replay_window: int = 256,
        delivery_timeout: float = DEFAULT_DELIVERY_TIMEOUT_SECONDS,
    ) -> None:
        self.identity = identity
        self.device = device
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)

        if signing_public_key is None or signing_secret_key is None:
            signing_public_key, signing_secret_key = sig_keygen(ml_dsa_65)
        self.signing_public_key = signing_public_key
        self._signing_secret_key = signing_secret_key

        self.audit_logger = AuditLogger(
            f"{identity}/{device}",
            str(self.state_dir / "crypto_audit.log"),
        )
        self.replay_cache = PersistentReplayCache(
            self.state_dir / "replay.db",
            window_size=replay_window,
        )
        self.resumption_store = PersistentResumptionStore(
            self.state_dir / "resumption.db",
            audit_logger=self.audit_logger,
        )
        self.chunk_receiver = ChunkReceiver(
            local_identity=identity,
            local_device=device,
            replay_cache=self.replay_cache,
            audit_logger=self.audit_logger,
            timeout_seconds=delivery_timeout,
        )
        self.device_registry = SingleDeviceRegistry(self.state_dir / "devices.db")
        self.device_registry.register_device(identity, device)
        self._sessions: Dict[str, SessionKeys] = {}
        self._session_epochs: Dict[str, int] = {}
        self._outbound_counters: Dict[str, int] = {}
        self._pending_handshakes: Dict[str, EphemeralHandshakeSession] = {}
        self._pending_rekeys: Dict[str, Tuple[str, EphemeralHandshakeSession]] = {}

    # ------------------------------------------------------------------
    # Handshake (Responder & Initiator)
    # ------------------------------------------------------------------
    def create_hello(self) -> Dict[str, str]:
        """Responder: create a signed ephemeral X25519 + ML-KEM-768 hello."""
        hs = EphemeralHandshakeSession(self.identity, self.device, self._signing_secret_key)
        hello = hs.create_responder_hello()
        self._pending_handshakes[hello["session_id"]] = hs
        return hello

    def initiate_session(
        self,
        responder_hello: Dict[str, str],
        responder_public_key: bytes,
    ) -> Tuple[Dict[str, str], SessionKeys]:
        """Initiator: verify hello, enforce 1-device-per-user, establish session keys."""
        resp_id = responder_hello.get("responder_identity", "")
        resp_dev = responder_hello.get("responder_device", "")
        try:
            self.device_registry.register_device(resp_id, resp_dev)
        except DevicePolicyError as exc:
            emit_crypto_event(
                self.audit_logger,
                actor=resp_id or "unknown",
                source_service=f"{resp_id}/{resp_dev}",
                target_service=f"{self.identity}/{self.device}",
                action="message_rejected",
                outcome="rejected",
                session_id=responder_hello.get("session_id", ""),
                reason=exc.reason,
            )
            raise
        hs = EphemeralHandshakeSession(self.identity, self.device, self._signing_secret_key)
        init_msg, keys = hs.initiate(responder_hello, responder_public_key)
        self._sessions[keys.session_id] = keys
        self._session_epochs[keys.session_id] = 1
        self._outbound_counters[keys.session_id] = 0
        return init_msg, keys

    def accept_session(
        self,
        init_msg: Dict[str, str],
        initiator_public_key: bytes,
    ) -> SessionKeys:
        """Responder: verify transcript, enforce 1-device-per-user, derive session keys."""
        sid = init_msg["session_id"]
        init_id = init_msg.get("initiator_identity", "")
        init_dev = init_msg.get("initiator_device", "")
        try:
            self.device_registry.register_device(init_id, init_dev)
        except DevicePolicyError as exc:
            emit_crypto_event(
                self.audit_logger,
                actor=init_id or "unknown",
                source_service=f"{init_id}/{init_dev}",
                target_service=f"{self.identity}/{self.device}",
                action="message_rejected",
                outcome="rejected",
                session_id=sid,
                reason=exc.reason,
            )
            raise
        hs = self._pending_handshakes.pop(sid, None)
        if hs is None:
            raise ValueError(f"No pending handshake for session_id={sid}")
        keys = hs.complete_responder(init_msg, initiator_public_key)
        self._sessions[keys.session_id] = keys
        self._session_epochs[keys.session_id] = 1
        self._outbound_counters[keys.session_id] = 0
        return keys

    # ------------------------------------------------------------------
    # Asymmetric Epoch Rekeying (Post-Compromise Security)
    # ------------------------------------------------------------------
    def create_rekey_hello(self, session_id: str) -> Dict[str, str]:
        """Responder: start a fresh asymmetric X25519 + ML-KEM rekey for an existing session."""
        if session_id not in self._sessions:
            raise ValueError(f"Unknown session_id={session_id}")
        hs = EphemeralHandshakeSession(self.identity, self.device, self._signing_secret_key)
        hello = hs.create_responder_hello()
        hello["rekey_for_session_id"] = session_id
        self._pending_rekeys[session_id] = (hello["session_id"], hs)
        return hello

    def _mix_rekey(self, session_id: str, fresh_keys: SessionKeys) -> int:
        old_keys = self._sessions[session_id]
        new_epoch = self._session_epochs.get(session_id, 1) + 1
        salt = f"{session_id}|epoch={new_epoch}".encode("utf-8")
        # fresh_keys.tx_key / rx_key are already directionally aligned (alice.tx == bob.rx)
        new_tx = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt, info=b"track4/v1/rekey-dir"
        ).derive(old_keys.resumption_secret + fresh_keys.tx_key)
        new_rx = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt, info=b"track4/v1/rekey-dir"
        ).derive(old_keys.resumption_secret + fresh_keys.rx_key)
        new_res = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=salt, info=b"track4/v1/rekey-res"
        ).derive(old_keys.resumption_secret + fresh_keys.resumption_secret)
        self._sessions[session_id] = SessionKeys(
            session_id=session_id,
            transcript_hash=fresh_keys.transcript_hash,
            tx_key=new_tx,
            rx_key=new_rx,
            resumption_secret=new_res,
            peer_identity=old_keys.peer_identity,
            peer_device=old_keys.peer_device,
        )
        self._session_epochs[session_id] = new_epoch
        return new_epoch

    def initiate_rekey(
        self,
        session_id: str,
        rekey_hello: Dict[str, str],
        responder_public_key: bytes,
    ) -> Tuple[Dict[str, str], int]:
        """Initiator: perform fresh asymmetric rekey, advance epoch, and drop prior epoch keys."""
        if session_id not in self._sessions:
            raise ValueError(f"Unknown session_id={session_id}")
        hello_clean = {k: v for k, v in rekey_hello.items() if k != "rekey_for_session_id"}
        hs = EphemeralHandshakeSession(self.identity, self.device, self._signing_secret_key)
        init_msg, fresh_keys = hs.initiate(hello_clean, responder_public_key)
        new_epoch = self._mix_rekey(session_id, fresh_keys)
        return init_msg, new_epoch

    def accept_rekey(
        self,
        session_id: str,
        init_msg: Dict[str, str],
        initiator_public_key: bytes,
    ) -> int:
        """Responder: complete fresh asymmetric rekey, advance epoch, and drop prior epoch keys."""
        pending = self._pending_rekeys.pop(session_id, None)
        if pending is None:
            raise ValueError(f"No pending rekey for session_id={session_id}")
        expected_sub_sid, hs = pending
        if init_msg.get("session_id") != expected_sub_sid:
            raise ValueError("Rekey sub-session mismatch")
        fresh_keys = hs.complete_responder(init_msg, initiator_public_key)
        return self._mix_rekey(session_id, fresh_keys)

    # ------------------------------------------------------------------
    # Encryption & Decryption (Single Envelope + Chunked)
    # ------------------------------------------------------------------
    def encrypt(
        self,
        session_id: str,
        plaintext: bytes,
        *,
        epoch: Optional[int] = None,
        pad_bucket: int = 0,
    ) -> Dict[str, Any]:
        """Encrypt and sign a single message for the session's bound peer."""
        keys = self._sessions[session_id]
        active_epoch = epoch if epoch is not None else self._session_epochs.get(session_id, 1)
        counter = self._outbound_counters.get(session_id, 0)
        self._outbound_counters[session_id] = counter + 1
        return seal_envelope(
            sender_identity=self.identity,
            sender_device=self.device,
            recipient_identity=keys.peer_identity,
            recipient_device=keys.peer_device,
            session_id=session_id,
            session_key=keys.tx_key,
            signing_secret_key=self._signing_secret_key,
            plaintext=plaintext,
            counter=counter,
            epoch=active_epoch,
            pad_bucket=pad_bucket,
        )

    def decrypt(
        self,
        envelope: Dict[str, Any],
        sender_public_key: bytes,
    ) -> bytes:
        """Verify recipient binding, signature, epoch, replay cache, key commit, and decrypt AEAD."""
        sid = str(envelope.get("session_id", ""))
        keys = self._sessions.get(sid)
        active_epoch = self._session_epochs.get(sid)
        if keys is not None and active_epoch is not None and int(envelope.get("epoch", -1)) != active_epoch:
            raise EnvelopeError(f"Stale or mismatched epoch: expected {active_epoch}")
        session_key = keys.rx_key if keys is not None else b"\x00" * 32
        return open_envelope(
            envelope,
            local_identity=self.identity,
            local_device=self.device,
            session_key=session_key,
            sender_public_key=sender_public_key,
            replay_cache=self.replay_cache,
            audit_logger=self.audit_logger,
        )

    def encrypt_chunked(
        self,
        session_id: str,
        plaintext: bytes,
        *,
        chunk_size: int = 1024,
        epoch: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Split plaintext into chunks with unique deterministic nonces and seal."""
        keys = self._sessions[session_id]
        active_epoch = epoch if epoch is not None else self._session_epochs.get(session_id, 1)
        start_counter = self._outbound_counters.get(session_id, 0)
        envs = chunk_and_seal(
            sender_identity=self.identity,
            sender_device=self.device,
            recipient_identity=keys.peer_identity,
            recipient_device=keys.peer_device,
            session_id=session_id,
            session_key=keys.tx_key,
            signing_secret_key=self._signing_secret_key,
            plaintext=plaintext,
            start_counter=start_counter,
            epoch=active_epoch,
            chunk_size=chunk_size,
        )
        self._outbound_counters[session_id] = start_counter + len(envs)
        return envs

    def decrypt_chunk(
        self,
        envelope: Dict[str, Any],
        sender_public_key: bytes,
    ) -> Optional[bytes]:
        """Ingest one chunk; returns reassembled plaintext once all chunks verify."""
        sid = str(envelope.get("session_id", ""))
        keys = self._sessions.get(sid)
        session_key = keys.rx_key if keys is not None else b"\x00" * 32
        return self.chunk_receiver.ingest_chunk(
            envelope,
            session_key=session_key,
            sender_public_key=sender_public_key,
        )

    # ------------------------------------------------------------------
    # Peer-Bound Session Resumption
    # ------------------------------------------------------------------
    def issue_resumption_ticket(
        self,
        session_id: str,
        ttl_seconds: float = 300.0,
    ) -> Dict[str, object]:
        """Responder: issue a peer-bound, single-use resumption ticket."""
        keys = self._sessions[session_id]
        return self.resumption_store.issue_ticket(
            session_id=session_id,
            peer_identity=keys.peer_identity,
            peer_device=keys.peer_device,
            original_transcript_hash=keys.transcript_hash,
            resumption_secret=keys.resumption_secret,
            ttl_seconds=ttl_seconds,
        )

    def resume_session(
        self,
        ticket: Dict[str, object],
        *,
        presented_identity: str,
        presented_device: str,
        fresh_nonce: bytes,
        proof_of_possession: str,
        new_transcript_hash: str,
    ) -> Tuple[SessionKeys, Dict[str, object]]:
        """Responder: verify peer binding, expiry, replay, and PoP, then install new session."""
        new_keys, rotated_ticket = self.resumption_store.resume(
            ticket,
            presented_identity=presented_identity,
            presented_device=presented_device,
            fresh_nonce=fresh_nonce,
            proof_of_possession=proof_of_possession,
            new_transcript_hash=new_transcript_hash,
            local_service=f"{self.identity}/{self.device}",
        )
        self._sessions[new_keys.session_id] = new_keys
        self._session_epochs[new_keys.session_id] = 1
        self._outbound_counters[new_keys.session_id] = 0
        return new_keys, rotated_ticket

    # ------------------------------------------------------------------
    # Policy-Enforced File Sharing (20 MB cap + Default Media Formats)
    # ------------------------------------------------------------------
    def share_file(
        self,
        session_id: str,
        filename: str,
        data: bytes,
        *,
        mime_type: Optional[str] = None,
        chunk_size: int = 65536,
    ) -> List[Dict[str, Any]]:
        """Validate 20 MB cap, default media format/magic bytes, and encrypt into chunks."""
        keys = self._sessions[session_id]
        try:
            self.device_registry.verify_device(keys.peer_identity, keys.peer_device)
            meta = validate_shared_file(filename, data, mime_type=mime_type, max_bytes=MAX_FILE_SIZE_BYTES)
        except (FilePolicyError, DevicePolicyError) as exc:
            emit_crypto_event(
                self.audit_logger,
                actor=self.identity,
                source_service=f"{self.identity}/{self.device}",
                target_service=f"{keys.peer_identity}/{keys.peer_device}",
                action="message_rejected",
                outcome="rejected",
                session_id=session_id,
                reason=exc.reason,
            )
            raise
        header_bytes = json.dumps(meta, sort_keys=True, separators=(",", ":")).encode("utf-8")
        framed = len(header_bytes).to_bytes(4, "big") + header_bytes + bytes(data)
        return self.encrypt_chunked(session_id, framed, chunk_size=chunk_size)

    def receive_file_chunk(
        self,
        envelope: Dict[str, Any],
        sender_public_key: bytes,
    ) -> Optional[Tuple[Dict[str, Any], bytes]]:
        """Decrypt file chunk and enforce 20 MB + format + single-device policy on reassembly."""
        sender_id = str(envelope.get("sender_identity", ""))
        sender_dev = str(envelope.get("sender_device", ""))
        sid = str(envelope.get("session_id", ""))
        msg_id = str(envelope.get("message_id", ""))
        try:
            self.device_registry.verify_device(sender_id, sender_dev)
        except DevicePolicyError as exc:
            emit_crypto_event(
                self.audit_logger,
                actor=sender_id or "unknown",
                source_service=f"{sender_id}/{sender_dev}",
                target_service=f"{self.identity}/{self.device}",
                action="message_rejected",
                outcome="rejected",
                session_id=sid,
                message_id=msg_id,
                reason=exc.reason,
            )
            raise

        framed = self.decrypt_chunk(envelope, sender_public_key)
        if framed is None:
            return None
        if len(framed) < 4:
            raise FilePolicyError("Malformed shared file framing")
        hdr_len = int.from_bytes(framed[:4], "big")
        if hdr_len <= 0 or 4 + hdr_len > len(framed):
            raise FilePolicyError("Malformed shared file header")
        meta = json.loads(framed[4 : 4 + hdr_len].decode("utf-8"))
        file_bytes = framed[4 + hdr_len :]
        verified = validate_shared_file(
            str(meta.get("filename", "")),
            file_bytes,
            mime_type=meta.get("mime_type"),
            max_bytes=MAX_FILE_SIZE_BYTES,
        )
        if verified["sha256"] != meta.get("sha256"):
            raise FilePolicyError("Shared file SHA-256 mismatch")
        return verified, file_bytes
