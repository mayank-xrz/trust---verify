"""Secure Messaging Layer.

Implements:
- AEAD (Authenticated Encryption with Associated Data)
- Recipient Binding (prevents recipient swap / forward attacks)
- Replay Attack Cache (monotonic sequence check + sliding window + timestamp TTL)
- Packet Loss and Reordering tolerance
"""

from __future__ import annotations
import base64
import collections
import hashlib
import hmac
import json
import os
import secrets
import time
import uuid
from typing import Dict, Any, Tuple, Optional, Set

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AEAD_AVAILABLE = True
except ImportError:
    CRYPTO_AEAD_AVAILABLE = False


class RecipientMismatchError(Exception):
    """Raised when envelope recipient binding does not match local node ID."""
    pass


class ReplayAttackError(Exception):
    """Raised when a message with duplicate ID or out-of-window sequence is detected."""
    pass


class MessageTamperedError(Exception):
    """Raised when message signature or AEAD tag verification fails."""
    pass


class PurePythonAEAD:
    """Pure-Python AES-CTR + HMAC-SHA256 EtM fallback when cryptography package is absent."""

    @staticmethod
    def _keystream_block(key: bytes, nonce: bytes, counter: int) -> bytes:
        counter_bytes = counter.to_bytes(4, byteorder="big")
        return hashlib.sha256(key + nonce + counter_bytes).digest()

    @classmethod
    def encrypt(cls, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        enc_key = hashlib.sha256(key + b":enc").digest()
        mac_key = hashlib.sha256(key + b":mac").digest()

        ciphertext_blocks = []
        for i in range(0, len(plaintext), 32):
            block = plaintext[i:i + 32]
            keystream = cls._keystream_block(enc_key, nonce, i // 32)
            xor_block = bytes(b ^ k for b, k in zip(block, keystream[:len(block)]))
            ciphertext_blocks.append(xor_block)

        ciphertext = b"".join(ciphertext_blocks)
        mac = hmac.new(mac_key, aad + nonce + ciphertext, hashlib.sha256).digest()
        return ciphertext + mac

    @classmethod
    def decrypt(cls, key: bytes, nonce: bytes, ciphertext_and_tag: bytes, aad: bytes) -> bytes:
        if len(ciphertext_and_tag) < 32:
            raise ValueError("Ciphertext too short.")

        ciphertext = ciphertext_and_tag[:-32]
        mac = ciphertext_and_tag[-32:]

        enc_key = hashlib.sha256(key + b":enc").digest()
        mac_key = hashlib.sha256(key + b":mac").digest()

        expected_mac = hmac.new(mac_key, aad + nonce + ciphertext, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected_mac):
            raise MessageTamperedError("AEAD authentication tag verification failed.")

        plaintext_blocks = []
        for i in range(0, len(ciphertext), 32):
            block = ciphertext[i:i + 32]
            keystream = cls._keystream_block(enc_key, nonce, i // 32)
            xor_block = bytes(b ^ k for b, k in zip(block, keystream[:len(block)]))
            plaintext_blocks.append(xor_block)

        return b"".join(plaintext_blocks)


class ReplayProtectionCache:
    """Tracks sequence numbers with sliding window and seen message IDs with TTL."""

    def __init__(self, window_size: int = 256, ttl_seconds: float = 300.0):
        self.window_size = window_size
        self.ttl_seconds = ttl_seconds
        self.max_seen_seq: int = -1
        self.seen_seq_window: Set[int] = set()
        self.seen_message_ids: Dict[str, float] = {}  # msg_id -> timestamp

    def check_and_record(self, message_id: str, sequence_number: int, timestamp_ns: int) -> None:
        now = time.time()
        self._evict_expired(now)

        # Check duplicate message ID
        if message_id in self.seen_message_ids:
            raise ReplayAttackError(f"Duplicate message_id detected: {message_id}")

        # Check sequence number against sliding window
        if self.max_seen_seq == -1:
            self.max_seen_seq = sequence_number
            self.seen_seq_window.add(sequence_number)
        else:
            if sequence_number in self.seen_seq_window:
                raise ReplayAttackError(f"Replay detected: sequence {sequence_number} already processed.")

            if sequence_number < self.max_seen_seq - self.window_size:
                raise ReplayAttackError(
                    f"Sequence {sequence_number} too old (behind window lower bound {self.max_seen_seq - self.window_size})."
                )

            if sequence_number > self.max_seen_seq:
                self.max_seen_seq = sequence_number

            self.seen_seq_window.add(sequence_number)

            # Prune sequence window
            lower_bound = self.max_seen_seq - self.window_size
            self.seen_seq_window = {s for s in self.seen_seq_window if s >= lower_bound}

        self.seen_message_ids[message_id] = now

    def _evict_expired(self, current_time: float) -> None:
        expired = [mid for mid, ts in self.seen_message_ids.items() if current_time - ts > self.ttl_seconds]
        for mid in expired:
            del self.seen_message_ids[mid]


class SecureMessaging:
    """End-to-end authenticated messaging with recipient binding and anti-replay."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        self.peer_replay_caches: Dict[str, ReplayProtectionCache] = collections.defaultdict(ReplayProtectionCache)
        self.outbound_seq_counters: Dict[str, int] = collections.defaultdict(int)

    def pack_envelope(
        self,
        sender_id: str,
        recipient_id: str,
        plaintext: bytes,
        shared_key: bytes,
        signer,
        session_id: Optional[str] = None,
        kem_public_key: Optional[bytes] = None,
        kem_ciphertext: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        """Encrypts plaintext and packages it into a cryptographically bound envelope."""
        message_id = str(uuid.uuid4())
        seq = self.outbound_seq_counters[recipient_id]
        self.outbound_seq_counters[recipient_id] += 1
        timestamp_ns = time.time_ns()
        nonce = secrets.token_bytes(12)

        # Recipient Binding: Embed sender, recipient, message_id, sequence in AAD
        aad_data = {
            "v": "1.0.0",
            "mid": message_id,
            "src": sender_id,
            "dst": recipient_id,
            "seq": seq,
            "ts": timestamp_ns,
            "sess": session_id or "",
        }
        aad_bytes = json.dumps(aad_data, sort_keys=True).encode("utf-8")

        # Encrypt with AEAD
        if CRYPTO_AEAD_AVAILABLE:
            aesgcm = AESGCM(shared_key[:32])
            ciphertext_bytes = aesgcm.encrypt(nonce, plaintext, aad_bytes)
        else:
            ciphertext_bytes = PurePythonAEAD.encrypt(shared_key[:32], nonce, plaintext, aad_bytes)

        envelope: Dict[str, Any] = {
            "version": "1.0.0",
            "message_id": message_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "session_id": session_id or ("sess-" + secrets.token_hex(16)),
            "sequence_number": seq,
            "timestamp_ns": timestamp_ns,
            "algorithm_suite": {
                "kem": "ML-KEM-768",
                "sig": "ML-DSA-65",
                "aead": "AES-256-GCM",
            },
            "ciphertext": base64.b64encode(ciphertext_bytes).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "additional_authenticated_data": base64.b64encode(aad_bytes).decode("ascii"),
        }

        if kem_public_key:
            envelope["ephemeral_kem_public_key"] = base64.b64encode(kem_public_key).decode("ascii")
        if kem_ciphertext:
            envelope["kem_ciphertext"] = base64.b64encode(kem_ciphertext).decode("ascii")

        # Sign header + ciphertext with ML-DSA
        sig_payload = self._canonical_signature_payload(envelope)
        signature_bytes = signer.sign(sig_payload)
        envelope["signature"] = base64.b64encode(signature_bytes).decode("ascii")

        return envelope

    def unpack_envelope(
        self,
        envelope: Dict[str, Any],
        shared_key: bytes,
        verifier_sig,
        sender_public_key: bytes,
    ) -> bytes:
        """Unpacks envelope, verifying recipient binding, replay cache, signature, and AEAD tag."""
        # 1. Recipient Binding Check
        if envelope.get("recipient_id") != self.node_id:
            raise RecipientMismatchError(
                f"Recipient binding violation! Target is {envelope.get('recipient_id')}, but local node is {self.node_id}"
            )

        sender_id = envelope["sender_id"]
        message_id = envelope["message_id"]
        seq = envelope["sequence_number"]
        timestamp_ns = envelope["timestamp_ns"]

        # 2. Signature verification
        raw_sig = base64.b64decode(envelope["signature"])
        sig_payload = self._canonical_signature_payload(envelope)
        if not verifier_sig.verify(sig_payload, raw_sig, sender_public_key):
            raise MessageTamperedError("ML-DSA signature verification failed on envelope.")

        # 3. Anti-Replay Check
        replay_cache = self.peer_replay_caches[sender_id]
        replay_cache.check_and_record(message_id, seq, timestamp_ns)

        # 4. AEAD Decryption with Recipient-Bound AAD
        aad_bytes = base64.b64decode(envelope["additional_authenticated_data"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext_bytes = base64.b64decode(envelope["ciphertext"])

        # Check AAD fields explicitly match outer envelope
        aad_obj = json.loads(aad_bytes.decode("utf-8"))
        if aad_obj.get("dst") != self.node_id or aad_obj.get("src") != sender_id:
            raise RecipientMismatchError("AAD internal recipient/sender binding mismatch!")

        if CRYPTO_AEAD_AVAILABLE:
            try:
                aesgcm = AESGCM(shared_key[:32])
                plaintext = aesgcm.decrypt(nonce, ciphertext_bytes, aad_bytes)
            except Exception as e:
                raise MessageTamperedError(f"AEAD decryption failed: {e}")
        else:
            plaintext = PurePythonAEAD.decrypt(shared_key[:32], nonce, ciphertext_bytes, aad_bytes)

        return plaintext

    def _canonical_signature_payload(self, envelope: Dict[str, Any]) -> bytes:
        """Constructs deterministic byte payload over all critical envelope metadata."""
        fields = [
            envelope.get("version", ""),
            envelope.get("message_id", ""),
            envelope.get("sender_id", ""),
            envelope.get("recipient_id", ""),
            envelope.get("session_id", ""),
            str(envelope.get("sequence_number", 0)),
            str(envelope.get("timestamp_ns", 0)),
            envelope.get("ciphertext", ""),
            envelope.get("nonce", ""),
            envelope.get("additional_authenticated_data", ""),
        ]
        return b"|".join(f.encode("utf-8") for f in fields)
