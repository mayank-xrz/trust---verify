"""Demo PQC crypto facade backed by pqcrypto (ML-KEM-768, ML-DSA-65).

Uses the real NIST-standardized pqcrypto algorithms and fails closed when
pqcrypto is unavailable; classical fallbacks are deliberately disabled so
``src/crypto/`` remains the single canonical crypto stack.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import hmac
import json
import secrets
import time
import uuid
from typing import Any, Dict, Optional, Set, Tuple

try:
    from pqcrypto.kem import ml_kem_768
    from pqcrypto.sign import ml_dsa_65

    from src.crypto._pqcrypto_compat import (
        kem_decaps,
        kem_encaps,
        kem_keygen,
        sig_keygen,
        sig_sign,
        sig_verify,
    )
    PQCRYPTO_AVAILABLE = True
except ImportError:
    PQCRYPTO_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AEAD_AVAILABLE = True
except ImportError:
    CRYPTO_AEAD_AVAILABLE = False

# RFC 3526 2048-bit MODP Group used only if pqcrypto wheel is absent locally
_MODP_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF",
    16,
)
_MODP_G = 2
_MODP_Q = (_MODP_P - 1) // 2


class RecipientMismatchError(Exception):
    """Raised when envelope recipient binding does not match local node ID."""


class ReplayAttackError(Exception):
    """Raised when a message with duplicate ID or out-of-window sequence is detected."""


class MessageTamperedError(Exception):
    """Raised when message signature or AEAD tag verification fails."""


class ResumptionHijackError(Exception):
    """Raised when a session resumption token is used by an unauthorized peer."""


class MLKEMKeyExchange:
    """ML-KEM-768 Key Encapsulation Mechanism provider (NIST FIPS 203)."""

    ALGORITHM = "ML-KEM-768"
    FALLBACK_ALGORITHM = "MOCK-KEM-768"

    def __init__(self, algorithm: str = ALGORITHM, use_fallback: bool = False):
        if use_fallback or not PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto ML-KEM-768 is required; classical fallback is disabled")
        self.use_fallback = False
        self.algorithm = algorithm
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None

    @property
    def algorithm_name(self) -> str:
        return self.algorithm

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pub, priv = kem_keygen(ml_kem_768)
        self._public_key, self._private_key = pub, priv
        return pub, priv

    def encapsulate(self, peer_public_key: bytes) -> Tuple[bytes, bytes]:
        ct, ss = kem_encaps(ml_kem_768, peer_public_key)
        return ct, ss[:32]

    def decapsulate(self, ciphertext: bytes, private_key: Optional[bytes] = None) -> bytes:
        priv = private_key or self._private_key
        if priv is None:
            raise ValueError("No private key available for decapsulation.")
        ss = kem_decaps(ml_kem_768, priv, ciphertext)
        return ss[:32]

    def wipe_keys(self) -> None:
        self._private_key = None
        self._public_key = None


class MLDSASignature:
    """ML-DSA-65 Digital Signature provider (NIST FIPS 204)."""

    ALGORITHM = "ML-DSA-65"
    FALLBACK_ALGORITHM = "SCHNORR-MODP-2048"

    def __init__(self, algorithm: str = ALGORITHM, use_fallback: bool = False):
        if use_fallback or not PQCRYPTO_AVAILABLE:
            raise RuntimeError("pqcrypto ML-DSA-65 is required; classical fallback is disabled")
        self.use_fallback = False
        self.algorithm = algorithm
        self._private_key: Optional[bytes] = None
        self._public_key: Optional[bytes] = None

    @property
    def algorithm_name(self) -> str:
        return self.algorithm

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        pub, priv = sig_keygen(ml_dsa_65)
        self._public_key, self._private_key = pub, priv
        return pub, priv

    def sign(self, message: bytes, private_key: Optional[bytes] = None) -> bytes:
        priv = private_key or self._private_key
        if priv is None:
            raise ValueError("No private key available for signing.")
        return sig_sign(ml_dsa_65, priv, message)

    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        return sig_verify(ml_dsa_65, public_key, message, signature)


class _FallbackAEAD:
    @staticmethod
    def _block(key: bytes, nonce: bytes, counter: int) -> bytes:
        return hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()

    @classmethod
    def encrypt(cls, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
        enc_k = hashlib.sha256(key + b":enc").digest()
        mac_k = hashlib.sha256(key + b":mac").digest()
        chunks = [
            bytes(b ^ k for b, k in zip(plaintext[i:i + 32], cls._block(enc_k, nonce, i // 32)))
            for i in range(0, len(plaintext), 32)
        ]
        ct = b"".join(chunks)
        mac = hmac.new(mac_k, aad + nonce + ct, hashlib.sha256).digest()
        return ct + mac

    @classmethod
    def decrypt(cls, key: bytes, nonce: bytes, ct_and_tag: bytes, aad: bytes) -> bytes:
        if len(ct_and_tag) < 32:
            raise ValueError("Ciphertext too short.")
        ct, mac = ct_and_tag[:-32], ct_and_tag[-32:]
        enc_k = hashlib.sha256(key + b":enc").digest()
        mac_k = hashlib.sha256(key + b":mac").digest()
        expected = hmac.new(mac_k, aad + nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(mac, expected):
            raise MessageTamperedError("AEAD authentication tag verification failed.")
        chunks = [
            bytes(b ^ k for b, k in zip(ct[i:i + 32], cls._block(enc_k, nonce, i // 32)))
            for i in range(0, len(ct), 32)
        ]
        return b"".join(chunks)


class ReplayProtectionCache:
    """Sliding-window sequence cache + TTL seen message ID deduplication."""

    def __init__(self, window_size: int = 256, ttl_seconds: float = 300.0):
        self.window_size = window_size
        self.ttl_seconds = ttl_seconds
        self.max_seen_seq: int = -1
        self.seen_seq_window: Set[int] = set()
        self.seen_message_ids: Dict[str, float] = {}

    def check_and_record(self, message_id: str, sequence_number: int, timestamp_ns: int) -> None:
        now = time.time()
        expired = [mid for mid, ts in self.seen_message_ids.items() if now - ts > self.ttl_seconds]
        for mid in expired:
            del self.seen_message_ids[mid]

        if message_id in self.seen_message_ids:
            raise ReplayAttackError(f"Duplicate message_id detected: {message_id}")

        if self.max_seen_seq == -1:
            self.max_seen_seq = sequence_number
            self.seen_seq_window.add(sequence_number)
        else:
            if sequence_number in self.seen_seq_window:
                raise ReplayAttackError(f"Replay detected: sequence {sequence_number} already processed.")
            if sequence_number < self.max_seen_seq - self.window_size:
                raise ReplayAttackError(f"Sequence {sequence_number} outside sliding window.")
            if sequence_number > self.max_seen_seq:
                self.max_seen_seq = sequence_number
            self.seen_seq_window.add(sequence_number)
            lower = self.max_seen_seq - self.window_size
            self.seen_seq_window = {s for s in self.seen_seq_window if s >= lower}

        self.seen_message_ids[message_id] = now


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
        signer: Any,
        session_id: Optional[str] = None,
        kem_public_key: Optional[bytes] = None,
        kem_ciphertext: Optional[bytes] = None,
    ) -> Dict[str, Any]:
        message_id = str(uuid.uuid4())
        seq = self.outbound_seq_counters[recipient_id]
        self.outbound_seq_counters[recipient_id] += 1
        timestamp_ns = time.time_ns()
        nonce = secrets.token_bytes(12)

        aad_bytes = json.dumps(
            {
                "v": "1.0.0",
                "mid": message_id,
                "src": sender_id,
                "dst": recipient_id,
                "seq": seq,
                "ts": timestamp_ns,
                "sess": session_id or "",
            },
            sort_keys=True,
        ).encode("utf-8")

        if CRYPTO_AEAD_AVAILABLE:
            ciphertext_bytes = AESGCM(shared_key[:32]).encrypt(nonce, plaintext, aad_bytes)
        else:
            ciphertext_bytes = _FallbackAEAD.encrypt(shared_key[:32], nonce, plaintext, aad_bytes)

        envelope: Dict[str, Any] = {
            "version": "1.0.0",
            "message_id": message_id,
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "session_id": session_id or ("sess-" + secrets.token_hex(16)),
            "sequence_number": seq,
            "timestamp_ns": timestamp_ns,
            "algorithm_suite": {"kem": "ML-KEM-768", "sig": "ML-DSA-65", "aead": "AES-256-GCM"},
            "ciphertext": base64.b64encode(ciphertext_bytes).decode("ascii"),
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "additional_authenticated_data": base64.b64encode(aad_bytes).decode("ascii"),
        }
        if kem_public_key:
            envelope["ephemeral_kem_public_key"] = base64.b64encode(kem_public_key).decode("ascii")
        if kem_ciphertext:
            envelope["kem_ciphertext"] = base64.b64encode(kem_ciphertext).decode("ascii")

        sig_bytes = signer.sign(self._canonical_signature_payload(envelope))
        envelope["signature"] = base64.b64encode(sig_bytes).decode("ascii")
        return envelope

    def unpack_envelope(
        self,
        envelope: Dict[str, Any],
        shared_key: bytes,
        verifier_sig: Any,
        sender_public_key: bytes,
    ) -> bytes:
        if envelope.get("recipient_id") != self.node_id:
            raise RecipientMismatchError(
                f"Recipient binding violation! Target is {envelope.get('recipient_id')}, but local node is {self.node_id}"
            )

        sender_id = envelope["sender_id"]
        raw_sig = base64.b64decode(envelope["signature"])
        if not verifier_sig.verify(self._canonical_signature_payload(envelope), raw_sig, sender_public_key):
            raise MessageTamperedError("ML-DSA signature verification failed on envelope.")

        self.peer_replay_caches[sender_id].check_and_record(
            envelope["message_id"], envelope["sequence_number"], envelope["timestamp_ns"]
        )

        aad_bytes = base64.b64decode(envelope["additional_authenticated_data"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext_bytes = base64.b64decode(envelope["ciphertext"])
        aad_obj = json.loads(aad_bytes.decode("utf-8"))
        if aad_obj.get("dst") != self.node_id or aad_obj.get("src") != sender_id:
            raise RecipientMismatchError("AAD internal recipient/sender binding mismatch!")

        if CRYPTO_AEAD_AVAILABLE:
            try:
                return AESGCM(shared_key[:32]).decrypt(nonce, ciphertext_bytes, aad_bytes)
            except Exception as exc:
                raise MessageTamperedError(f"AEAD decryption failed: {exc}") from exc
        return _FallbackAEAD.decrypt(shared_key[:32], nonce, ciphertext_bytes, aad_bytes)

    @staticmethod
    def _canonical_signature_payload(envelope: Dict[str, Any]) -> bytes:
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


class SessionManager:
    """Manages active sessions and peer-bound resumption tickets."""

    def __init__(self, node_id: str, ticket_lifetime_seconds: float = 3600.0):
        self.node_id = node_id
        self.ticket_lifetime_seconds = ticket_lifetime_seconds
        self._ticket_master_key = secrets.token_bytes(32)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(self, peer_node_id: str, shared_master_secret: bytes, is_client: bool = False) -> Tuple[str, bytes]:
        session_id = "sess-" + secrets.token_hex(16)
        channel_key = hashlib.sha3_256(b"TBV-CHANNEL-KEY:" + shared_master_secret + session_id.encode("utf-8")).digest()
        resumption_secret = hashlib.sha3_256(
            b"TBV-RESUMPTION-SECRET:" + shared_master_secret + session_id.encode("utf-8")
        ).digest()
        self.active_sessions[session_id] = {
            "session_id": session_id,
            "peer_node_id": peer_node_id,
            "channel_key": channel_key,
            "resumption_secret": resumption_secret,
            "created_at": time.time(),
            "sequence": 0,
        }
        return session_id, channel_key

    def issue_resumption_ticket(self, session_id: str) -> str:
        session = self.active_sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")
        now = time.time()
        raw_payload = json.dumps(
            {
                "sid": session["session_id"],
                "peer": session["peer_node_id"],
                "iss": self.node_id,
                "sec": base64.b64encode(session["resumption_secret"]).decode("ascii"),
                "iat": now,
                "exp": now + self.ticket_lifetime_seconds,
            },
            sort_keys=True,
        ).encode("utf-8")
        ticket_mac = hmac.new(self._ticket_master_key, raw_payload, hashlib.sha256).digest()
        return base64.urlsafe_b64encode(raw_payload + ticket_mac).decode("ascii")

    def resume_session(self, ticket_token: str, requesting_peer_id: str) -> Tuple[str, bytes]:
        try:
            raw = base64.urlsafe_b64decode(ticket_token.encode("ascii"))
            if len(raw) < 32:
                raise ValueError("Malformed ticket.")
            payload_bytes, provided_mac = raw[:-32], raw[-32:]
            expected_mac = hmac.new(self._ticket_master_key, payload_bytes, hashlib.sha256).digest()
            if not hmac.compare_digest(provided_mac, expected_mac):
                raise ResumptionHijackError("Resumption ticket signature verification failed!")
            data = json.loads(payload_bytes.decode("utf-8"))
        except Exception as exc:
            if isinstance(exc, ResumptionHijackError):
                raise
            raise ResumptionHijackError(f"Invalid ticket encoding: {exc}") from exc

        if time.time() > data["exp"]:
            raise ResumptionHijackError("Resumption ticket has expired.")
        if data["peer"] != requesting_peer_id:
            raise ResumptionHijackError(
                f"Resumption hijack attempt detected! Ticket issued for {data['peer']}, but presented by {requesting_peer_id}"
            )

        old_secret = base64.b64decode(data["sec"])
        new_sid = "sess-" + secrets.token_hex(16)
        new_key = hashlib.sha3_256(b"TBV-RESUMED-CHANNEL-KEY:" + old_secret + new_sid.encode("utf-8")).digest()
        self.active_sessions[new_sid] = {
            "session_id": new_sid,
            "peer_node_id": requesting_peer_id,
            "channel_key": new_key,
            "resumption_secret": hashlib.sha3_256(old_secret + b":ratchet").digest(),
            "created_at": time.time(),
            "sequence": 0,
        }
        return new_sid, new_key

    def close_session(self, session_id: str) -> None:
        self.active_sessions.pop(session_id, None)
