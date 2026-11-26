"""Forward-Secret Hybrid Handshake (Ephemeral X25519 + Ephemeral ML-KEM-768 + ML-DSA-65).

Design:
- Each session generates a fresh ephemeral X25519 keypair and a fresh ephemeral ML-KEM-768 keypair.
- Session keys are derived via HKDF-SHA256 over (transcript_hash || x25519_ss || mlkem_ss)
  with distinct domain-separated `info` labels per derived key.
- Long-term ML-DSA-65 identity keys sign the handshake transcript ONLY; they are never
  used to derive session keys or to encrypt.
- Ephemeral private keys and raw shared secrets are overwritten in mutable bytearrays and
  cleared after key derivation. Note: Python `bytes` objects are immutable and garbage-collected;
  zeroization in Python is therefore best-effort (residual copies may briefly exist in CPython
  heap/allocator until overwritten or freed).
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from ._pqcrypto_compat import kem_decaps, kem_encaps, kem_keygen, sig_sign, sig_verify


class HandshakeError(Exception):
    """Raised when handshake verification or key exchange fails."""


def _best_effort_zeroize(buf: Optional[bytearray]) -> None:
    if buf is not None:
        for i in range(len(buf)):
            buf[i] = 0


def _zeroize_bytes(buf: Optional[bytes]) -> None:
    """Overwrite an immutable ``bytes`` payload in place (CPython best effort).

    PQClean/pqcrypto only accepts ``bytes`` for secret keys, so the only way to
    remove the transient copy is to write zeros into its backing buffer before it
    is released to the allocator.
    """
    if not isinstance(buf, bytes) or not buf:
        return
    try:
        ctypes.memset(id(buf) + bytes.__basicsize__ - 1, 0, len(buf))
    except Exception:
        pass


def _hkdf_derive(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


@dataclass
class SessionKeys:
    session_id: str
    transcript_hash: str
    tx_key: bytes
    rx_key: bytes
    resumption_secret: bytes
    peer_identity: str
    peer_device: str

    def zeroize(self) -> None:
        """Scrub directional keys and the resumption secret in place."""
        for name in ("tx_key", "rx_key", "resumption_secret"):
            value = getattr(self, name, b"")
            _zeroize_bytes(value)
            setattr(self, name, b"")

    def __del__(self) -> None:
        try:
            self.zeroize()
        except Exception:
            pass


class EphemeralHandshakeSession:
    """Holds one side of an in-progress handshake; wipes ephemeral secrets on completion."""

    def __init__(self, identity: str, device: str, signing_secret_key: bytes) -> None:
        self.identity = identity
        self.device = device
        self._signing_secret_key = signing_secret_key
        self._x25519_priv: Optional[X25519PrivateKey] = None
        self._mlkem_priv: Optional[bytearray] = None
        self._x25519_pub_bytes: Optional[bytes] = None
        self._mlkem_pub_bytes: Optional[bytes] = None

    def has_ephemeral_secrets(self) -> bool:
        return self._x25519_priv is not None or self._mlkem_priv is not None

    def _wipe_ephemerals(self) -> None:
        _best_effort_zeroize(self._mlkem_priv)
        self._mlkem_priv = None
        self._x25519_priv = None

    def create_responder_hello(self) -> Dict[str, str]:
        """Generate fresh ephemeral X25519 + ML-KEM-768 keys and sign the offer."""
        self._x25519_priv = X25519PrivateKey.generate()
        self._x25519_pub_bytes = self._x25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        mlkem_pub, mlkem_priv = kem_keygen(ml_kem_768)
        self._mlkem_pub_bytes = mlkem_pub
        self._mlkem_priv = bytearray(mlkem_priv)
        _zeroize_bytes(mlkem_priv)

        hello = {
            "responder_identity": self.identity,
            "responder_device": self.device,
            "session_id": "sess-" + secrets.token_hex(16),
            "x25519_pub": base64.b64encode(self._x25519_pub_bytes).decode("ascii"),
            "mlkem_pub": base64.b64encode(self._mlkem_pub_bytes).decode("ascii"),
        }
        canonical_hello = json.dumps(hello, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig = sig_sign(ml_dsa_65, self._signing_secret_key, b"track4/v1/hello\x00" + canonical_hello)
        hello["signature"] = base64.b64encode(sig).decode("ascii")
        return hello

    def initiate(
        self,
        responder_hello: Dict[str, str],
        responder_signing_public_key: bytes,
    ) -> Tuple[Dict[str, str], SessionKeys]:
        """Verify responder hello, generate initiator ephemerals, derive keys, and wipe ephemerals."""
        hello_unsigned = {k: v for k, v in responder_hello.items() if k != "signature"}
        canonical_hello = json.dumps(hello_unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        sig_bytes = base64.b64decode(responder_hello["signature"], validate=True)
        if not sig_verify(ml_dsa_65, responder_signing_public_key, b"track4/v1/hello\x00" + canonical_hello, sig_bytes):
            raise HandshakeError("Responder hello ML-DSA-65 signature invalid")

        resp_x25519_pub = X25519PublicKey.from_public_bytes(
            base64.b64decode(hello_unsigned["x25519_pub"], validate=True)
        )
        resp_mlkem_pub = base64.b64decode(hello_unsigned["mlkem_pub"], validate=True)

        eph_x25519_priv = X25519PrivateKey.generate()
        eph_x25519_pub = eph_x25519_priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        mlkem_ct, mlkem_ss = kem_encaps(ml_kem_768, resp_mlkem_pub)
        x25519_ss = eph_x25519_priv.exchange(resp_x25519_pub)

        transcript = {
            "session_id": hello_unsigned["session_id"],
            "initiator_identity": self.identity,
            "initiator_device": self.device,
            "responder_identity": hello_unsigned["responder_identity"],
            "responder_device": hello_unsigned["responder_device"],
            "resp_x25519_pub": hello_unsigned["x25519_pub"],
            "resp_mlkem_pub": hello_unsigned["mlkem_pub"],
            "init_x25519_pub": base64.b64encode(eph_x25519_pub).decode("ascii"),
            "mlkem_ct": base64.b64encode(mlkem_ct).decode("ascii"),
        }
        transcript_bytes = json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode("utf-8")
        transcript_hash_bytes = hashlib.sha256(transcript_bytes).digest()
        transcript_hash_hex = transcript_hash_bytes.hex()

        ikm = bytearray(transcript_hash_bytes + x25519_ss + mlkem_ss)
        try:
            tx_key = _hkdf_derive(bytes(ikm), transcript_hash_bytes, b"track4/v1/initiator-to-responder")
            rx_key = _hkdf_derive(bytes(ikm), transcript_hash_bytes, b"track4/v1/responder-to-initiator")
            resumption_secret = _hkdf_derive(bytes(ikm), transcript_hash_bytes, b"track4/v1/resumption-secret")
        finally:
            _best_effort_zeroize(ikm)
            _zeroize_bytes(x25519_ss)
            _zeroize_bytes(mlkem_ss)
            del eph_x25519_priv
            self._wipe_ephemerals()

        init_sig = sig_sign(
            ml_dsa_65,
            self._signing_secret_key,
            b"track4/v1/transcript\x00" + transcript_hash_bytes,
        )
        init_msg = {
            **transcript,
            "signature": base64.b64encode(init_sig).decode("ascii"),
        }
        keys = SessionKeys(
            session_id=hello_unsigned["session_id"],
            transcript_hash=transcript_hash_hex,
            tx_key=tx_key,
            rx_key=rx_key,
            resumption_secret=resumption_secret,
            peer_identity=hello_unsigned["responder_identity"],
            peer_device=hello_unsigned["responder_device"],
        )
        return init_msg, keys

    def complete_responder(
        self,
        init_msg: Dict[str, str],
        initiator_signing_public_key: bytes,
    ) -> SessionKeys:
        """Verify initiator transcript signature, decapsulate, derive keys, and wipe ephemerals."""
        if self._x25519_priv is None or self._mlkem_priv is None:
            raise HandshakeError("No ephemeral keys present (already wiped or not initialized)")

        transcript = {k: v for k, v in init_msg.items() if k != "signature"}
        transcript_bytes = json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode("utf-8")
        transcript_hash_bytes = hashlib.sha256(transcript_bytes).digest()
        sig_bytes = base64.b64decode(init_msg["signature"], validate=True)

        if not sig_verify(
            ml_dsa_65,
            initiator_signing_public_key,
            b"track4/v1/transcript\x00" + transcript_hash_bytes,
            sig_bytes,
        ):
            self._wipe_ephemerals()
            raise HandshakeError("Initiator transcript ML-DSA-65 signature invalid")

        init_x25519_pub = X25519PublicKey.from_public_bytes(
            base64.b64decode(transcript["init_x25519_pub"], validate=True)
        )
        mlkem_ct = base64.b64decode(transcript["mlkem_ct"], validate=True)

        x25519_ss = self._x25519_priv.exchange(init_x25519_pub)
        mlkem_priv_bytes = bytes(self._mlkem_priv)
        try:
            mlkem_ss = kem_decaps(ml_kem_768, mlkem_priv_bytes, mlkem_ct)
        finally:
            _zeroize_bytes(mlkem_priv_bytes)

        ikm = bytearray(transcript_hash_bytes + x25519_ss + mlkem_ss)
        try:
            # Responder rx matches initiator tx, responder tx matches initiator rx
            rx_key = _hkdf_derive(bytes(ikm), transcript_hash_bytes, b"track4/v1/initiator-to-responder")
            tx_key = _hkdf_derive(bytes(ikm), transcript_hash_bytes, b"track4/v1/responder-to-initiator")
            resumption_secret = _hkdf_derive(bytes(ikm), transcript_hash_bytes, b"track4/v1/resumption-secret")
        finally:
            _best_effort_zeroize(ikm)
            _zeroize_bytes(x25519_ss)
            _zeroize_bytes(mlkem_ss)
            self._wipe_ephemerals()

        return SessionKeys(
            session_id=transcript["session_id"],
            transcript_hash=transcript_hash_bytes.hex(),
            tx_key=tx_key,
            rx_key=rx_key,
            resumption_secret=resumption_secret,
            peer_identity=transcript["initiator_identity"],
            peer_device=transcript["initiator_device"],
        )
