"""Real cryptographic primitives (Ed25519, AES-256-GCM, SHA-256, ML-KEM-768).

No custom cryptographic primitives and no mocked security fallbacks.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def public_key_fingerprint(public_key_bytes: bytes) -> str:
    """Deterministic SHA-256 fingerprint of raw public key bytes."""
    return sha256_hex(public_key_bytes)


def canonical_json_bytes(obj: Any) -> bytes:
    """Canonical UTF-8 JSON encoding."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def generate_ed25519_keypair() -> tuple[bytes, bytes]:
    """Generate raw 32-byte (public_key, private_key) Ed25519 pair."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return (
        pub.public_bytes(Encoding.Raw, PublicFormat.Raw),
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()),
    )


def ed25519_sign(private_key_bytes: bytes, message: bytes) -> bytes:
    """Sign message with raw 32-byte Ed25519 private key."""
    priv = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return priv.sign(message)


def ed25519_verify(public_key_bytes: bytes, message: bytes, signature: bytes) -> bool:
    """Verify Ed25519 signature. Returns True iff cryptographically valid."""
    try:
        pub = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        pub.verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


def aes_gcm_wrap(key_32: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """Wrap key/secret material with AES-256-GCM -> (nonce_12, ciphertext_with_tag)."""
    nonce = os.urandom(12)
    ct = AESGCM(key_32).encrypt(nonce, plaintext, aad)
    return nonce, ct


def aes_gcm_unwrap(key_32: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """Unwrap AES-256-GCM ciphertext."""
    return AESGCM(key_32).decrypt(nonce, ciphertext, aad)


def ml_kem_768_encaps(public_key_bytes: bytes) -> tuple[bytes, bytes]:
    """Encapsulate against raw ML-KEM-768 public key using vetted pqcrypto."""
    import pqcrypto.kem.ml_kem_768 as _ml_kem

    if hasattr(_ml_kem, "encaps"):
        ct, ss = _ml_kem.encaps(public_key_bytes)
    else:
        ct, ss = _ml_kem.encrypt(public_key_bytes)
    return bytes(ct), bytes(ss)


def hmac_sha256_hex(key: bytes, data: bytes) -> str:
    """Lowercase hex HMAC-SHA-256."""
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def b64d(encoded: str) -> bytes:
    return base64.b64decode(encoded, validate=True)
