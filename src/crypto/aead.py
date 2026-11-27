"""AES-256-GCM via the ``cryptography`` library — no Node.js subprocess.

Key material never leaves the Python process: there is no stdin/stdout
subprocess boundary and no base64 round-trip through a child process.
Requires ``cryptography`` (already a hard dependency in requirements.txt).
"""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .primitives import CryptoError


def _validate_key_nonce(key, nonce):
    if len(key) != 32 or len(nonce) != 12:
        raise CryptoError("invalid AEAD key or nonce")


def encrypt(key, nonce, aad, plaintext):
    """AES-256-GCM encrypt. Returns (ciphertext, 16-byte tag)."""
    _validate_key_nonce(key, nonce)
    sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
    return sealed[:-16], sealed[-16:]


def decrypt(key, nonce, aad, ciphertext, tag):
    """AES-256-GCM decrypt. Raises CryptoError on authentication failure."""
    _validate_key_nonce(key, nonce)
    if len(tag) != 16:
        raise CryptoError("invalid authentication tag")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise CryptoError("AEAD authentication failed") from exc
