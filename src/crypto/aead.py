"""In-process AES-256-GCM with a detached 16-byte authentication tag."""

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .primitives import CryptoError


def _cipher(key, nonce):
    if len(key) != 32 or len(nonce) != 12:
        raise CryptoError("invalid AEAD key or nonce")
    return AESGCM(key)


def encrypt(key, nonce, aad, plaintext):
    sealed = _cipher(key, nonce).encrypt(nonce, plaintext, aad)
    return sealed[:-16], sealed[-16:]


def decrypt(key, nonce, aad, ciphertext, tag):
    cipher = _cipher(key, nonce)
    if len(tag) != 16:
        raise CryptoError("invalid authentication tag")
    try:
        return cipher.decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag as exc:
        raise CryptoError("AEAD authentication failed") from exc
