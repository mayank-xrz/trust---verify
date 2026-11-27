"""AES-256-GCM with a Node fallback for the offline adapter."""

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None

from .node_bridge import call_node
from .primitives import CryptoError, b64, unb64


def _call(operation, key, nonce, aad, data, tag=None):
    request = {"op": operation, "key": b64(key), "nonce": b64(nonce), "aad": b64(aad), "data": b64(data)}
    if tag is not None:
        request["tag"] = b64(tag)
    return call_node(request, CryptoError)


def _validate_key_nonce(key, nonce):
    if len(key) != 32 or len(nonce) != 12:
        raise CryptoError("invalid AEAD key or nonce")


def encrypt(key, nonce, aad, plaintext):
    _validate_key_nonce(key, nonce)
    if AESGCM is not None:
        sealed = AESGCM(key).encrypt(nonce, plaintext, aad)
        return sealed[:-16], sealed[-16:]
    result = _call("encrypt", key, nonce, aad, plaintext)
    return unb64(result["data"]), unb64(result["tag"], 16)


def decrypt(key, nonce, aad, ciphertext, tag):
    _validate_key_nonce(key, nonce)
    if len(tag) != 16:
        raise CryptoError("invalid authentication tag")
    if AESGCM is not None:
        try:
            return AESGCM(key).decrypt(nonce, ciphertext + tag, aad)
        except InvalidTag as exc:
            raise CryptoError("AEAD authentication failed") from exc
    result = _call("decrypt", key, nonce, aad, ciphertext, tag)
    return unb64(result["data"])
