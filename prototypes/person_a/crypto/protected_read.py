"""Organizer-specific ML-KEM/HMAC interoperability operation."""
import hashlib
import hmac

from pqcrypto.kem import ml_kem_768

from .primitives import CryptoError, b64, encapsulate, unb64


def protected_read(challenge, stored_body, public_key_b64):
    if not isinstance(challenge, str) or not isinstance(stored_body, str):
        raise CryptoError("invalid protected read input")
    public_key = unb64(public_key_b64, ml_kem_768.PUBLIC_KEY_SIZE)
    ciphertext, shared_secret = encapsulate(public_key)
    proof = hmac.new(shared_secret, (challenge + stored_body).encode("utf-8"), hashlib.sha256).hexdigest()
    return {"ciphertext": b64(ciphertext), "proof": proof}
