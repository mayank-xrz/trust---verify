"""Compatibility layer supporting both pqcrypto==0.4.0 and pqcrypto==1.0.0."""

from __future__ import annotations

from typing import Tuple, cast


def kem_keygen(mod) -> Tuple[bytes, bytes]:
    if hasattr(mod, "keygen"):
        return cast(Tuple[bytes, bytes], mod.keygen())
    return cast(Tuple[bytes, bytes], mod.generate_keypair())


def kem_encaps(mod, public_key: bytes) -> Tuple[bytes, bytes]:
    if hasattr(mod, "encaps"):
        return cast(Tuple[bytes, bytes], mod.encaps(public_key))
    return cast(Tuple[bytes, bytes], mod.encrypt(public_key))


def kem_decaps(mod, secret_key: bytes, ciphertext: bytes) -> bytes:
    if hasattr(mod, "decaps"):
        return cast(bytes, mod.decaps(secret_key, ciphertext))
    return cast(bytes, mod.decrypt(secret_key, ciphertext))


def sig_keygen(mod) -> Tuple[bytes, bytes]:
    if hasattr(mod, "keygen"):
        return cast(Tuple[bytes, bytes], mod.keygen())
    return cast(Tuple[bytes, bytes], mod.generate_keypair())


def sig_sign(mod, secret_key: bytes, message: bytes) -> bytes:
    return cast(bytes, mod.sign(secret_key, message))


def sig_verify(mod, public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify signature across pqcrypto 0.4.0 (bool) and 1.0.0 (None or raise)."""
    try:
        res = mod.verify(public_key, message, signature)
    except Exception:
        return False
    return res is not False
