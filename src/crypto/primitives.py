"""Checked ML-KEM-768, ML-DSA-65, and domain-separated KDF operations."""
import base64
import binascii
import hashlib
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from ._pqcrypto_compat import kem_decaps, kem_encaps, kem_keygen, sig_keygen, sig_sign, sig_verify

SUITE = "ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1"


class CryptoError(ValueError):
    pass


def canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def b64(data):
    return base64.b64encode(data).decode("ascii")


def unb64(value, size=None):
    if not isinstance(value, str) or not value.isascii():
        raise CryptoError("invalid base64")
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise CryptoError("invalid base64") from exc
    if b64(raw) != value or (size is not None and len(raw) != size):
        raise CryptoError("invalid encoded length")
    return raw


def kem_keypair():
    try:
        return kem_keygen(ml_kem_768)
    except Exception as exc:
        raise CryptoError("ML-KEM key generation failed") from exc


def encapsulate(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise CryptoError("invalid ML-KEM public key length")
    try:
        return kem_encaps(ml_kem_768, public_key)
    except Exception as exc:
        raise CryptoError("ML-KEM encapsulation failed") from exc


def decapsulate(secret_key, ciphertext):
    if not isinstance(secret_key, bytes) or len(secret_key) != ml_kem_768.SECRET_KEY_SIZE:
        raise CryptoError("invalid ML-KEM secret key length")
    if not isinstance(ciphertext, bytes) or len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
        raise CryptoError("invalid ML-KEM ciphertext length")
    try:
        return kem_decaps(ml_kem_768, secret_key, ciphertext)
    except Exception as exc:
        raise CryptoError("ML-KEM decapsulation failed") from exc


def signing_keypair():
    try:
        return sig_keygen(ml_dsa_65)
    except Exception as exc:
        raise CryptoError("ML-DSA key generation failed") from exc


def sign(secret_key, domain, transcript):
    if not isinstance(secret_key, bytes) or len(secret_key) != ml_dsa_65.SECRET_KEY_SIZE:
        raise CryptoError("invalid ML-DSA secret key length")
    if not isinstance(domain, str) or not domain.startswith("track4/v1/"):
        raise CryptoError("invalid signature domain")
    try:
        return sig_sign(ml_dsa_65, secret_key, domain.encode("ascii") + b"\x00" + canonical(transcript))
    except Exception as exc:
        raise CryptoError("ML-DSA signing failed") from exc


def verify(public_key, domain, transcript, signature):
    if not isinstance(public_key, bytes) or len(public_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
        raise CryptoError("invalid ML-DSA public key length")
    if not isinstance(signature, bytes) or len(signature) != ml_dsa_65.SIGNATURE_SIZE:
        raise CryptoError("invalid ML-DSA signature length")
    if not isinstance(domain, str) or not domain.startswith("track4/v1/"):
        raise CryptoError("invalid signature domain")
    if not sig_verify(ml_dsa_65, public_key, domain.encode("ascii") + b"\x00" + canonical(transcript), signature):
        raise CryptoError("signature verification failed")


def hkdf(secret, salt, info, length=32):
    if not isinstance(secret, bytes) or not secret or not isinstance(salt, bytes) or not isinstance(info, bytes):
        raise CryptoError("invalid KDF input")
    if not 1 <= length <= 255 * 32:
        raise CryptoError("invalid KDF length")
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(secret)


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
