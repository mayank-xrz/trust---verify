"""Checked ML-KEM-768, ML-DSA-65, and domain-separated KDF operations."""
import base64
import binascii
import hashlib
import json
import subprocess
from pathlib import Path

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

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
    return ml_kem_768.generate_keypair()


def encapsulate(public_key):
    if not isinstance(public_key, bytes) or len(public_key) != ml_kem_768.PUBLIC_KEY_SIZE:
        raise CryptoError("invalid ML-KEM public key length")
    try:
        return ml_kem_768.encrypt(public_key)
    except (ValueError, TypeError) as exc:
        raise CryptoError("ML-KEM encapsulation failed") from exc


def decapsulate(secret_key, ciphertext):
    if not isinstance(secret_key, bytes) or len(secret_key) != ml_kem_768.SECRET_KEY_SIZE:
        raise CryptoError("invalid ML-KEM secret key length")
    if not isinstance(ciphertext, bytes) or len(ciphertext) != ml_kem_768.CIPHERTEXT_SIZE:
        raise CryptoError("invalid ML-KEM ciphertext length")
    try:
        return ml_kem_768.decrypt(secret_key, ciphertext)
    except (ValueError, TypeError) as exc:
        raise CryptoError("ML-KEM decapsulation failed") from exc


def signing_keypair():
    return ml_dsa_65.generate_keypair()


def sign(secret_key, domain, transcript):
    if not isinstance(secret_key, bytes) or len(secret_key) != ml_dsa_65.SECRET_KEY_SIZE:
        raise CryptoError("invalid ML-DSA secret key length")
    if not isinstance(domain, str) or not domain.startswith("track4/v1/"):
        raise CryptoError("invalid signature domain")
    return ml_dsa_65.sign(secret_key, domain.encode("ascii") + b"\x00" + canonical(transcript))


def verify(public_key, domain, transcript, signature):
    if not isinstance(public_key, bytes) or len(public_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
        raise CryptoError("invalid ML-DSA public key length")
    if not isinstance(signature, bytes) or len(signature) != ml_dsa_65.SIGNATURE_SIZE:
        raise CryptoError("invalid ML-DSA signature length")
    if not isinstance(domain, str) or not domain.startswith("track4/v1/"):
        raise CryptoError("invalid signature domain")
    try:
        valid = ml_dsa_65.verify(public_key, domain.encode("ascii") + b"\x00" + canonical(transcript), signature)
    except (ValueError, TypeError) as exc:
        raise CryptoError("signature verification failed") from exc
    if not valid:
        raise CryptoError("signature verification failed")


def hkdf(secret, salt, info, length=32):
    if not isinstance(secret, bytes) or not secret or not isinstance(salt, bytes) or not isinstance(info, bytes):
        raise CryptoError("invalid KDF input")
    if not 1 <= length <= 255 * 32:
        raise CryptoError("invalid KDF length")
    request = {"op": "hkdf", "ikm": b64(secret), "salt": b64(salt), "info": b64(info), "length": length}
    try:
        result = subprocess.run(["node", str(Path(__file__).with_name("node_aead.cjs"))],
                                input=json.dumps(request), text=True, capture_output=True,
                                check=True, timeout=10)
        return unb64(json.loads(result.stdout)["data"], length)
    except (subprocess.SubprocessError, ValueError, KeyError) as exc:
        raise CryptoError("HKDF operation failed") from exc


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()
