"""Ephemeral X25519 via Python ``cryptography`` library — no Node.js subprocess."""

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .primitives import CryptoError


def keypair():
    priv = X25519PrivateKey.generate()
    pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pub_der, priv_der


def ephemeral_shared(peer_public_key):
    if not isinstance(peer_public_key, bytes) or len(peer_public_key) != 44:
        raise CryptoError("invalid X25519 key length")
    priv = X25519PrivateKey.generate()
    pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    try:
        peer_pub = serialization.load_der_public_key(peer_public_key)
        if not isinstance(peer_pub, X25519PublicKey):
            raise CryptoError("invalid X25519 public key")
        ss = priv.exchange(peer_pub)
    except Exception as exc:
        raise CryptoError("invalid X25519 key") from exc
    return pub_der, ss


def shared(private_key, public_key):
    if not isinstance(private_key, bytes) or len(private_key) != 48 or not isinstance(public_key, bytes) or len(public_key) != 44:
        raise CryptoError("invalid X25519 key length")
    try:
        priv = serialization.load_der_private_key(private_key, password=None)
        pub = serialization.load_der_public_key(public_key)
        if not isinstance(priv, X25519PrivateKey) or not isinstance(pub, X25519PublicKey):
            raise CryptoError("invalid X25519 key")
        return priv.exchange(pub)
    except Exception as exc:
        raise CryptoError("invalid X25519 key") from exc
