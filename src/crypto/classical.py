"""Ephemeral X25519 via Node.js runtime or Python cryptography library."""

import shutil

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .node_bridge import call_node
from .primitives import CryptoError, b64, unb64


def keypair():
    if shutil.which("node"):
        result = call_node({"op": "x25519_keypair"}, CryptoError)
        return unb64(result["public_key"], 44), unb64(result["private_key"], 48)
    priv = X25519PrivateKey.generate()
    pub_der = priv.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    priv_der = priv.private_bytes(serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return pub_der, priv_der


def ephemeral_shared(peer_public_key):
    if not isinstance(peer_public_key, bytes) or len(peer_public_key) != 44:
        raise CryptoError("invalid X25519 key length")
    if shutil.which("node"):
        result = call_node(
            {"op": "x25519_ephemeral_shared", "peer_public_key": b64(peer_public_key)},
            CryptoError,
        )
        return unb64(result["public_key"], 44), unb64(result["data"], 32)
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
    if shutil.which("node"):
        result = call_node(
            {"op": "x25519_shared", "private_key": b64(private_key), "public_key": b64(public_key)},
            CryptoError,
        )
        return unb64(result["data"], 32)
    try:
        priv = serialization.load_der_private_key(private_key, password=None)
        pub = serialization.load_der_public_key(public_key)
        if not isinstance(priv, X25519PrivateKey) or not isinstance(pub, X25519PublicKey):
            raise CryptoError("invalid X25519 key")
        return priv.exchange(pub)
    except Exception as exc:
        raise CryptoError("invalid X25519 key") from exc
