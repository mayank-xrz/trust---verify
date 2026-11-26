"""Ephemeral X25519 using the guaranteed Node.js standard crypto library."""

from .node_bridge import call_node
from .primitives import CryptoError, b64, unb64


def keypair():
    result = call_node({"op": "x25519_keypair"}, CryptoError)
    return unb64(result["public_key"], 44), unb64(result["private_key"], 48)


def ephemeral_shared(peer_public_key):
    if not isinstance(peer_public_key, bytes) or len(peer_public_key) != 44:
        raise CryptoError("invalid X25519 key length")
    result = call_node(
        {"op": "x25519_ephemeral_shared", "peer_public_key": b64(peer_public_key)},
        CryptoError,
    )
    return unb64(result["public_key"], 44), unb64(result["data"], 32)


def shared(private_key, public_key):
    if not isinstance(private_key, bytes) or len(private_key) != 48 or not isinstance(public_key, bytes) or len(public_key) != 44:
        raise CryptoError("invalid X25519 key length")
    result = call_node(
        {"op": "x25519_shared", "private_key": b64(private_key), "public_key": b64(public_key)},
        CryptoError,
    )
    return unb64(result["data"], 32)
