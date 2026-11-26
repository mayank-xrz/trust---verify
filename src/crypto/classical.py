"""Ephemeral X25519 using the guaranteed Node.js standard crypto library."""
import json
from pathlib import Path
import subprocess

from .primitives import CryptoError, b64, unb64

HELPER = Path(__file__).with_name("node_aead.cjs")


def _call(request):
    try:
        result = subprocess.run(["node", str(HELPER)], input=json.dumps(request), text=True,
                                capture_output=True, check=True, timeout=10)
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise CryptoError("X25519 operation failed") from exc


def keypair():
    result = _call({"op": "x25519_keypair"})
    return unb64(result["public_key"], 44), unb64(result["private_key"], 48)


def shared(private_key, public_key):
    if not isinstance(private_key, bytes) or len(private_key) != 48 or not isinstance(public_key, bytes) or len(public_key) != 44:
        raise CryptoError("invalid X25519 key length")
    return unb64(_call({"op": "x25519_shared", "private_key": b64(private_key), "public_key": b64(public_key)})["data"], 32)
