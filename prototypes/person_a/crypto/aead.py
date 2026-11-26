"""AES-256-GCM through the guaranteed Node.js runtime; no custom cipher code."""
import json
from pathlib import Path
import subprocess

from .primitives import CryptoError, b64, unb64

HELPER = Path(__file__).with_name("node_aead.cjs")


def _call(operation, key, nonce, aad, data, tag=None):
    if len(key) != 32 or len(nonce) != 12:
        raise CryptoError("invalid AEAD key or nonce")
    request = {"op": operation, "key": b64(key), "nonce": b64(nonce), "aad": b64(aad), "data": b64(data)}
    if tag is not None:
        if len(tag) != 16:
            raise CryptoError("invalid authentication tag")
        request["tag"] = b64(tag)
    try:
        result = subprocess.run(["node", str(HELPER)], input=json.dumps(request), text=True,
                                capture_output=True, check=True, timeout=10)
        return json.loads(result.stdout)
    except (subprocess.SubprocessError, ValueError) as exc:
        raise CryptoError("AEAD authentication failed") from exc


def encrypt(key, nonce, aad, plaintext):
    result = _call("encrypt", key, nonce, aad, plaintext)
    return unb64(result["data"]), unb64(result["tag"], 16)


def decrypt(key, nonce, aad, ciphertext, tag):
    result = _call("decrypt", key, nonce, aad, ciphertext, tag)
    return unb64(result["data"])
