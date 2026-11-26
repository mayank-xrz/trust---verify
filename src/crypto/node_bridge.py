"""Subprocess bridge to Node.js standard crypto with cached binary lookup and distinct errors."""

import json
from pathlib import Path
import shutil
import subprocess

HELPER = Path(__file__).with_name("node_aead.cjs")
_NODE_BIN = None


def _node_path(CryptoError):
    global _NODE_BIN
    if _NODE_BIN is None:
        resolved = shutil.which("node")
        if not resolved:
            raise CryptoError("Node.js runtime ('node') not found in PATH")
        _NODE_BIN = resolved
    return _NODE_BIN


def call_node(request, CryptoError, timeout=10):
    node_bin = _node_path(CryptoError)
    try:
        result = subprocess.run(
            [node_bin, str(HELPER)],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            check=True,
            timeout=timeout,
        )
        return json.loads(result.stdout)
    except subprocess.TimeoutExpired as exc:
        raise CryptoError("Node.js crypto helper timed out") from exc
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 3 or "AEAD_AUTH_FAILED" in (exc.stderr or ""):
            raise CryptoError("AEAD authentication failed") from exc
        raise CryptoError(f"Node.js crypto helper failed (exit {exc.returncode})") from exc
    except (OSError, ValueError) as exc:
        raise CryptoError("Node.js crypto helper communication failed") from exc


def batch_node(ops, CryptoError, timeout=10):
    if not ops:
        return []
    return call_node({"op": "batch", "ops": ops}, CryptoError, timeout=timeout)["results"]
