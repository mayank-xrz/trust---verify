"""Persistent newline-delimited JSON bridge to Node.js standard crypto."""
import atexit
import json
import os
from pathlib import Path
import select
import shutil
import subprocess
import threading
import time

HELPER = Path(__file__).with_name("node_aead.cjs")
_NODE_BIN = None
_worker = None
_buffer = b""
_request_id = 0
_lock = threading.Lock()


def _node_path(CryptoError):
    global _NODE_BIN
    if _NODE_BIN is None:
        _NODE_BIN = shutil.which("node")
        if not _NODE_BIN:
            raise CryptoError("Node.js runtime ('node') not found in PATH")
    return _NODE_BIN


def _stop_worker():
    global _worker, _buffer
    if _worker is not None and _worker.poll() is None:
        _worker.kill()
        try:
            _worker.wait(timeout=1)
        except subprocess.TimeoutExpired:
            pass
    if _worker is not None:
        for pipe in (_worker.stdin, _worker.stdout):
            if pipe is not None:
                pipe.close()
    _worker = None
    _buffer = b""


atexit.register(_stop_worker)


def _start_worker(CryptoError):
    global _worker
    if _worker is None or _worker.poll() is not None:
        _stop_worker()
        try:
            _worker = subprocess.Popen([_node_path(CryptoError), str(HELPER)],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                       stderr=subprocess.DEVNULL, bufsize=0)
        except OSError as exc:
            raise CryptoError("Node.js crypto worker startup failure") from exc
    return _worker


def call_node(request, CryptoError, timeout=10):
    global _request_id, _buffer
    with _lock:
        worker = _start_worker(CryptoError)
        _request_id += 1
        request_id = _request_id
        try:
            worker.stdin.write((json.dumps({**request, "id": request_id}) + "\n").encode())
            deadline = time.monotonic() + timeout
            while b"\n" not in _buffer:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not select.select([worker.stdout], [], [], remaining)[0]:
                    _stop_worker()
                    raise CryptoError("Node.js crypto worker timed out")
                chunk = os.read(worker.stdout.fileno(), 65536)
                if not chunk:
                    _stop_worker()
                    raise CryptoError("Node.js crypto worker crashed")
                _buffer += chunk
                if len(_buffer) > 32 * 1024 * 1024:
                    _stop_worker()
                    raise CryptoError("Node.js crypto worker malformed response")
            line, _buffer = _buffer.split(b"\n", 1)
            response = json.loads(line)
            if not isinstance(response, dict) or response.get("id") != request_id:
                raise ValueError("wrong response id")
            if response.get("error") == "AEAD_AUTH_FAILED":
                raise CryptoError("AEAD authentication failed")
            if "error" in response:
                raise CryptoError("Node.js crypto operation failed")
            if not isinstance(response.get("result"), dict):
                raise ValueError("missing result")
            return response["result"]
        except CryptoError:
            raise
        except BrokenPipeError as exc:
            _stop_worker()
            raise CryptoError("Node.js crypto worker crashed") from exc
        except (OSError, ValueError, TypeError) as exc:
            _stop_worker()
            raise CryptoError("Node.js crypto worker malformed response") from exc


def batch_node(ops, CryptoError, timeout=10):
    if not ops:
        return []
    return call_node({"op": "batch", "ops": ops}, CryptoError, timeout=timeout)["results"]
