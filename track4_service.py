"""Single Track 4 adapter entry point; one JSON request per process."""

import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
import tempfile

from src.crypto import aead
from src.crypto.primitives import CryptoError, b64, canonical, hkdf, unb64
from src.crypto.protected_read import protected_read
from src.crypto.session import TrustRegistry

GENESIS_HASH = "0" * 64


def state_dir():
    root = Path(os.environ.get("TRACK4_STATE_DIR") or tempfile.gettempdir()) / "track4-local"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def load(path):
    if not path.exists():
        return {
            "owners": {},
            "contents": {},
            "disabled": [],
            "audit_log": [],
            "used_challenges": {},
        }
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _atomic_write_text(path, text):
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def save(path, state):
    _atomic_write_text(path, json.dumps(state, separators=(",", ":"), ensure_ascii=False))


def _derive_storage_key(key_material):
    ikm = key_material.encode("utf-8") if isinstance(key_material, str) and key_material else secrets.token_bytes(32)
    salt = secrets.token_bytes(16)
    return hkdf(ikm, salt, b"track4/v1/state-at-rest", length=32)


def _load_storage_key(root):
    key_path = root / ".storage_key"
    if not key_path.exists():
        raise CryptoError("storage key missing")
    return unb64(key_path.read_text(encoding="utf-8").strip(), 32)


def _encrypt_contents(storage_key, contents):
    encrypted = {}
    for asset_id, body in contents.items():
        nonce = secrets.token_bytes(12)
        aad = canonical({"asset": asset_id})
        ct, tag = aead.encrypt(storage_key, nonce, aad, body.encode("utf-8"))
        encrypted[asset_id] = {"nonce": b64(nonce), "ciphertext": b64(ct), "tag": b64(tag)}
    return encrypted


def _decrypt_asset(storage_key, asset_id, entry):
    if isinstance(entry, str):
        return entry
    aad = canonical({"asset": asset_id})
    plaintext = aead.decrypt(
        storage_key,
        unb64(entry["nonce"], 12),
        aad,
        unb64(entry["ciphertext"]),
        unb64(entry["tag"], 16),
    )
    return plaintext.decode("utf-8")


def _compute_entry_hash(prev_hash, entry_body):
    return hashlib.sha256(prev_hash.encode("ascii") + canonical(entry_body)).hexdigest()


def _append_audit(state, op, actor, asset, request_id, decision):
    audit_log = state.setdefault("audit_log", [])
    prev_hash = audit_log[-1]["entry_hash"] if audit_log else GENESIS_HASH
    entry_body = {
        "seq": len(audit_log),
        "op": op,
        "actor": actor,
        "asset": asset,
        "request_id": request_id,
        "decision": decision,
        "prev_hash": prev_hash,
    }
    entry_hash = _compute_entry_hash(prev_hash, entry_body)
    audit_log.append({**entry_body, "entry_hash": entry_hash})


def verify_chain(audit_log):
    prev_hash = GENESIS_HASH
    for idx, entry in enumerate(audit_log):
        if not isinstance(entry, dict):
            return False
        if entry.get("seq") != idx or entry.get("prev_hash") != prev_hash:
            return False
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        expected = _compute_entry_hash(prev_hash, body)
        if entry.get("entry_hash") != expected:
            return False
        prev_hash = expected
    return True


def _lookup_read_decision(audit_log, request_id):
    for entry in reversed(audit_log):
        if entry.get("op") == "read" and entry.get("request_id") == request_id:
            return entry.get("decision", "deny")
    return None


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError("request must be object")
    root = state_dir()
    with (root / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = root / "state.json"
        state = load(path)
        op = request.get("op")
        if op == "setup":
            owners, contents, disabled = request.get("owners"), request.get("contents"), request.get("disabled")
            if not isinstance(owners, dict) or not isinstance(contents, dict) or not isinstance(disabled, list):
                raise ValueError("invalid setup")
            if (
                not all(isinstance(k, str) and isinstance(v, str) for k, v in owners.items())
                or not all(isinstance(k, str) and isinstance(v, str) for k, v in contents.items())
                or not all(isinstance(v, str) for v in disabled)
            ):
                raise ValueError("invalid setup data")
            storage_key = _derive_storage_key(request.get("key_material"))
            _atomic_write_text(root / ".storage_key", b64(storage_key))
            encrypted_contents = _encrypt_contents(storage_key, contents)
            save(
                path,
                {
                    "owners": owners,
                    "contents": encrypted_contents,
                    "disabled": disabled,
                    "audit_log": [],
                    "used_challenges": {},
                },
            )
            return {"ready": True}
        if op == "revoke":
            actor = request.get("actor")
            if not isinstance(actor, str):
                raise ValueError("invalid actor")
            state["disabled"] = sorted(set(state["disabled"]) | {actor})
            _append_audit(state, "revoke", actor, None, None, "allow")
            save(path, state)
            trust_path = root / "trust_registry.json"
            if trust_path.exists():
                TrustRegistry(trust_path).revoke(actor)
            return {}
        if op == "audit":
            request_id = request.get("request_id")
            if not isinstance(request_id, str):
                raise ValueError("invalid request id")
            decision = _lookup_read_decision(state.get("audit_log", []), request_id)
            if decision is None:
                _append_audit(state, "audit_unknown", None, None, request_id, "deny")
                save(path, state)
                return {"request_id": request_id, "decision": "deny"}
            return {"request_id": request_id, "decision": decision}
        if op in ("read", "protected_read"):
            actor, asset = request.get("actor"), request.get("asset")
            if not isinstance(actor, str) or not isinstance(asset, str):
                raise ValueError("invalid identity")
            allowed = state["owners"].get(asset) == actor and actor not in state["disabled"] and asset in state["contents"]
            if op == "read":
                request_id = request.get("request_id")
                if not isinstance(request_id, str):
                    raise ValueError("invalid request id")
                decision = "allow" if allowed else "deny"
                _append_audit(state, "read", actor, asset, request_id, decision)
                save(path, state)
                if not allowed:
                    return {"decision": "deny"}
                storage_key = _load_storage_key(root)
                return {"decision": "allow", "body": _decrypt_asset(storage_key, asset, state["contents"][asset])}
            if not allowed:
                _append_audit(state, "protected_read", actor, asset, None, "deny")
                save(path, state)
                return {"decision": "deny"}
            challenge = request.get("challenge")
            used = state.setdefault("used_challenges", {}).setdefault(actor, [])
            if isinstance(challenge, str) and challenge in used:
                raise ValueError("challenge already used")
            storage_key = _load_storage_key(root)
            body = _decrypt_asset(storage_key, asset, state["contents"][asset])
            result = protected_read(challenge, body, request.get("public_key"))
            used.append(challenge)
            _append_audit(state, "protected_read", actor, asset, None, "allow")
            save(path, state)
            return result
        raise ValueError("unsupported operation")


def main():
    try:
        request = json.load(sys.stdin)
        result = dispatch(request)
        if not isinstance(result, dict):
            raise ValueError("invalid response")
        sys.stdout.write(json.dumps(result, allow_nan=False) + "\n")
    except Exception:
        print("Request failed", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
