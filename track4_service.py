"""Single Track 4 adapter entry point; one JSON request per process."""

import fcntl
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from src.crypto.policy import TimezoneMismatchError, normalize_timezone
from src.crypto.primitives import CryptoError, b64, canonical, unb64
from src.crypto.protected_read import MAX_CHALLENGE_LENGTH, protected_read
from src.crypto.session import PrekeyStore, TrustRegistry

GENESIS_HASH = "0" * 64


def state_dir():
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        root = Path(env_dir) / "track4-local"
    else:
        root = Path(tempfile.gettempdir()) / f"track4-local-{os.getuid()}"
    if root.exists():
        if root.is_symlink() or not root.is_dir():
            raise CryptoError("unsafe state directory")
        st = root.lstat()
        if st.st_uid != os.getuid():
            raise CryptoError("state directory ownership mismatch")
        os.chmod(root, 0o700)
    else:
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
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=b"track4/v1/state-at-rest").derive(ikm)


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
        ct_and_tag = AESGCM(storage_key).encrypt(nonce, body.encode("utf-8"), aad)
        encrypted[asset_id] = {"nonce": b64(nonce), "ciphertext": b64(ct_and_tag[:-16]), "tag": b64(ct_and_tag[-16:])}
    return encrypted


def _decrypt_asset(storage_key, asset_id, entry):
    if isinstance(entry, str):
        return entry
    aad = canonical({"asset": asset_id})
    try:
        plaintext = AESGCM(storage_key).decrypt(
            unb64(entry["nonce"], 12),
            unb64(entry["ciphertext"]) + unb64(entry["tag"], 16),
            aad,
        )
    except Exception as exc:
        raise CryptoError("AEAD authentication failed") from exc
    return plaintext.decode("utf-8")


def _compute_entry_hash(prev_hash, entry_body):
    return hashlib.sha256(prev_hash.encode("ascii") + canonical(entry_body)).hexdigest()


def _append_audit(state, op, actor, asset, request_id, decision, threat=None):
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
    if threat is not None:
        entry_body["threat"] = threat
    entry_hash = _compute_entry_hash(prev_hash, entry_body)
    audit_log.append({**entry_body, "entry_hash": entry_hash})


def _check_timezone_policy(state, actor, request):
    req_tz = request.get("timezone")
    if req_tz is None:
        return None
    req_dev = request.get("device") or "default"
    if not isinstance(req_dev, str) or not req_dev:
        return {"threat": "INVALID_DEVICE", "detail": "Invalid device identifier"}
    try:
        norm_tz = normalize_timezone(req_tz)
    except TimezoneMismatchError as exc:
        return exc.threat_details
    last_logins = state.setdefault("last_login", {})
    prev = last_logins.get(actor)
    if prev is None:
        last_logins[actor] = {"device": req_dev, "timezone": norm_tz}
        return None
    if prev["timezone"] != norm_tz or prev["device"] != req_dev:
        return {
            "threat": "ANOMALOUS_TIMEZONE_ACCESS",
            "severity": "HIGH",
            "last_device": prev["device"],
            "current_device": req_dev,
            "last_timezone": prev["timezone"],
            "request_timezone": norm_tz,
            "detail": (
                f"Access rejected for '{actor}': device/timezone differs from last login "
                f"(last='{prev['device']}' @ '{prev['timezone']}', current='{req_dev}' @ '{norm_tz}') "
                "and can cause session hijack or auth fault."
            ),
        }
    return None


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
    if not isinstance(request_id, str) or not request_id:
        return None
    for entry in reversed(audit_log):
        if entry.get("op") in ("read", "protected_read") and entry.get("request_id") == request_id:
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
        if not verify_chain(state.get("audit_log", [])):
            raise CryptoError("audit chain verification failed")
        # The judged adapter keeps enrollment and prekey state in the same deterministic directory.
        registry = TrustRegistry(root / "trust_registry.json")
        prekeys = PrekeyStore(root / "prekeys.json", registry=registry)
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
            registry._save()
            prekeys._save()
            new_state = {
                    "owners": owners,
                    "contents": encrypted_contents,
                    "disabled": disabled,
                    "audit_log": [],
                    "used_challenges": {},
                }
            _append_audit(new_state, "setup", None, None, None, "allow")
            save(path, new_state)
            return {"ready": True}
        if op == "revoke":
            actor = request.get("actor")
            if not isinstance(actor, str):
                raise ValueError("invalid actor")
            state["disabled"] = sorted(set(state["disabled"]) | {actor})
            _append_audit(state, "revoke", actor, None, None, "allow")
            save(path, state)
            registry.revoke(actor)
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
            _append_audit(state, "audit", None, None, request_id, decision)
            save(path, state)
            return {"request_id": request_id, "decision": decision}
        if op in ("read", "protected_read"):
            actor, asset = request.get("actor"), request.get("asset")
            if not isinstance(actor, str) or not isinstance(asset, str):
                raise ValueError("invalid identity")
            allowed = state["owners"].get(asset) == actor and actor not in state["disabled"] and asset in state["contents"]
            tz_threat = _check_timezone_policy(state, actor, request) if allowed else None
            if tz_threat is not None:
                allowed = False
            if op == "read":
                request_id = request.get("request_id")
                if not isinstance(request_id, str):
                    raise ValueError("invalid request id")
                decision = "allow" if allowed else "deny"
                _append_audit(state, "read", actor, asset, request_id, decision, threat=tz_threat)
                save(path, state)
                if not allowed:
                    return {"decision": "deny"}
                storage_key = _load_storage_key(root)
                return {"decision": "allow", "body": _decrypt_asset(storage_key, asset, state["contents"][asset])}
            req_id = request.get("request_id")
            if req_id is not None and (not isinstance(req_id, str) or not req_id):
                raise ValueError("invalid request id")
            challenge = request.get("challenge")
            context = canonical({"actor": actor, "asset": asset, "request_id": req_id})
            valid_challenge = isinstance(challenge, str) and 0 < len(challenge) <= MAX_CHALLENGE_LENGTH
            challenge_hash = hashlib.sha256(context + b"\x00" + challenge.encode("utf-8")).hexdigest() if valid_challenge else None
            used = state.setdefault("used_challenges", {})
            now = int(time.time())
            used = {key: expiry for key, expiry in used.items() if isinstance(expiry, int) and expiry > now}
            state["used_challenges"] = used
            replay = challenge_hash is not None and any(secrets.compare_digest(challenge_hash, key) for key in used)
            if not allowed or not valid_challenge or replay:
                _append_audit(state, "protected_read", actor, asset, request.get("request_id"), "deny", threat=tz_threat)
                save(path, state)
                return {"decision": "deny"}
            try:
                storage_key = _load_storage_key(root)
                body = _decrypt_asset(storage_key, asset, state["contents"][asset])
                result = protected_read(challenge, body, request.get("public_key"))
            except (CryptoError, KeyError, UnicodeError):
                _append_audit(state, "protected_read", actor, asset, request.get("request_id"), "deny")
                save(path, state)
                return {"decision": "deny"}
            used[challenge_hash] = now + 3600
            _append_audit(state, "protected_read", actor, asset, request.get("request_id"), "allow")
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
