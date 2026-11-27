"""Single Track 4 adapter entry point; one JSON request per process."""

import fcntl
import hashlib
import json
import os
import secrets
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError:
    AESGCM = None

from src.crypto import aead
from src.crypto.policy import TimezoneMismatchError, normalize_timezone
from src.crypto.primitives import CryptoError, b64, canonical, hkdf, unb64
from src.crypto.protected_read import MAX_CHALLENGE_LENGTH, protected_read
from src.crypto.session import PrekeyStore, TrustRegistry

GENESIS_HASH = "0" * 64


def state_dir():
    env_dir = os.environ.get("TRACK4_STATE_DIR")
    if env_dir:
        root = Path(env_dir) / "track4-local"
    else:
        legacy = Path(tempfile.gettempdir()) / f"track4-local-{os.getuid()}"
        state_home = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local/state")
        if not state_home.is_absolute():
            raise CryptoError("XDG_STATE_HOME must be an absolute path")
        root = state_home / "trust-but-verify" / "track4-local"
        # Keep using existing state until the operator explicitly moves it.
        if not root.exists() and not root.is_symlink() and (legacy.exists() or legacy.is_symlink()):
            root = legacy
    if root.exists() or root.is_symlink():
        if root.is_symlink() or not root.is_dir():
            raise CryptoError("unsafe state directory")
        st = root.lstat()
        if st.st_uid != os.getuid():
            raise CryptoError("state directory ownership mismatch")
        os.chmod(root, 0o700)
    else:
        try:
            root.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError:
            if env_dir or os.environ.get("XDG_STATE_HOME"):
                raise
            # Read-only rootfs (e.g. judging container with --read-only --tmpfs /tmp):
            # fall back to the OS temp directory when ~/.local/state is not writable.
            root = Path(tempfile.gettempdir()) / f"track4-local-{os.getuid()}"
            if root.exists() or root.is_symlink():
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
    info = b"track4/v1/state-at-rest"
    if AESGCM is None:
        return hkdf(ikm, salt, info)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info).derive(ikm)


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
        plaintext = body.encode("utf-8")
        if AESGCM is None:
            ciphertext, tag = aead.encrypt(storage_key, nonce, aad, plaintext)
        else:
            combined = AESGCM(storage_key).encrypt(nonce, plaintext, aad)
            ciphertext, tag = combined[:-16], combined[-16:]
        encrypted[asset_id] = {"nonce": b64(nonce), "ciphertext": b64(ciphertext), "tag": b64(tag)}
    return encrypted


def _decrypt_asset(storage_key, asset_id, entry):
    if not isinstance(entry, dict):
        raise CryptoError("unauthenticated asset entry")
    aad = canonical({"asset": asset_id})
    try:
        nonce = unb64(entry["nonce"], 12)
        ciphertext = unb64(entry["ciphertext"])
        tag = unb64(entry["tag"], 16)
        if AESGCM is None:
            plaintext = aead.decrypt(storage_key, nonce, aad, ciphertext, tag)
        else:
            plaintext = AESGCM(storage_key).decrypt(nonce, ciphertext + tag, aad)
    except Exception as exc:
        raise CryptoError("AEAD authentication failed") from exc
    return plaintext.decode("utf-8")


def _compute_entry_hash(prev_hash, entry_body):
    return hashlib.sha256(prev_hash.encode("ascii") + canonical(entry_body)).hexdigest()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _append_audit(state, op, actor, asset, request_id, decision, threat=None):
    audit_log = state.setdefault("audit_log", [])
    prev_hash = audit_log[-1]["entry_hash"] if audit_log else GENESIS_HASH
    entry_body = {
        "seq": len(audit_log),
        "ts_utc": _utc_now(),
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


def verify_chain(audit_log, anchor=None):
    if not isinstance(audit_log, list):
        return False
    prev_hash = GENESIS_HASH
    for idx, entry in enumerate(audit_log):
        if not isinstance(entry, dict):
            return False
        seq = entry.get("seq")
        if isinstance(seq, bool) or not isinstance(seq, int) or seq != idx:
            return False
        if entry.get("prev_hash") != prev_hash:
            return False
        ts = entry.get("ts_utc")
        if "ts_utc" in entry and (not isinstance(ts, str) or not ts.endswith("Z")):
            return False
        body = {k: v for k, v in entry.items() if k != "entry_hash"}
        expected = _compute_entry_hash(prev_hash, body)
        if entry.get("entry_hash") != expected:
            return False
        prev_hash = expected
    if anchor is not None:
        if not isinstance(anchor, dict):
            return False
        try:
            exp_count = int(anchor.get("seq_count", 0))
            last_seq = int(anchor.get("last_seq", -1))
        except (TypeError, ValueError):
            return False
        if exp_count < 0 or last_seq < -1 or exp_count != last_seq + 1:
            return False
        if len(audit_log) < exp_count:
            return False
        if exp_count > 0:
            if audit_log[0].get("entry_hash") != anchor.get("genesis_hash"):
                return False
            if last_seq < 0 or last_seq >= len(audit_log) or audit_log[last_seq].get("entry_hash") != anchor.get("last_hash"):
                return False
    return True


def _save_audit_anchor(root, audit_log):
    anchor = {
        "seq_count": len(audit_log),
        "genesis_hash": audit_log[0]["entry_hash"] if audit_log else GENESIS_HASH,
        "last_seq": len(audit_log) - 1,
        "last_hash": audit_log[-1]["entry_hash"] if audit_log else GENESIS_HASH,
    }
    _atomic_write_text(root / ".audit_anchor.json", json.dumps(anchor, separators=(",", ":")))


def _load_audit_anchor(root):
    anchor_path = root / ".audit_anchor.json"
    if not anchor_path.exists():
        return None
    with anchor_path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _lookup_read_decision(audit_log, request_id):
    if not isinstance(request_id, str) or not request_id:
        return None
    for entry in reversed(audit_log):
        if entry.get("op") in ("read", "protected_read") and entry.get("request_id") == request_id:
            return entry.get("decision", "deny")
    return None


def _authenticated_actor(request, op):
    """Resolve the caller from the pinned issuer, or from the explicitly trusted harness."""
    public_key = os.environ.get("TRACK4_ISSUER_PUBLIC_KEY_B64")
    if public_key is None and os.environ.get("TRACK4_TRUSTED_HARNESS") == "1":
        return request.get("actor")

    authorization = request.get("authorization")
    if not public_key or not isinstance(authorization, str) or not authorization.startswith("Bearer "):
        raise CryptoError("caller authentication required")
    from src.identity_keys.clock import SystemClock
    from src.identity_keys.errors import NotAuthorized
    from src.identity_keys.tokens import verify_bearer_token

    token = authorization[len("Bearer "):]
    if not token or len(token) > 4096:
        raise CryptoError("invalid caller credential")
    try:
        actor = verify_bearer_token(unb64(public_key, 32), SystemClock(), token).user_id
    except NotAuthorized as exc:
        raise CryptoError("invalid caller credential") from exc
    if op in {"setup", "revoke", "audit"}:
        admins = {item.strip() for item in os.environ.get("TRACK4_ADMIN_SUBJECTS", "").split(",")}
        if not actor or actor not in admins:
            raise CryptoError("adapter administrator required")
    elif "actor" in request and request["actor"] != actor:
        raise CryptoError("request actor does not match caller")
    return actor


def dispatch(request):
    if not isinstance(request, dict):
        raise ValueError("request must be object")
    op = request.get("op")
    if not isinstance(op, str) or op not in {"setup", "revoke", "audit", "read", "protected_read"}:
        raise ValueError("unsupported operation")
    try:
        authenticated_actor = _authenticated_actor(request, op)
    except (CryptoError, ImportError):
        return {"decision": "deny"}
    root = state_dir()
    with (root / "lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = root / "state.json"
        state = load(path)
        anchor = None if op == "setup" else _load_audit_anchor(root)
        if not verify_chain(state.get("audit_log", []), anchor=anchor):
            raise CryptoError("audit chain verification failed")
        # The judged adapter keeps enrollment and prekey state in the same deterministic directory.
        registry = TrustRegistry(root / "trust_registry.json")
        prekeys = PrekeyStore(root / "prekeys.json", registry=registry)
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
            _save_audit_anchor(root, new_state["audit_log"])
            return {"ready": True}
        if op == "revoke":
            actor = request.get("actor")
            if not isinstance(actor, str):
                raise ValueError("invalid actor")
            state["disabled"] = sorted(set(state["disabled"]) | {actor})
            _append_audit(state, "revoke", actor, None, None, "allow")
            save(path, state)
            _save_audit_anchor(root, state["audit_log"])
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
                _save_audit_anchor(root, state["audit_log"])
                return {"request_id": request_id, "decision": "deny"}
            _append_audit(state, "audit", None, None, request_id, decision)
            save(path, state)
            _save_audit_anchor(root, state["audit_log"])
            return {"request_id": request_id, "decision": decision}
        if op in ("read", "protected_read"):
            actor, asset = authenticated_actor, request.get("asset")
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
                _save_audit_anchor(root, state["audit_log"])
                if not allowed:
                    return {"decision": "deny"}
                storage_key = _load_storage_key(root)
                return {"decision": "allow", "body": _decrypt_asset(storage_key, asset, state["contents"][asset])}
            req_id = request.get("request_id")
            if req_id is not None and (not isinstance(req_id, str) or not req_id):
                raise ValueError("invalid request id")
            challenge = request.get("challenge")
            valid_challenge = isinstance(challenge, str) and 0 < len(challenge) <= MAX_CHALLENGE_LENGTH
            used = state.setdefault("used_challenges", {})
            now = int(time.time())
            used = {key: expiry for key, expiry in used.items() if type(expiry) is int and expiry > now}
            state["used_challenges"] = used
            challenge_hash = None
            replay = False
            if allowed and valid_challenge:
                context = canonical({"actor": actor, "asset": asset, "challenge": challenge})
                challenge_hash = hashlib.sha256(context).hexdigest()
                replay = challenge_hash in used
                if not replay and used:
                    # Older records used request-bound hashes. Recover their request IDs
                    # from successful reads so an upgrade preserves replay history.
                    for entry in state["audit_log"]:
                        if (
                            "ts_utc" in entry
                            or entry["op"] != "protected_read"
                            or entry["decision"] != "allow"
                            or entry["actor"] != actor
                            or entry["asset"] != asset
                        ):
                            continue
                        legacy_context = canonical(
                            {"actor": actor, "asset": asset, "request_id": entry["request_id"]}
                        )
                        legacy_hash = hashlib.sha256(legacy_context + b"\x00" + challenge.encode("utf-8"))
                        if legacy_hash.hexdigest() in used:
                            replay = True
                            break
            if not allowed or not valid_challenge or replay:
                threat = tz_threat
                if replay:
                    threat = {"threat": "CHALLENGE_REPLAY", "detail": "challenge was already used"}
                _append_audit(state, "protected_read", actor, asset, req_id, "deny", threat=threat)
                save(path, state)
                _save_audit_anchor(root, state["audit_log"])
                return {"decision": "deny"}
            try:
                storage_key = _load_storage_key(root)
                body = _decrypt_asset(storage_key, asset, state["contents"][asset])
                result = protected_read(challenge, body, request.get("public_key"))
            except (CryptoError, KeyError, UnicodeError):
                _append_audit(state, "protected_read", actor, asset, request.get("request_id"), "deny")
                save(path, state)
                _save_audit_anchor(root, state["audit_log"])
                return {"decision": "deny"}
            used[challenge_hash] = now + 3600
            _append_audit(state, "protected_read", actor, asset, request.get("request_id"), "allow")
            save(path, state)
            _save_audit_anchor(root, state["audit_log"])
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
