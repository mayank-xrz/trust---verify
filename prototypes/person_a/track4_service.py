"""Single Track 4 adapter entry point; one JSON request per process."""
import fcntl
import json
import os
import sys
import tempfile
from pathlib import Path

from crypto.protected_read import protected_read


def state_dir():
    root = Path(os.environ.get("TRACK4_STATE_DIR") or tempfile.gettempdir()) / "track4-local"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def load(path):
    if not path.exists():
        return {"owners": {}, "contents": {}, "disabled": [], "audit": {}}
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def save(path, state):
    fd, temp = tempfile.mkstemp(prefix=".state-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(state, stream, separators=(",", ":"), ensure_ascii=False)
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
            if not all(isinstance(k, str) and isinstance(v, str) for k, v in owners.items()) or not all(isinstance(k, str) and isinstance(v, str) for k, v in contents.items()) or not all(isinstance(v, str) for v in disabled):
                raise ValueError("invalid setup data")
            save(path, {"owners": owners, "contents": contents, "disabled": disabled, "audit": {}})
            return {"ready": True}
        if op == "revoke":
            actor = request.get("actor")
            if not isinstance(actor, str):
                raise ValueError("invalid actor")
            state["disabled"] = sorted(set(state["disabled"]) | {actor})
            save(path, state)
            return {}
        if op == "audit":
            request_id = request.get("request_id")
            if not isinstance(request_id, str):
                raise ValueError("invalid request id")
            return {"request_id": request_id, "decision": state["audit"].get(request_id, "deny")}
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
                state["audit"][request_id] = decision
                save(path, state)
                return {"decision": "allow", "body": state["contents"][asset]} if allowed else {"decision": "deny"}
            if not allowed:
                return {"decision": "deny"}
            return protected_read(request.get("challenge"), state["contents"][asset], request.get("public_key"))
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
