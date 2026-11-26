"""Ephemeral local-development secrets.

The API refuses to start without a shared token-signing seed (and other
secrets), so the compose-free helper scripts generate random values once and
persist them to a private file under the system temp directory.  Nothing is
committed, and every value is unique to this machine's local run.

Usage:
    python -m scripts.local_secrets            # JSON object on stdout
    python -m scripts.local_secrets --shell    # shell export statements
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
from pathlib import Path

DEFAULT_PATH = Path(os.environ.get("TBV_LOCAL_ENV_FILE", "/tmp/tbv_local_env.json"))

# name -> raw byte length before base64 encoding
SECRETS = {
    "TOKEN_SIGNING_SEED_B64": 32,
    "WRAP_MASTER_KEY_B64": 32,
    "CLUSTER_SYNC_SECRET": 32,
    "ADMIN_ENROLL_TOKEN": 16,
}


def ensure_local_secrets(path: Path | None = None) -> dict[str, str]:
    target = path or DEFAULT_PATH
    data: dict[str, str] = {}
    if target.exists():
        try:
            loaded = json.loads(target.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = {k: str(v) for k, v in loaded.items() if isinstance(v, str)}
        except (OSError, ValueError):
            data = {}
    changed = False
    for name, raw_len in SECRETS.items():
        if not data.get(name):
            data[name] = base64.b64encode(secrets.token_bytes(raw_len)).decode("ascii")
            changed = True
    if changed:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(data, sort_keys=True), encoding="utf-8")
        target.chmod(stat.S_IRUSR | stat.S_IWUSR)
    return {name: data[name] for name in SECRETS}


def main() -> int:
    import sys

    values = ensure_local_secrets()
    if "--shell" in sys.argv[1:]:
        for name, value in values.items():
            print(f"export {name}={value!r}")
    else:
        print(json.dumps(values, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
