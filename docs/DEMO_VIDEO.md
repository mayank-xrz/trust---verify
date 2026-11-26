# Demo video — 5-minute shot list

Status: **BLOCKED-HUMAN**. The recording and upload must be performed by a
human. This document is the script and checklist; it deliberately contains no
invented URL. When the video exists, set `DEMO_VIDEO_URL` in the environment
used to build the brief and README (see `env.example`). Until then the variable
stays empty and the published artifacts must say "video pending".

## Recording setup

- Resolution: 1920×1080 or 1280×720, 30 fps, readable terminal font (≥16 pt).
- Shell: fresh terminal at the repository root with `.venv/bin` on `PATH`.
- Pre-warm the environment: `.venv/bin/python -m pytest tests -q` once before
  recording so the first command is not delayed by imports.
- Keep the terminal prompt and command visible; narrate what the output proves.
- Total budget: 5:00. Do not speed up footage; cut dead time instead.

## Scene 1 — Threat model and scope (0:00–0:40)

Show `docs/threat_model.md` and the architecture diagram in `README.md`.

Narration points:

- Adversary: network attacker, malicious/compromised node, replay/relay,
  stolen device, future quantum adversary (HNDL).
- Trust boundary: the identity/key authority is trusted for initial enrollment;
  every later message is verified end-to-end.
- Non-goals: no endpoint malware defence, no physical security, no claim of
  formal verification, no AI/ML detector.

## Scene 2 — Enrollment authorization (0:40–1:30)

Run the focused regression suite:

```sh
.venv/bin/python -m pytest tests/test_phase2_authz.py -q \
  -k "enroll_start_requires or enroll_completion or takeover or admin_token_fails"
```

Show four passing tests. Then demonstrate the negative path live:

```sh
.venv/bin/python - <<'PY'
import os, tempfile
from pathlib import Path
from alembic.config import Config
from alembic import command
from fastapi.testclient import TestClient
from scripts.seed_sandbox import seed_database
from src.identity_keys.api import create_app
from src.identity_keys.db import create_db_engine, create_session_factory

tmp = tempfile.mkdtemp()
url = f"sqlite+pysqlite:///{Path(tmp)/'demo.db'}"
cfg = Config("alembic.ini")
cfg.set_main_option("script_location", "alembic")
cfg.set_main_option("sqlalchemy.url", url)
command.upgrade(cfg, "head")
sf = create_session_factory(create_db_engine(url))
users = seed_database(sf, seed=42)
os.environ["ADMIN_ENROLL_TOKEN"] = "demo-admin-token"
c = TestClient(create_app(database_url=url))
print("unauth:", c.post(f"/api/v1/enroll/start?user_id={users['alice']}").status_code)
print("admin :", c.post(f"/api/v1/enroll/start?user_id={users['alice']}",
      headers={"X-Admin-Enroll-Token": "demo-admin-token"}).status_code)
PY
```

Expected: `unauth: 401`, `admin : 200`. Explain that the audit takeover PoC
(attacker starts enrollment for a victim) now fails closed.

## Scene 3 — Replay rejection (1:30–2:30)

```sh
.venv/bin/python -m src.cli demo-replay
```

Expected JSON: `valid_accepted: true`, `replay_rejected: true`,
`recipient_mismatch_rejected: true`, `log_valid: true`. Point at the rejected
replay and the recipient-binding rejection; these are two different attacks.

## Scene 4 — Revocation and propagation (2:30–3:30)

```sh
PATH="$PWD/.venv/bin:$PATH" ./scripts/run_demo.sh
```

Let it reach Step 4, then pause on:

- `Revoked Key ...`
- `Cross-node propagation latency: ... ms` (read the number from the run; do
  not quote a fixed number in the narration)
- `node-b denied request using revoked key: HTTP 400`
- `node-c denied request using revoked key: HTTP 400`

Explain that the revocation is signed and peers re-read authoritative state
rather than trusting a push payload.

## Scene 5 — Crash/restart and damaged backup (3:30–4:20)

Continue the same `run_demo.sh` run through Step 5:

- `WAL Crash Recovery: Torn write discarded, consistent state recovered`
- `Damaged Backup Blocked: Payload SHA-256 hash mismatch`

Optionally show `scripts/fault.py` for the crash-point injection. State that
the WAL is fsynced and the backup is authenticated with ML-DSA-65.

## Scene 6 — Explainable detector alert (4:20–5:00)

Stay on Step 6 of `run_demo.sh` and show the alert block:

- `[CRITICAL] ... UNAUTHORIZED_PRIVILEGE_ELEVATION`
- `[HIGH] ... CRYPTOGRAPHIC_ATTACK_DETECTED`

For each alert, name the identity, the service/node, and the event id (the
`event_id` and `services[]` fields are part of the alert contract). Close with
the audit-chain verification lines for node-a/b/c.

## Upload checklist

- [ ] Record all six scenes in one take (or clean cuts with no missing context).
- [ ] Confirm no secrets, tokens, or personal paths appear on screen.
- [ ] Upload to the approved host and set `DEMO_VIDEO_URL` to the final URL.
- [ ] Rebuild `docs/project_brief.pdf` and update `README.md` from that variable.
- [ ] Verify `grep -R "trust-but-verify.dev/demo-walkthrough" .` returns nothing.
- [ ] Replace "video pending" in the brief/README with the real URL.

**Human action required:** record, upload, and supply `DEMO_VIDEO_URL`. Do not
commit a guessed or placeholder URL as if it were real.
