"""Coordinator-clock revocation propagation latency benchmark across 3 nodes."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.seed_sandbox import seed_database  # noqa: E402
from src.identity_keys.api import create_app  # noqa: E402
from src.identity_keys.clock import SystemClock  # noqa: E402
from src.identity_keys.crypto import b64e, ed25519_sign, generate_ed25519_keypair  # noqa: E402
from src.identity_keys.db import create_db_engine, create_session_factory  # noqa: E402
from src.identity_keys.metrics import summarize_latencies_ms  # noqa: E402
from src.identity_keys.revocation import RevocationReason  # noqa: E402


def _probe_node(
    client: TestClient,
    token: str,
    *,
    poll_interval_s: float = 0.005,
    pull_before_probe: bool = False,
    pull_interval_s: float = 0.0,
) -> int:
    """Poll node until it denies with DEVICE_REVOKED and return coordinator monotonic_ns."""
    last_pull = time.monotonic_ns()
    while True:
        now_ns = time.monotonic_ns()
        if pull_before_probe and (now_ns - last_pull) >= int(pull_interval_s * 1_000_000_000):
            client.app.state.sync_mgr.pull_revocations()
            last_pull = now_ns
        resp = client.post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {token}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        ).json()
        if resp["allowed"] is False and resp["reason_code"] in ("DEVICE_REVOKED", "REVOKED"):
            return time.monotonic_ns()
        time.sleep(poll_interval_s)


def run_scenario(
    *,
    name: str,
    m_runs: int,
    push_sync: bool,
    pull_interval_ms: int,
    seed: int,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix=f"rev-bench-{name}-") as tmp:
        db_url = f"sqlite+pysqlite:///{Path(tmp) / 'bench.db'}"
        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db_url)
        command.upgrade(cfg, "head")

        sf = create_session_factory(create_db_engine(db_url))
        users = seed_database(sf, seed=seed)
        _, seed_priv = generate_ed25519_keypair()
        os.environ["TOKEN_SIGNING_SEED_B64"] = b64e(seed_priv)
        os.environ["CLUSTER_SYNC_SECRET"] = "bench-sync-secret"
        os.environ["ADMIN_ENROLL_TOKEN"] = "bench-admin-token"
        admin_headers = {"X-Admin-Enroll-Token": "bench-admin-token"}

        clock = SystemClock()
        clients = {
            nid: TestClient(create_app(node_id=nid, database_url=db_url, clock=clock))
            for nid in ("node-a", "node-b", "node-c")
        }
        for c in clients.values():
            c.app.state.sync_mgr.pull_revocations()

        per_node: dict[str, list[float]] = {nid: [] for nid in clients}
        overall_max: list[float] = []

        for i in range(m_runs):
            pub, priv = generate_ed25519_keypair()
            st = clients["node-a"].post(
                f"/api/v1/enroll/start?user_id={users['alice']}", headers=admin_headers
            ).json()
            pop = ed25519_sign(priv, st["nonce"].encode())
            dev = (
                clients["node-a"]
                .post(
                    "/api/v1/enroll",
                    headers=admin_headers,
                    json={
                        "enrollment_id": st["enrollment_id"],
                        "nonce": st["nonce"],
                        "label": f"bench-dev-{i}",
                        "public_key_b64": b64e(pub),
                        "proof_of_possession_b64": b64e(pop),
                    },
                )
                .json()
            )
            ch = (
                clients["node-a"]
                .post(f"/api/v1/auth/challenge?device_id={dev['device_id']}")
                .json()
            )
            sig = ed25519_sign(priv, ch["challenge"].encode())
            tok = (
                clients["node-a"]
                .post(
                    "/api/v1/auth/verify",
                    json={
                        "device_id": dev["device_id"],
                        "challenge": ch["challenge"],
                        "signature_b64": b64e(sig),
                    },
                )
                .json()["access_token"]
            )

            admin_ctx = clients["node-a"].app.state.token_authority.verify(tok)
            _ = admin_ctx
            rev_svc = clients["node-a"].app.state.revocation_svc
            from src.identity_keys.tokens import ActorContext

            rev_svc.revoke_device(
                ActorContext(users["carol"], "carol-dev", "jti-bench"),
                dev["device_id"],
                RevocationReason.DEVICE_LOST,
                push_sync=push_sync,
            )
            t_commit = time.monotonic_ns()
            if push_sync:
                for c in clients.values():
                    c.app.state.sync_mgr.pull_revocations()

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                futs = {
                    nid: pool.submit(
                        _probe_node,
                        c,
                        tok,
                        poll_interval_s=0.005,
                        pull_before_probe=not push_sync,
                        pull_interval_s=pull_interval_ms / 1000.0,
                    )
                    for nid, c in clients.items()
                }
                t_enf = {nid: fut.result() for nid, fut in futs.items()}

            latencies = {nid: max(0.0, (t_enf[nid] - t_commit) / 1_000_000.0) for nid in clients}
            for nid, ms in latencies.items():
                per_node[nid].append(ms)
            overall_max.append(max(latencies.values()))

        return {
            "scenario": name,
            "m_runs": m_runs,
            "seed": seed,
            "push_sync": push_sync,
            "pull_interval_ms": pull_interval_ms,
            "per_node": {nid: summarize_latencies_ms(vals) for nid, vals in per_node.items()},
            "overall_last_node": summarize_latencies_ms(overall_max),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description="Measure cross-node revocation latency.")
    parser.add_argument("--ci", action="store_true", help="Run CI mode (M=20)")
    parser.add_argument("--m", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    m_runs = args.m if args.m is not None else (20 if args.ci else 100)

    results = [
        run_scenario(
            name="push_plus_pull",
            m_runs=m_runs,
            push_sync=True,
            pull_interval_ms=250,
            seed=args.seed,
        ),
        run_scenario(
            name="pull_only_250ms",
            m_runs=m_runs,
            push_sync=False,
            pull_interval_ms=250,
            seed=args.seed,
        ),
    ]

    reports_dir = REPO_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "revocation_latency.json").write_text(
        json.dumps(results, indent=2), encoding="utf-8"
    )

    lines = [
        "# Revocation Propagation Latency Report",
        "",
        "- **Measurement method:** Single-coordinator `time.monotonic_ns()` "
        "(`t_enforced[node] - t_commit`) with 5 ms parallel probe loop across 3 nodes.",
        f"- **Seed:** `{args.seed}` | **M:** `{m_runs}` per scenario | "
        "**Limits:** Single-host `TestClient` + SQLite, includes 5 ms probe granularity.",
        "",
        "| Scenario | Push | Pull (ms) | Min (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) |",
        "| --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for r in results:
        o = r["overall_last_node"]
        lines.append(
            f"| {r['scenario']} | {r['push_sync']} | {r['pull_interval_ms']} | "
            f"{o['min_ms']} | {o['median_ms']} | {o['p95_ms']} | {o['p99_ms']} | {o['max_ms']} |"
        )
    (reports_dir / "revocation_latency.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
