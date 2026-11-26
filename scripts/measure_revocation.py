"""Measure API denial and sync convergence after an authoritative device revocation."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import secrets
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.parse import urlsplit

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import event
from sqlalchemy.orm import Session

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.seed_sandbox import seed_database  # noqa: E402
from src.identity_keys.api import create_app  # noqa: E402
from src.identity_keys.crypto import b64e, ed25519_sign, generate_ed25519_keypair  # noqa: E402
from src.identity_keys.db import create_db_engine, create_session_factory  # noqa: E402
from src.identity_keys.metrics import summarize_latencies_ms  # noqa: E402
from src.identity_keys.models import Revocation  # noqa: E402

NODE_IDS = ("node-a", "node-b", "node-c")
PROBE_INTERVAL_SECONDS = 0.005
PROBE_TIMEOUT_SECONDS = 5.0


def _enroll_and_authenticate(
    client: TestClient, user_id: str, label: str, admin_headers: dict[str, str],
) -> tuple[str, str]:
    pub, priv = generate_ed25519_keypair()
    start = client.post(
        "/api/v1/enroll/start", params={"user_id": user_id}, headers=admin_headers
    ).raise_for_status().json()
    device = client.post(
        "/api/v1/enroll",
        headers=admin_headers,
        json={
            "enrollment_id": start["enrollment_id"],
            "nonce": start["nonce"],
            "label": label,
            "public_key_b64": b64e(pub),
            "proof_of_possession_b64": b64e(ed25519_sign(priv, start["nonce"].encode())),
        },
    ).raise_for_status().json()
    device_id = device["device_id"]
    challenge = client.post(
        "/api/v1/auth/challenge", params={"device_id": device_id}
    ).raise_for_status().json()["challenge"]
    result = client.post(
        "/api/v1/auth/verify",
        json={
            "device_id": device_id,
            "challenge": challenge,
            "signature_b64": b64e(ed25519_sign(priv, challenge.encode())),
        },
    ).raise_for_status().json()
    return device_id, result["access_token"]


def _authorize(client: TestClient, token: str) -> dict[str, Any]:
    return client.post(
        "/api/v1/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={"resource_id": "brief-alpha", "permission": "resource:read"},
    ).raise_for_status().json()


def _probe_node(
    client: TestClient, token: str, committed: concurrent.futures.Future[tuple[int, int]],
) -> tuple[float, float, int]:
    commit_ns, commit_seq = committed.result(timeout=PROBE_TIMEOUT_SECONDS)
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    denied_ns = synced_ns = None
    other_denials = 0
    while time.monotonic() < deadline:
        if denied_ns is None:
            decision = _authorize(client, token)
            if not decision["allowed"]:
                if decision["reason_code"] == "DEVICE_REVOKED":
                    denied_ns = time.monotonic_ns()
                else:
                    other_denials += 1
        if synced_ns is None:
            sync = client.get("/node/sync-status").raise_for_status().json()
            if sync["watermark"] >= commit_seq and sync["db_reachable"] and not sync["stale"]:
                synced_ns = time.monotonic_ns()
        if denied_ns is not None and synced_ns is not None:
            return (denied_ns - commit_ns) / 1e6, (synced_ns - commit_ns) / 1e6, other_denials
        time.sleep(PROBE_INTERVAL_SECONDS)
    raise TimeoutError("Node did not report both DEVICE_REVOKED and a converged watermark")


def run_scenario(
    *, name: str, m_runs: int, push_sync: bool, pull_interval_ms: int, seed: int,
) -> dict[str, Any]:
    if m_runs < 1 or pull_interval_ms < 1:
        raise ValueError("Runs and pull interval must be positive")
    admin_enroll_token = secrets.token_urlsafe(32)
    _, signing_seed = generate_ed25519_keypair()
    environment = {
        "ADMIN_ENROLL_TOKEN": admin_enroll_token,
        "TOKEN_SIGNING_SEED_B64": b64e(signing_seed),
        "CLUSTER_SYNC_SECRET": secrets.token_urlsafe(32),
        "HEARTBEAT_INTERVAL_MS": str(pull_interval_ms),
    }
    with ExitStack() as stack:
        stack.enter_context(patch.dict(os.environ, environment))
        tmp = stack.enter_context(tempfile.TemporaryDirectory(prefix=f"rev-bench-{name}-"))
        db_url = f"sqlite+pysqlite:///{Path(tmp) / 'bench.db'}"
        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db_url)
        command.upgrade(cfg, "head")
        engine = create_db_engine(db_url)
        stack.callback(engine.dispose)
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        users = seed_database(create_session_factory(engine), seed=seed)

        clients = {}
        for node_id in NODE_IDS:
            app = create_app(node_id=node_id, database_url=db_url)
            stack.callback(app.state.engine.dispose)
            clients[node_id] = stack.enter_context(TestClient(app))
        primary = clients["node-a"]
        revocation_svc = primary.app.state.revocation_svc
        # Route the production signed push through the peers' HTTP handlers in-process.
        if push_sync:
            revocation_svc.peer_urls = {node: f"http://{node}" for node in NODE_IDS[1:]}

        def deliver_hint(url: str, *, json: dict[str, Any], timeout: float):
            target = urlsplit(url)
            return clients[target.hostname].post(target.path, json=json).raise_for_status()

        stack.enter_context(patch("src.identity_keys.revocation.httpx.post", side_effect=deliver_hint))
        commit_signals: dict[str, concurrent.futures.Future[tuple[int, int]]] = {}

        def before_commit(session: Session) -> None:
            for row in session.new:
                if isinstance(row, Revocation) and row.target_id in commit_signals:
                    session.info["benchmark_revocation"] = (row.target_id, row.commit_seq)
                    break

        def after_commit(session: Session) -> None:
            marker = session.info.pop("benchmark_revocation", None)
            if marker is not None:
                target, seq = marker
                commit_signals[target].set_result((time.monotonic_ns(), seq))

        for name_of_event, listener in (("before_commit", before_commit), ("after_commit", after_commit)):
            event.listen(revocation_svc.session_factory, name_of_event, listener)
            stack.callback(event.remove, revocation_svc.session_factory, name_of_event, listener)

        admin_headers = {"X-Admin-Enroll-Token": admin_enroll_token}
        _, operator_token = _enroll_and_authenticate(primary, users["carol"], "benchmark-operator", admin_headers)
        denial_samples: dict[str, list[float]] = {node: [] for node in clients}
        sync_samples: dict[str, list[float]] = {node: [] for node in clients}
        last_denial, last_sync = [], []
        other_denials = 0
        pool = stack.enter_context(concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)))

        for i in range(m_runs):
            device_id, token = _enroll_and_authenticate(primary, users["alice"], f"benchmark-{i}", admin_headers)
            for node_id, client in clients.items():
                decision = _authorize(client, token)
                if not decision["allowed"]:
                    raise RuntimeError(f"{node_id} failed the baseline access check: {decision['reason_code']}")

            committed: concurrent.futures.Future[tuple[int, int]] = concurrent.futures.Future()
            commit_signals[device_id] = committed
            probes = {node: pool.submit(_probe_node, client, token, committed) for node, client in clients.items()}
            try:
                primary.post(
                    "/revocations/device",
                    headers={"Authorization": f"Bearer {operator_token}"},
                    json={"device_id": device_id, "reason_code": "DEVICE_LOST"},
                ).raise_for_status()
            except Exception as exc:
                if not committed.done():
                    committed.set_exception(exc)
                raise
            observed = {node: result.result() for node, result in probes.items()}
            del commit_signals[device_id]
            for node, (denied_ms, sync_ms, other) in observed.items():
                denial_samples[node].append(denied_ms)
                sync_samples[node].append(sync_ms)
                other_denials += other
            last_denial.append(max(values[0] for values in observed.values()))
            last_sync.append(max(values[1] for values in observed.values()))

        return {
            "scenario": name,
            "m_runs": m_runs,
            "seed": seed,
            "push_sync": push_sync,
            "pull_interval_ms": pull_interval_ms,
            "other_denials_excluded": other_denials,
            "per_node": {node: summarize_latencies_ms(vals) for node, vals in denial_samples.items()},
            "overall_last_node": summarize_latencies_ms(last_denial),
            "watermark_per_node": {node: summarize_latencies_ms(vals) for node, vals in sync_samples.items()},
            "watermark_last_node": summarize_latencies_ms(last_sync),
        }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ci", action="store_true", help="Run 20 iterations per scenario")
    parser.add_argument("--m", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "reports")
    args = parser.parse_args()
    m_runs = args.m if args.m is not None else (20 if args.ci else 100)
    if m_runs < 1:
        parser.error("--m must be positive")

    results = [
        run_scenario(name=name, m_runs=m_runs, push_sync=push, pull_interval_ms=250, seed=args.seed)
        for name, push in (("push_plus_pull", True), ("pull_only_250ms", False))
    ]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "revocation_latency.json").write_text(
        json.dumps(results, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# Revocation Propagation Latency Report",
        "",
        "Measured from SQLAlchemy's successful commit callback to the last of three nodes returning",
        "`DEVICE_REVOKED` or reporting a converged watermark. Each node must allow the same device",
        "and resource before the measured revocation. Each node waits 5 ms between probe cycles.",
        "",
        f"Seed **{args.seed}**, **{m_runs}** trials per scenario. Single-host TestClient with shared SQLite",
        "in WAL mode. In push mode, node-a sends signed HTTP hints in-process to node-b and node-c.",
        "All nodes run a 250 ms heartbeat in both scenarios. Authorization reads the shared",
        "database, so a node can deny a revoked device before its sync watermark catches up.",
        "Timings include request handling and probe delay.",
        "",
        "| Scenario | Last denial p50 | Last denial p95 | Last denial max | Last sync p50 | Last sync p95 | Excluded denials |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for result in results:
        denial = result["overall_last_node"]
        watermark = result["watermark_last_node"]
        lines.append(
            f"| {result['scenario']} | {denial['median_ms']} ms | {denial['p95_ms']} ms | "
            f"{denial['max_ms']} ms | {watermark['median_ms']} ms | {watermark['p95_ms']} ms | "
            f"{result['other_denials_excluded']} |"
        )
    report = "\n".join(lines) + "\n"
    (args.output_dir / "revocation_latency.md").write_text(report, encoding="utf-8")
    print(report, end="")


if __name__ == "__main__":
    main()
