"""Measure three independent identity processes on localhost using a shared SQLite DB."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path

import httpx
from alembic import command
from alembic.config import Config

from scripts.measure_revocation import NODE_IDS, REPO_ROOT, _authorize, _enroll_and_authenticate, _probe_node
from scripts.seed_sandbox import seed_database
from src.identity_keys.crypto import b64e, generate_ed25519_keypair
from src.identity_keys.db import create_db_engine, create_session_factory


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def start_node(stack, directory, node, environment, *, app="src.identity_keys.api:app", health="/healthz"):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        log = stack.enter_context((directory / f"{node}.log").open("w"))
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", app, "--fd", str(listener.fileno())],
            pass_fds=(listener.fileno(),),
            env={**environment, "NODE_ID": node},
            stdout=log,
            stderr=log,
        )
    stack.callback(stop, process)
    client = stack.enter_context(httpx.Client(base_url=f"http://127.0.0.1:{port}", trust_env=False))
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline and process.poll() is None:
        try:
            if client.get(health).is_success:
                return client
        except httpx.TransportError:
            pass
        time.sleep(0.05)
    raise RuntimeError(f"{node} failed to start: {(directory / f'{node}.log').read_text()}")


def measure(runs):
    with ExitStack() as stack:
        directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="track4-live-")))
        database_url = f"sqlite+pysqlite:///{directory / 'live.db'}"
        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", database_url)
        command.upgrade(cfg, "head")
        engine = create_db_engine(database_url)
        stack.callback(engine.dispose)
        with engine.connect() as connection:
            connection.exec_driver_sql("PRAGMA journal_mode=WAL")
        users = seed_database(create_session_factory(engine), seed=42)
        _, seed = generate_ed25519_keypair()
        admin = secrets.token_urlsafe(32)
        environment = {
            **os.environ,
            "DATABASE_URL": database_url,
            "ADMIN_ENROLL_TOKEN": admin,
            "TOKEN_SIGNING_SEED_B64": b64e(seed),
            "CLUSTER_SYNC_SECRET": secrets.token_urlsafe(32),
            "HEARTBEAT_INTERVAL_MS": "250",
        }
        clients = {node: start_node(stack, directory, node, environment) for node in NODE_IDS}
        pool = stack.enter_context(concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)))
        primary = clients["node-a"]
        headers = {"X-Admin-Enroll-Token": admin}
        _, operator = _enroll_and_authenticate(primary, users["carol"], "operator", headers)
        results = []
        for i in range(runs):
            device, token = _enroll_and_authenticate(primary, users["alice"], f"trial-{i}", headers)
            for node, client in clients.items():
                if not _authorize(client, token)["allowed"]:
                    raise RuntimeError(f"{node} failed the baseline authorization")
            signal = concurrent.futures.Future()
            probes = {node: pool.submit(_probe_node, client, token, signal) for node, client in clients.items()}
            started = time.monotonic_ns()
            try:
                result = primary.post(
                    "/revocations/device",
                    headers={"Authorization": f"Bearer {operator}"},
                    json={"device_id": device, "reason_code": "DEVICE_LOST"},
                ).raise_for_status().json()
                acknowledged = time.monotonic_ns()
                signal.set_result((started, result["commit_seq"]))
            except Exception as exc:
                signal.set_exception(exc)
                raise
            observed = {node: probe.result() for node, probe in probes.items()}
            results.append({
                "trial": i + 1,
                "request_ack_ms": round((acknowledged - started) / 1e6, 3),
                "nodes": {node: {"deny_ms": round(denied, 3), "watermark_ms": round(sync, 3),
                                 "other_denials": other}
                          for node, (denied, sync, other) in observed.items()},
            })
        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5)
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    print(json.dumps(measure(args.runs), indent=2))
