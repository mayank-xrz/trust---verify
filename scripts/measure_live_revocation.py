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
from datetime import datetime, timezone
from pathlib import Path

import httpx
from alembic import command
from alembic.config import Config

from scripts.measure_revocation import NODE_IDS, REPO_ROOT, _authenticate, _authorize, _enroll_and_authenticate, _probe_node
from scripts.seed_sandbox import seed_database
from src.identity_keys.crypto import b64e, ed25519_sign, generate_ed25519_keypair
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.models import Resource, Revocation


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


def wait_for_sync(node, client):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        status = client.get("/node/sync-status").raise_for_status().json()
        if status["db_reachable"] and not status["stale"]:
            return
        time.sleep(0.025)
    raise RuntimeError(f"{node} did not become ready through its own heartbeat")


def recover_owner(client, user, old_device, recovery_code):
    begin = client.post("/reenroll/begin", json={"user_id": user}).raise_for_status().json()
    public_key, private_key = generate_ed25519_keypair()
    result = client.post("/reenroll/complete", json={
        "enrollment_id": begin["enrollment_id"], "nonce": begin["nonce"],
        "label": "replacement-device", "new_public_key_b64": b64e(public_key),
        "pop_signature_b64": b64e(ed25519_sign(private_key, begin["nonce"].encode())),
        "old_device_ids": [old_device], "recovery_code": recovery_code,
    }).raise_for_status().json()
    if result["device_id"] == old_device:
        raise RuntimeError("Recovery did not enroll a new device")
    return _authenticate(client, result["device_id"], private_key)


def revocation_table(trial):
    lines = [
        "| Node | Authority revocation timestamp (UTC) | First confirmed denial (UTC) | Elapsed ms |",
        "| --- | --- | --- | ---: |",
    ]
    for node, row in trial["nodes"].items():
        lines.append(
            f"| {node} | {trial['revoked_at_utc']} | {row['first_denial_utc']} | {row['elapsed_ms']:.3f} |"
        )
    return "\n".join(lines)


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
        sessions = create_session_factory(engine)
        users = seed_database(sessions, seed=42)
        with tx_session(sessions) as session:
            session.add(Resource(resource_id="brief-beta", owner_user_id=users["bob"],
                                 kind="document", created_at=datetime.now(timezone.utc)))
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
        for node, client in clients.items():
            wait_for_sync(node, client)
        pool = stack.enter_context(concurrent.futures.ThreadPoolExecutor(max_workers=len(clients)))
        primary = clients["node-a"]
        headers = {"X-Admin-Enroll-Token": admin}
        _, operator = _enroll_and_authenticate(primary, users["carol"], "operator", headers)
        _, unaffected = _enroll_and_authenticate(primary, users["bob"], "unaffected-device", headers)
        results = []
        for i in range(runs):
            device, token = _enroll_and_authenticate(primary, users["alice"], f"trial-{i}", headers)
            for node, client in clients.items():
                baseline = _authorize(client, token)
                other_baseline = _authorize(client, unaffected, "brief-beta")
                if not baseline["allowed"] or not other_baseline["allowed"]:
                    raise RuntimeError(f"{node} baseline failed: {baseline['reason_code']}, "
                                       f"{other_baseline['reason_code']}")
            codes = primary.post("/reenroll/recovery-codes", headers={"Authorization": f"Bearer {token}"}).raise_for_status().json()["codes"]
            signal = concurrent.futures.Future()
            denials = {}
            probes = {
                node: pool.submit(
                    _probe_node, client, token, signal,
                    on_denial=lambda node=node: denials.__setitem__(node, datetime.now(timezone.utc)),
                )
                for node, client in clients.items()
            }
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
            with sessions() as session:
                record = session.get(Revocation, result["revocation_id"])
                revoked_at = record.committed_at
                if revoked_at.tzinfo is None:
                    revoked_at = revoked_at.replace(tzinfo=timezone.utc)
            replacement = recover_owner(primary, users["alice"], device, codes[0])
            rows = {}
            for node, client in clients.items():
                replacement_allowed = _authorize(client, replacement)["allowed"]
                unaffected_allowed = _authorize(client, unaffected, "brief-beta")["allowed"]
                old_denied = _authorize(client, token)["reason_code"] == "DEVICE_REVOKED"
                if not (replacement_allowed and unaffected_allowed and old_denied):
                    raise RuntimeError(f"{node} failed the recovery or unaffected-access check")
                denied_ms, sync, other = observed[node]
                rows[node] = {
                    "first_denial_utc": denials[node].isoformat(),
                    "elapsed_ms": round((denials[node] - revoked_at).total_seconds() * 1000, 3),
                    "request_to_denial_ms": round(denied_ms, 3),
                    "request_to_watermark_ms": round(sync, 3),
                    "other_denials": other,
                    "replacement_allowed": replacement_allowed,
                    "unaffected_allowed": unaffected_allowed,
                    "old_device_still_denied": old_denied,
                }
            results.append({
                "trial": i + 1,
                "revocation_id": result["revocation_id"],
                "commit_seq": result["commit_seq"],
                "revoked_at_utc": revoked_at.isoformat(),
                "request_ack_ms": round((acknowledged - started) / 1e6, 3),
                "last_denial_ms": max(row["elapsed_ms"] for row in rows.values()),
                "nodes": rows,
            })
        return results


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be positive")
    observations = measure(args.runs)
    if args.json:
        print(json.dumps(observations, indent=2))
    else:
        for trial in observations:
            print(revocation_table(trial))
            print(f"Last confirmed denial: {trial['last_denial_ms']:.3f} ms. "
                  "Replacement and unaffected credentials allowed on all three nodes.")
