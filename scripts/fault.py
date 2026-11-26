"""Fault-injection helper to stop/start a node or block its DB connection."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
from pathlib import Path

PID_DIR = Path("/tmp/tbv_pids")


def stop_node(node: str, mode: str) -> None:
    if mode == "docker":
        subprocess.run(["docker", "stop", f"tbv-{node}"], check=True)
    else:
        pid_file = PID_DIR / f"{node}.pid"
        if pid_file.exists():
            pid = int(pid_file.read_text(encoding="utf-8").strip())
            os.kill(pid, signal.SIGTERM)
            pid_file.unlink(missing_ok=True)


def start_node(node: str, mode: str) -> None:
    if mode == "docker":
        subprocess.run(["docker", "start", f"tbv-{node}"], check=True)
    else:
        from scripts.local_secrets import ensure_local_secrets

        ports = {"node-a": "8101", "node-b": "8102", "node-c": "8103"}
        port = ports[node]
        env = os.environ.copy()
        # Reuse the persisted local secrets so the restarted node can verify
        # tokens issued by its peers.
        env.update(ensure_local_secrets())
        env["NODE_ID"] = node
        env["NODE_PORT"] = port
        PID_DIR.mkdir(parents=True, exist_ok=True)
        proc = subprocess.Popen(
            ["uvicorn", "src.identity_keys.api:app", "--host", "127.0.0.1", "--port", port],
            env=env,
        )
        (PID_DIR / f"{node}.pid").write_text(str(proc.pid), encoding="utf-8")


def block_db(node: str, mode: str) -> None:
    if mode == "docker":
        subprocess.run(
            ["docker", "network", "disconnect", "tbv-sandbox-net", f"tbv-{node}"], check=True
        )
    else:
        raise RuntimeError(
            "Local DB block: point DATABASE_URL to an unreachable host"
        )


def unblock_db(node: str, mode: str) -> None:
    if mode == "docker":
        subprocess.run(
            ["docker", "network", "connect", "tbv-sandbox-net", f"tbv-{node}"], check=True
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Inject faults on sandbox nodes.")
    parser.add_argument("action", choices=["stop", "start", "block-db", "unblock-db"])
    parser.add_argument("node", choices=["node-a", "node-b", "node-c"])
    parser.add_argument("--mode", choices=["docker", "local"], default="docker")
    args = parser.parse_args()

    if args.action == "stop":
        stop_node(args.node, args.mode)
    elif args.action == "start":
        start_node(args.node, args.mode)
    elif args.action == "block-db":
        block_db(args.node, args.mode)
    elif args.action == "unblock-db":
        unblock_db(args.node, args.mode)


if __name__ == "__main__":
    main()
