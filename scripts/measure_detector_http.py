"""Measure local HTTP request-to-alert latency for the shipped synthetic demo event."""

from __future__ import annotations

import json
import os
import secrets
import tempfile
import time
from contextlib import ExitStack
from pathlib import Path
from statistics import median

from scripts.measure_live_revocation import start_node


def main():
    samples = []
    # Restart between batches so the measurement isolates the same rule.
    for _ in range(7):
        with ExitStack() as stack:
            directory = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="track4-detector-")))
            operator_token = secrets.token_urlsafe(32)
            client = start_node(
                stack, directory, "node-a", {**os.environ, "DATA_DIR": str(directory), "DEMO_SANDBOX_ENABLED": "1", "DEMO_OPERATOR_TOKEN": operator_token},
                app="demo.node.server:app", health="/health",
            )
            for _ in range(3):
                started = time.perf_counter_ns()
                payload = client.post("/api/sandbox/detector/privilege-escalation", headers={"Authorization": f"Bearer {operator_token}"}).raise_for_status().json()
                alert = payload.get("latest_alert") or {}
                if not payload.get("blocked") or alert.get("rule_name") != "UNAUTHORIZED_PRIVILEGE_ELEVATION":
                    raise RuntimeError("HTTP response did not contain the expected detector alert")
                samples.append((time.perf_counter_ns() - started) / 1e6)
    print(json.dumps({
        "samples_ms": [round(sample, 4) for sample in samples],
        "median_ms": round(median(samples), 4),
    }, indent=2))


if __name__ == "__main__":
    main()
