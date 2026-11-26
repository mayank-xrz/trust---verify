"""Generate a second deterministic, synthetic detector fixture from scenario labels."""

import json
import random
from pathlib import Path

OUTPUT = Path(__file__).resolve().parents[1] / "tests/fixtures/track4_detector_challenge.jsonl"


def generate():
    rng = random.Random(27183)
    start = 1_732_300_000_000_000_000
    services = ("portal-north", "analytics-worker", "invoice-api", "document-index")
    offsets = (-2400, -730, -125, 0, 310, 1100, 2900)
    benign_actions = ("LIST_REPORTS", "READ_INVOICE", "GET_PROFILE", "UPDATE_DRAFT", "READ_PUBLIC_DATA")
    events = []

    def add(suspicious, identity, action, status, *, metadata=None, edge=None, elapsed_ms=None):
        index = len(events)
        offset = rng.choice(offsets)
        if elapsed_ms is None:
            elapsed_ms = index * 12_000 + rng.randrange(700)
        events.append({
            "event_id": f"challenge-{index + 1:04d}",
            "timestamp_ns": start + (elapsed_ms + offset) * 1_000_000,
            "clock_offset_ms": offset,
            "expected_suspicious": suspicious,
            "subject": identity,
            "service": rng.choice(services),
            "resource": "/workbench",
            "action": action,
            "status": status,
            "metadata": metadata or {},
            **({"edge": edge} if edge else {}),
        })

    for index in range(1040):
        identity = f"tenant-{index % 7}-operator-{index % 61}"
        if index % 103 == 0:
            add(False, identity, "RECEIVE", "DENIED", metadata={
                "authenticated_sender": True, "recipient_key_state": "expired",
                "seconds_since_cutoff": 0.35, "error": "Recipient key is expired",
            })
        elif index % 43 == 0:
            add(False, identity, "ROTATE_KEY", "SUCCESS", metadata={"role": "admin"})
        else:
            add(False, identity, rng.choice(benign_actions), rng.choice(("SUCCESS", "SUCCESS", "DENIED")))

    for group in range(6):
        add(True, f"operator-temp-{group}", "REVOKE_KEY", "DENIED", metadata={"role": "viewer"})
        add(True, f"relay-temp-{group}", "REQUEST_DUPLICATE", "DENIED", metadata={"error": "Duplicate message"})
        add(True, f"outbound-relay-{group}", "DELIVER", "DENIED", metadata={"error": "Signature invalid"})
        add(True, f"svc-analytics-{group}", "READ_INVOICE", "SUCCESS", edge=["audit-service", "invoice-api"])
        # The label describes the synthetic scenario even if the rule does not detect it.
        add(True, f"report-exporter-{group}", "DOWNLOAD_REPORT_ARCHIVE", "SUCCESS")
        add(True, f"forwarder-{group}", "DELIVER", "DENIED", metadata={"error": "Authenticated recipient mismatch"})

    # Swap neighboring arrivals without changing their source timestamps or labels.
    for index in range(11, len(events) - 1, 29):
        events[index], events[index + 1] = events[index + 1], events[index]
    return events


if __name__ == "__main__":
    OUTPUT.write_text("".join(json.dumps(row, separators=(",", ":")) + "\n" for row in generate()), encoding="utf-8")
