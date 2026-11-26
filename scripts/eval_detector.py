"""Detector evaluation: confusion matrix on the synthetic labelled dataset.

The dataset is **synthetic**. It is a deterministic, hand-labelled set of
routine and attack events used to exercise the rule engine; it is not a
real-world corpus and must not be presented as one.

Usage:
    python scripts/eval_detector.py
    python scripts/eval_detector.py --json reports/detector_eval.json
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.detector.rules import ContextRuleEngine  # noqa: E402

BASE_TIME = 1_700_000_000.0


def _routine_event(i: int) -> dict[str, Any]:
    return {
        "event_id": f"evt-normal-{i}",
        "timestamp_ns": int((BASE_TIME + i * 2.0) * 1_000_000_000),
        "subject": f"user-{i % 25}",
        "service": "api-gateway",
        "resource": f"/items/{i}",
        "action": "GET_ITEM",
        "status": "SUCCESS",
        "metadata": {"role": "user"},
    }


def _attack_event(i: int) -> dict[str, Any]:
    is_admin_attempt = i % 2 == 0
    return {
        "event_id": f"evt-attack-{i}",
        "timestamp_ns": int((BASE_TIME + 500.0 + i) * 1_000_000_000),
        "subject": f"attacker-{i}",
        "service": "api-gateway",
        "resource": "/admin/keys/rotate" if is_admin_attempt else "/api/v1/message",
        "action": "ROTATE_KEY" if is_admin_attempt else "REPLAY_BLOCKED",
        "status": "DENIED",
        "metadata": {"role": "guest", "error": "Replay detected: duplicate message"},
    }


def run_evaluation() -> dict[str, Any]:
    """Return a confusion matrix and derived metrics for the synthetic set."""
    engine = ContextRuleEngine(burst_threshold=20)
    tp = fp = tn = fn = 0
    latencies_ms: list[float] = []

    for i in range(100):
        t0 = time.perf_counter()
        alerts = engine.evaluate_event(_routine_event(i))
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        if alerts:
            fp += 1
        else:
            tn += 1

    for i in range(25):
        t0 = time.perf_counter()
        alerts = engine.evaluate_event(_attack_event(i))
        latencies_ms.append((time.perf_counter() - t0) * 1000.0)
        if alerts:
            tp += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    fp_per_1k = (fp / total * 1000.0) if total else 0.0

    return {
        "dataset": "synthetic",
        "dataset_note": (
            "Deterministic hand-labelled synthetic events (100 routine, 25 attack). "
            "Not a real-world corpus."
        ),
        "events": total,
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "false_positives_per_1k": round(fp_per_1k, 4),
        "mtta_ms": round(sum(latencies_ms) / len(latencies_ms), 4) if latencies_ms else 0.0,
    }


def _print_matrix(result: dict[str, Any]) -> None:
    cm = result["confusion_matrix"]
    print("Detector evaluation — SYNTHETIC data (not real-world)")
    print(f"  events: {result['events']}  (100 routine / 25 attack)")
    print("  Confusion matrix (rows = truth, cols = predicted):")
    print("                 predicted alert   predicted normal")
    print(f"  actual attack       {cm['tp']:>5}              {cm['fn']:>5}")
    print(f"  actual normal       {cm['fp']:>5}              {cm['tn']:>5}")
    print(
        f"  precision={result['precision']:.4f} recall={result['recall']:.4f} "
        f"f1={result['f1']:.4f} fp/1k={result['false_positives_per_1k']:.4f}"
    )
    print("  WARNING: synthetic labels; do not cite as production accuracy.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate the detector on synthetic data.")
    parser.add_argument("--json", default=None, help="optional output JSON path")
    args = parser.parse_args()

    result = run_evaluation()
    _print_matrix(result)
    print(json.dumps(result, indent=2, sort_keys=True))
    if args.json:
        out = Path(args.json)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
