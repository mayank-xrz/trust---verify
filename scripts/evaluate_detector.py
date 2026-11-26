"""Evaluate the shipped detector rules against the labelled Track 4 fixture."""

from __future__ import annotations

import json
import time
from pathlib import Path

from src.detector.graph_lateral import LateralMovementGraph
from src.detector.metrics import compute_f1_mtta
from src.detector.rules import ContextRuleEngine

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/track4_detector.jsonl"


def evaluate():
    rules = ContextRuleEngine()
    graph = LateralMovementGraph()
    evaluations = []
    latencies = []
    for line in FIXTURE.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        # Convert the source timestamp into the shared clock domain.
        event["timestamp_ns"] -= event["clock_offset_ms"] * 1_000_000
        started = time.perf_counter_ns()
        alerts = rules.evaluate_event(event)
        edge = event.get("edge")
        violation = graph.check_call(
            *edge, event["action"], event["subject"], event["timestamp_ns"] / 1e9
        ) if edge else None
        detected = bool(violation) or any(alert.severity != "LOW" for alert in alerts)
        expected = event["expected_suspicious"]
        if detected and expected:
            latencies.append((time.perf_counter_ns() - started) / 1e6)
        evaluations.append({"is_attack": expected, "detected": detected})

    return compute_f1_mtta(evaluations, latencies)


if __name__ == "__main__":
    print(json.dumps(evaluate().to_dict(), indent=2))
