"""Evaluate the shipped detector rules against the labelled Track 4 fixture."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from src.detector.graph_lateral import LateralMovementGraph
from src.detector.metrics import compute_f1_mtta
from src.detector.rules import ContextRuleEngine

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/track4_detector.jsonl"


def evaluate(dataset: Path = FIXTURE):
    rules = ContextRuleEngine()
    graph = LateralMovementGraph()
    evaluations = []
    latencies = []
    for line in dataset.read_text(encoding="utf-8").splitlines():
        event = json.loads(line)
        if type(event.get("expected_suspicious")) is not bool:
            raise ValueError("Each row needs a boolean expected_suspicious label")
        # Convert the source timestamp into the shared clock domain.
        event["timestamp_ns"] -= event.get("clock_offset_ms", 0) * 1_000_000
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

    if {row["is_attack"] for row in evaluations} != {False, True}:
        raise ValueError("Dataset must contain both benign and suspicious labels")
    return compute_f1_mtta(evaluations, latencies)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=FIXTURE)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset).to_dict(), indent=2))
