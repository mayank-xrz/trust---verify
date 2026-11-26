"""Evaluate unchanged Track 4 rules against labelled synthetic or external events."""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from src.detector.graph_lateral import LateralMovementGraph
from src.detector.metrics import compute_f1_mtta
from src.detector.rules import ContextRuleEngine

FIXTURE = Path(__file__).resolve().parents[1] / "tests/fixtures/track4_detector.jsonl"


CHALLENGE = FIXTURE.with_name("track4_detector_challenge.jsonl")


def evaluate_both(dataset: Path = FIXTURE):
    rules = ContextRuleEngine()
    graph = LateralMovementGraph()
    modes = ("all_severities", "non_low")
    evaluations = {mode: [] for mode in modes}
    latencies = {mode: [] for mode in modes}
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
        duration_ms = (time.perf_counter_ns() - started) / 1e6
        expected = event["expected_suspicious"]
        detections = {
            "all_severities": bool(violation or alerts),
            "non_low": bool(violation) or any(alert.severity != "LOW" for alert in alerts),
        }
        for mode, detected in detections.items():
            if detected and expected:
                latencies[mode].append(duration_ms)
            evaluations[mode].append({"is_attack": expected, "detected": detected})

    if {row["is_attack"] for row in evaluations["all_severities"]} != {False, True}:
        raise ValueError("Dataset must contain both benign and suspicious labels")
    return {mode: compute_f1_mtta(evaluations[mode], latencies[mode]) for mode in modes}


def evaluate(dataset: Path = FIXTURE):
    """Return the original non-LOW regression metric for existing callers."""
    return evaluate_both(dataset)["non_low"]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, help="Score one dataset instead of the shipped pair")
    args = parser.parse_args()
    datasets = {"input": args.dataset} if args.dataset else {"regression": FIXTURE, "challenge": CHALLENGE}
    scores = {name: {mode: metrics.to_dict() for mode, metrics in evaluate_both(path).items()}
              for name, path in datasets.items()}
    print(json.dumps(scores, indent=2))
