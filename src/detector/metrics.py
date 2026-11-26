"""Detection Engine Evaluation Metrics: F1, MTTA, and False Positives per 1k Events."""

from __future__ import annotations

import dataclasses
from statistics import median
from typing import Any, Dict, List


@dataclasses.dataclass
class DetectionBenchmarkMetrics:
    total_events: int
    true_positives: int
    false_positives: int
    false_negatives: int
    true_negatives: int
    precision: float
    recall: float
    f1_score: float
    mtta_ms: float  # Mean Time To Alert in milliseconds
    false_alerts_per_1k: float
    median_time_to_alert_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


def compute_f1_mtta(
    evaluations: List[Dict[str, Any]],
    alert_latencies_ms: List[float],
) -> DetectionBenchmarkMetrics:
    """Computes precision, recall, F1 score, MTTA, and FP/1,000 events.

    Each item in evaluations has:
    - 'is_attack': bool (ground truth)
    - 'detected': bool (detector output)
    """
    tp = sum(1 for e in evaluations if e["is_attack"] and e["detected"])
    fp = sum(1 for e in evaluations if not e["is_attack"] and e["detected"])
    fn = sum(1 for e in evaluations if e["is_attack"] and not e["detected"])
    tn = sum(1 for e in evaluations if not e["is_attack"] and not e["detected"])

    total = len(evaluations)
    precision = (tp / (tp + fp)) if (tp + fp) > 0 else 1.0
    recall = (tp / (tp + fn)) if (tp + fn) > 0 else 1.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    mtta = (sum(alert_latencies_ms) / len(alert_latencies_ms)) if alert_latencies_ms else 0.0
    benign = fp + tn
    fp_per_1k = (fp / benign * 1000.0) if benign else 0.0

    return DetectionBenchmarkMetrics(
        total_events=total,
        true_positives=tp,
        false_positives=fp,
        false_negatives=fn,
        true_negatives=tn,
        precision=round(precision, 4),
        recall=round(recall, 4),
        f1_score=round(f1, 4),
        mtta_ms=round(mtta, 2),
        false_alerts_per_1k=round(fp_per_1k, 4),
        median_time_to_alert_ms=round(median(alert_latencies_ms), 4) if alert_latencies_ms else 0.0,
    )
