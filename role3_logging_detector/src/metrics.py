"""
Evaluation metrics required by Track 4:
- Precision, Recall, F1
- Median Time to Alert (MTTA) in seconds
- False alerts per 1,000 benign events (FP/1k)
"""

from __future__ import annotations

import statistics
from typing import Any, Dict, List

from .detector import parse_iso_utc


def evaluate_detector(events: List[Dict[str, Any]], alerts: List[Dict[str, Any]]) -> Dict[str, float]:
    """Compare generated alerts against ground-truth `label` ('benign' or 'malicious') on events."""
    event_by_id = {ev["event_id"]: ev for ev in events}
    malicious_ids = {ev["event_id"] for ev in events if ev.get("label") == "malicious"}
    benign_count = sum(1 for ev in events if ev.get("label", "benign") == "benign")

    flagged_ids = set()
    detection_latencies_sec: List[float] = []

    for alert in alerts:
        alert_dt = parse_iso_utc(alert["detected_at"])
        for eid in alert.get("event_ids", []):
            flagged_ids.add(eid)
            if eid in malicious_ids:
                ev_dt = parse_iso_utc(event_by_id[eid]["event_time"])
                detection_latencies_sec.append(max(0.0, (alert_dt - ev_dt).total_seconds()))

    tp = len(flagged_ids & malicious_ids)
    fp = len(flagged_ids - malicious_ids)
    fn = len(malicious_ids - flagged_ids)

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    mtta = statistics.median(detection_latencies_sec) if detection_latencies_sec else 0.0
    fp_per_1k = (fp / benign_count * 1000.0) if benign_count > 0 else 0.0

    return {
        "tp": float(tp),
        "fp": float(fp),
        "fn": float(fn),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "median_time_to_alert_sec": round(mtta, 4),
        "false_alerts_per_1000_benign": round(fp_per_1k, 4),
    }
