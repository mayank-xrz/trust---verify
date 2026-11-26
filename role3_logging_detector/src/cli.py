"""CLI for Track 4 Role 3: verify-logs, detect, evaluate, and demo."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from .audit_logger import TamperEvidentLogger, verify_log_file
from .detector import SecurityDetector
from .metrics import evaluate_detector


def load_jsonl(path: str | Path) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def main() -> int:
    parser = argparse.ArgumentParser(description="Track 4 Role 3: Audit Logger & Explainable Detector")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_verify = sub.add_parser("verify-logs", help="Verify hash chain integrity of a .jsonl audit log")
    p_verify.add_argument("log_file", help="Path to audit .jsonl file")

    p_detect = sub.add_parser("detect", help="Run rule + graph detector on a .jsonl file")
    p_detect.add_argument("log_file", help="Path to events .jsonl file")
    p_detect.add_argument("--max-skew-sec", type=int, default=30)
    p_detect.add_argument("--xerj-url", default=None, help="Optional XERJ URL (e.g. http://127.0.0.1:9200)")

    p_eval = sub.add_parser("evaluate", help="Evaluate F1, MTTA, and FP/1k on labelled logs")
    p_eval.add_argument("labelled_file", help="Path to labelled .jsonl events")
    p_eval.add_argument("--max-skew-sec", type=int, default=30)

    p_demo = sub.add_parser("demo", help="Write hash-chained demo logs, verify, detect, and optionally push to XERJ")
    p_demo.add_argument("--out", default="demo_audit.jsonl")
    p_demo.add_argument("--xerj-url", default="http://127.0.0.1:9200")

    args = parser.parse_args()

    if args.cmd == "verify-logs":
        ok, count, msg = verify_log_file(args.log_file)
        print(msg)
        return 0 if ok else 1

    if args.cmd == "detect":
        events = load_jsonl(args.log_file)
        alerts = SecurityDetector(max_skew_seconds=args.max_skew_sec, xerj_url=args.xerj_url).analyze(events)
        print(json.dumps(alerts, indent=2))
        return 0

    if args.cmd == "evaluate":
        events = load_jsonl(args.labelled_file)
        alerts = SecurityDetector(max_skew_seconds=args.max_skew_sec).analyze(events)
        metrics = evaluate_detector(events, alerts)
        print(json.dumps({"metrics": metrics, "alerts": alerts}, indent=2))
        return 0

    if args.cmd == "demo":
        out_path = Path(args.out)
        if out_path.exists():
            out_path.unlink()
        logger = TamperEvidentLogger(out_path, xerj_url=args.xerj_url)
        logger.log_event("alice", "auth-gateway", "login", target="session-1", event_time="2026-11-26T10:00:00Z")
        logger.log_event(
            "admin-bob", "auth-gateway", "role_change", target="carol",
            privilege_before="user", privilege_after="admin",
            event_time="2026-11-26T10:01:00Z",
            metadata={"ticket_id": "CHG-104", "mfa_verified": "true"},
        )
        logger.log_event(
            "eve", "auth-gateway", "role_change", target="eve",
            privilege_before="user", privilege_after="admin",
            event_time="2026-11-26T10:02:00Z",
            metadata={"note": "normal\n{\"actor_id\":\"admin\"}"},
        )
        logger.log_event("eve", "msg-relay", "read", target="inbox", event_time="2026-11-26T10:02:20Z")
        logger.log_event("eve", "backup-store", "bulk_export", target="keys.bak", event_time="2026-11-26T10:02:40Z")

        ok, _, msg = verify_log_file(out_path)
        events = load_jsonl(out_path)
        alerts = SecurityDetector(xerj_url=args.xerj_url).analyze(events)
        print(msg)
        print(json.dumps({"alerts_generated": len(alerts), "alerts": alerts}, indent=2))
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
