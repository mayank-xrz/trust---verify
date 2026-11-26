"""
Injection-proof, tamper-evident hash-chained logger and verifier.
Optionally streams each verified log record to a local XERJ node for fast search.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")


def sanitize_text(value: Any) -> str:
    """Strip control characters (including CR/LF) so user text cannot forge a new JSONL line."""
    text = str(value)
    return CONTROL_CHARS_RE.sub(" ", text).strip()


def canonical_json(data: Dict[str, Any]) -> str:
    """Deterministic JSON serialization for hashing."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_entry_hash(record_without_hash: Dict[str, Any]) -> str:
    """Compute SHA-256 hex digest of a canonical log record."""
    return hashlib.sha256(canonical_json(record_without_hash).encode("utf-8")).hexdigest()


def post_to_xerj(xerj_url: str, index_name: str, doc_id: str, doc: Dict[str, Any]) -> bool:
    """Best-effort index of a log or alert document into XERJ (http://127.0.0.1:9200)."""
    url = f"{xerj_url.rstrip('/')}/{index_name}/_doc/{doc_id}"
    req = urllib.request.Request(
        url,
        data=json.dumps(doc).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            return 200 <= resp.status < 300
    except (urllib.error.URLError, TimeoutError, ValueError):
        return False


class TamperEvidentLogger:
    """Append-only JSONL logger where every line links to the previous line via SHA-256."""

    GENESIS_HASH = "0" * 64

    def __init__(self, log_path: str | Path, xerj_url: Optional[str] = None, xerj_index: str = "track4-audit"):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.xerj_url = xerj_url
        self.xerj_index = xerj_index
        self.seq, self.prev_hash = self._load_tail_state()

    def _load_tail_state(self) -> Tuple[int, str]:
        if not self.log_path.exists() or self.log_path.stat().st_size == 0:
            return 0, self.GENESIS_HASH
        last_line = ""
        with self.log_path.open("r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    last_line = line
        if not last_line:
            return 0, self.GENESIS_HASH
        last_record = json.loads(last_line)
        return int(last_record["seq"]), str(last_record["entry_hash"])

    def log_event(
        self,
        actor_id: str,
        service: str,
        action: str,
        target: str = "",
        status: str = "allow",
        privilege_before: str = "user",
        privilege_after: str = "user",
        event_time: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Sanitize inputs, chain hash to previous record, append to JSONL, and optionally index in XERJ."""
        self.seq += 1
        ts = event_time or datetime.now(timezone.utc).isoformat()
        clean_meta = {sanitize_text(k): sanitize_text(v) for k, v in (metadata or {}).items()}

        record: Dict[str, Any] = {
            "seq": self.seq,
            "event_id": f"evt-{self.seq:06d}",
            "event_time": sanitize_text(ts),
            "actor_id": sanitize_text(actor_id),
            "service": sanitize_text(service),
            "action": sanitize_text(action),
            "target": sanitize_text(target),
            "status": sanitize_text(status),
            "privilege_before": sanitize_text(privilege_before),
            "privilege_after": sanitize_text(privilege_after),
            "metadata": clean_meta,
            "prev_hash": self.prev_hash,
        }
        record["entry_hash"] = compute_entry_hash(record)

        with self.log_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n")
            f.flush()
            os.fsync(f.fileno())

        self.prev_hash = record["entry_hash"]

        if self.xerj_url:
            post_to_xerj(self.xerj_url, self.xerj_index, record["event_id"], record)

        return record


def verify_log_file(log_path: str | Path) -> Tuple[bool, int, str]:
    """
    Verify sequence continuity, prev_hash links, and SHA-256 entry_hash for every line.
    Returns (is_valid, verified_count, message).
    """
    path = Path(log_path)
    if not path.exists():
        return False, 0, f"Log file not found: {path}"

    expected_seq = 1
    expected_prev = TamperEvidentLogger.GENESIS_HASH
    count = 0

    with path.open("r", encoding="utf-8") as f:
        for line_no, raw_line in enumerate(f, start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                return False, count, f"Invalid JSON at line {line_no}: {exc}"

            if record.get("seq") != expected_seq:
                return False, count, f"Sequence break at line {line_no}: expected seq {expected_seq}, got {record.get('seq')}"
            if record.get("prev_hash") != expected_prev:
                return False, count, f"Broken hash chain at line {line_no} (seq {expected_seq})"

            claimed_hash = record.get("entry_hash")
            body = {k: v for k, v in record.items() if k != "entry_hash"}
            actual_hash = compute_entry_hash(body)
            if claimed_hash != actual_hash:
                return False, count, f"Tampered record at line {line_no} (seq {expected_seq}): hash mismatch"

            expected_seq += 1
            expected_prev = actual_hash
            count += 1

    return True, count, f"OK: verified {count} log entries with intact hash chain."
