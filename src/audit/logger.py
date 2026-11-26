"""Tamper-Evident Structured JSON Audit Logger with Cryptographic Hash Chain.

Features:
- Strict protection against newline injection, carriage return, and JSON escape smuggling.
- Cryptographic hash chaining: H_i = SHA-256(H_{i-1} || canonical_json(entry_i)).
- Optional ML-DSA digital signatures on checkpoint records.
- Thread-safe append-only storage.
"""

from __future__ import annotations
import base64
import hashlib
import json
import os
import re
import threading
import time
import uuid
from typing import Dict, Any, Optional

GENESIS_HASH = "0" * 64


class AuditRecord:
    def __init__(
        self,
        sequence: int,
        event_id: str,
        timestamp_ns: int,
        node_id: str,
        service: str,
        action: str,
        subject: str,
        resource: str,
        status: str,
        metadata: Dict[str, Any],
        prev_hash: str,
        entry_hash: str,
        signature: str = "",
        client_ip: str = "",
    ):
        self.sequence = sequence
        self.event_id = event_id
        self.timestamp_ns = timestamp_ns
        self.node_id = node_id
        self.service = service
        self.action = action
        self.subject = subject
        self.resource = resource
        self.status = status
        self.metadata = metadata
        self.client_ip = client_ip
        self.prev_hash = prev_hash
        self.entry_hash = entry_hash
        self.signature = signature

    def to_dict(self) -> Dict[str, Any]:
        data = {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp_ns": self.timestamp_ns,
            "node_id": self.node_id,
            "service": self.service,
            "action": self.action,
            "subject": self.subject,
            "resource": self.resource,
            "status": self.status,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "entry_hash": self.entry_hash,
        }
        if self.client_ip:
            data["client_ip"] = self.client_ip
        if self.signature:
            data["signature"] = self.signature
        return data


class AuditLogger:
    """Injection-safe, tamper-evident hash-chained logger."""

    def __init__(
        self,
        node_id: str,
        log_file_path: str,
        signer: Optional[Any] = None,
        checkpoint_interval: int = 10,
    ):
        self.node_id = node_id
        self.log_file_path = log_file_path
        self.signer = signer
        self.checkpoint_interval = checkpoint_interval
        self._lock = threading.Lock()
        self._current_sequence = 0
        self._last_hash = GENESIS_HASH

        self._init_or_resume_log()

    def _init_or_resume_log(self) -> None:
        """Initializes new log or resumes state from existing valid log file."""
        os.makedirs(os.path.dirname(os.path.abspath(self.log_file_path)), exist_ok=True)
        if not os.path.exists(self.log_file_path):
            with open(self.log_file_path, "w", encoding="utf-8") as f:
                f.write("# TBV AUDIT LOG V1\n")
            return

        # Resume last hash and sequence from existing log
        with open(self.log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    record = json.loads(line)
                    self._current_sequence = record.get("sequence", 0) + 1
                    self._last_hash = record.get("entry_hash", GENESIS_HASH)
                except Exception:
                    pass

    @staticmethod
    def sanitize_field(value: Any) -> Any:
        """Sanitizes strings against newline injection, null bytes, and control characters."""
        if isinstance(value, str):
            # Strip control characters, newlines, and carriage returns
            clean = re.sub(r"[\r\n\x00-\x1f\x7f-\x9f]", " ", value)
            return clean.strip()
        elif isinstance(value, dict):
            return {AuditLogger.sanitize_field(k): AuditLogger.sanitize_field(v) for k, v in value.items()}
        elif isinstance(value, list):
            return [AuditLogger.sanitize_field(v) for v in value]
        return value

    @staticmethod
    def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
        """Generates deterministic canonical JSON representation for hashing."""
        return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")

    def log_event(
        self,
        service: str,
        action: str,
        subject: str,
        resource: str,
        status: str = "SUCCESS",
        metadata: Optional[Dict[str, Any]] = None,
        client_ip: str = "",
    ) -> AuditRecord:
        """Creates a tamper-evident audit entry, updates the hash chain, and flushes to disk."""
        with self._lock:
            seq = self._current_sequence
            event_id = str(uuid.uuid4())
            ts_ns = time.time_ns()

            clean_meta = self.sanitize_field(metadata or {})
            clean_service = self.sanitize_field(service)
            clean_action = self.sanitize_field(action)
            clean_subject = self.sanitize_field(subject)
            clean_resource = self.sanitize_field(resource)
            clean_status = self.sanitize_field(status)
            clean_ip = self.sanitize_field(client_ip)

            # Build canonical body without hash and signature
            body = {
                "sequence": seq,
                "event_id": event_id,
                "timestamp_ns": ts_ns,
                "node_id": self.node_id,
                "service": clean_service,
                "action": clean_action,
                "subject": clean_subject,
                "resource": clean_resource,
                "status": clean_status,
                "metadata": clean_meta,
                "prev_hash": self._last_hash,
            }
            if clean_ip:
                body["client_ip"] = clean_ip

            canonical_bytes = self.canonical_json_bytes(body)
            # H_i = SHA256(prev_hash || canonical_json)
            entry_hash = hashlib.sha256(self._last_hash.encode("ascii") + canonical_bytes).hexdigest()

            # Sign checkpoint if configured
            sig_b64 = ""
            if self.signer and (seq % self.checkpoint_interval == 0):
                sig_bytes = self.signer.sign(entry_hash.encode("ascii"))
                sig_b64 = base64.b64encode(sig_bytes).decode("ascii")

            record = AuditRecord(
                sequence=seq,
                event_id=event_id,
                timestamp_ns=ts_ns,
                node_id=self.node_id,
                service=clean_service,
                action=clean_action,
                subject=clean_subject,
                resource=clean_resource,
                status=clean_status,
                metadata=clean_meta,
                prev_hash=self._last_hash,
                entry_hash=entry_hash,
                signature=sig_b64,
                client_ip=clean_ip,
            )

            # Write single-line atomic JSON entry to file
            log_line = json.dumps(record.to_dict(), separators=(",", ":")) + "\n"
            with open(self.log_file_path, "a", encoding="utf-8") as f:
                f.write(log_line)
                f.flush()
                os.fsync(f.fileno())

            self._last_hash = entry_hash
            self._current_sequence += 1

            return record
