"""Crypto event facade over the existing canonical SHA-256 audit chain."""
from datetime import datetime, timezone
import json
from pathlib import Path

from src.audit.logger import AuditLogger
from src.audit.verifier import AuditLogVerifier
from .primitives import CryptoError


class CryptoEvents:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.exists() and not AuditLogVerifier().verify_file(str(self.path)).is_valid:
            raise CryptoError("audit chain verification failed")
        self.logger = AuditLogger("track4-crypto", str(self.path))

    def emit(self, action, outcome, *, actor="", source_service="", target_service="",
             session_id="", message_id="", reason=""):
        # The legacy audit schema places objective-specific fields in metadata. Its
        # canonical body and hash-chain verifier are intentionally unchanged.
        timestamp = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        metadata = {"timestamp": timestamp, "actor": actor, "source_service": source_service,
                    "target_service": target_service, "outcome": outcome, "session_id": session_id,
                    "message_id": message_id, "reason": reason}
        record = self.logger.log_event("track4-crypto", action, actor, session_id, outcome, metadata)
        return {"event_id": record.event_id, **metadata, "action": action, "log_hash": record.entry_hash}

    def verify(self):
        return AuditLogVerifier().verify_file(str(self.path)).is_valid

    def read_events(self):
        """Expose toolkit-facing fields without changing the chained record format."""
        if not self.verify():
            raise CryptoError("audit chain verification failed")
        result = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if not line or line.startswith("#"):
                continue
            record = json.loads(line)
            result.append({"event_id": record["event_id"], "action": record["action"],
                           "log_hash": record["entry_hash"], **record["metadata"]})
        return result
