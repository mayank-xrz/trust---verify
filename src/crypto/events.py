"""Audit event helper for Track 4 crypto operations.

All events are emitted through the existing SHA-256 hash-chained AuditLogger
(`src.audit.logger.AuditLogger`) so canonicalization, control-character
sanitization, and hash-chain verification remain intact.
Never logs plaintext, session keys, ephemeral private keys, or shared secrets.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from src.audit.logger import AuditLogger


def utc_iso_ms() -> str:
    """Return current UTC timestamp in ISO-8601 format with milliseconds."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def emit_crypto_event(
    audit_logger: Optional[AuditLogger],
    *,
    actor: str,
    source_service: str,
    target_service: str,
    action: str,
    outcome: str,
    session_id: str = "",
    message_id: str = "",
    reason: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Emit a structured crypto event through AuditLogger if configured.

    Returns a dictionary containing the emitted event fields (including `log_hash`)
    for immediate inspection by callers and tests.
    """
    if audit_logger is None:
        return None

    ts = utc_iso_ms()
    status_map = {
        "allow": "SUCCESS",
        "accepted": "SUCCESS",
        "success": "SUCCESS",
        "deny": "DENIED",
        "rejected": "DENIED",
        "failed": "ERROR",
        "error": "ERROR",
    }
    log_status = status_map.get(outcome.lower(), "DENIED")

    meta: Dict[str, Any] = {
        "timestamp": ts,
        "actor": actor,
        "source_service": source_service,
        "target_service": target_service,
        "outcome": outcome,
        "session_id": session_id,
        "message_id": message_id,
        "reason": reason,
    }
    if extra:
        for k, v in extra.items():
            meta[k] = v

    record = audit_logger.log_event(
        service=source_service,
        action=action,
        subject=actor,
        resource=target_service,
        status=log_status,
        metadata=meta,
    )
    return {
        "event_id": record.event_id,
        "timestamp": ts,
        "actor": record.subject,
        "source_service": source_service,
        "target_service": target_service,
        "action": record.action,
        "outcome": outcome,
        "session_id": session_id,
        "message_id": message_id,
        "reason": reason,
        "log_hash": record.entry_hash,
    }
