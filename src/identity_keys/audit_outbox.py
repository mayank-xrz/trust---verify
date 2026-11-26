"""Transactional Audit Outbox emitter and dispatcher compatible with src/audit/logger.py."""

from __future__ import annotations

import os
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from src.audit.logger import AuditLogger

from .clock import Clock
from .db import tx_session
from .models import AuditOutbox


class AuditEmitter:
    """Writes structured audit events into audit_outbox inside the caller's DB transaction."""

    def __init__(self, node_id: str, clock: Clock) -> None:
        self.node_id = node_id
        self.clock = clock

    def emit(
        self,
        session: Session,
        *,
        actor_id: str,
        device_id: str | None,
        action: str,
        target: str,
        outcome: str,
        reason_code: str,
        correlation_id: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Stage an audit event in audit_outbox within the active transaction."""
        event_id = str(uuid.uuid4())
        now = self.clock.now()
        # Sanitize all string fields using AuditLogger.sanitize_field so record boundaries
        # cannot be forged by user-supplied newlines or control characters.
        payload = {
            "event_id": event_id,
            "actor_id": AuditLogger.sanitize_field(actor_id),
            "device_id": AuditLogger.sanitize_field(device_id) if device_id else None,
            "node_id": AuditLogger.sanitize_field(self.node_id),
            "action": AuditLogger.sanitize_field(action),
            "target": AuditLogger.sanitize_field(target),
            "timestamp": now.isoformat(),
            "timestamp_ns": int(now.timestamp() * 1_000_000_000),
            "correlation_id": AuditLogger.sanitize_field(correlation_id or str(uuid.uuid4())),
            "outcome": AuditLogger.sanitize_field(outcome),
            "reason_code": AuditLogger.sanitize_field(reason_code),
            "metadata": AuditLogger.sanitize_field(metadata or {}),
        }
        session.add(AuditOutbox(event_id=event_id, payload=payload, created_at=now))
        return event_id


class AuditDispatcher:
    """Delivers pending audit_outbox events to Person C's hash-chained AuditLogger."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        node_id: str,
        log_file_path: str | None = None,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.node_id = node_id
        path = (
            log_file_path
            or os.environ.get("AUDIT_LOG_PATH")
            or f"/tmp/tbv_data/{node_id}_audit.log"
        )
        self.logger = AuditLogger(node_id=node_id, log_file_path=path)

    def dispatch_pending(self, limit: int = 100) -> int:
        """Deliver undelivered outbox rows to AuditLogger and mark delivered_at."""
        delivered = 0
        with tx_session(self.session_factory) as session:
            rows = (
                session.execute(
                    select(AuditOutbox)
                    .where(AuditOutbox.delivered_at.is_(None))
                    .order_by(AuditOutbox.created_at.asc())
                    .limit(limit)
                )
                .scalars()
                .all()
            )
            for row in rows:
                p = row.payload
                status = "SUCCESS" if p.get("outcome") == "allow" else "DENIED"
                self.logger.log_event(
                    service="identity_keys",
                    action=str(p["action"]),
                    subject=str(p["actor_id"]),
                    resource=str(p["target"]),
                    status=status,
                    metadata={
                        "event_id": p["event_id"],
                        "device_id": p.get("device_id"),
                        "reason_code": p.get("reason_code"),
                        "correlation_id": p.get("correlation_id"),
                        **(p.get("metadata") or {}),
                    },
                )
                row.delivered_at = self.clock.now()
                delivered += 1
        return delivered
