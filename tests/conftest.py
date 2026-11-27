"""Shared pytest fixtures for PQC & Crypto acceptance tests.

All keys are generated at runtime; no secrets are committed.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict, List

import pytest
from pqcrypto.sign import ml_dsa_65

from src.audit.logger import AuditLogger
from src.crypto._pqcrypto_compat import sig_keygen


@pytest.fixture(autouse=True)
def trusted_organizer_adapter(monkeypatch):
    """Existing organizer protocol tests run inside the explicit trusted harness."""
    monkeypatch.setenv("TRACK4_TRUSTED_HARNESS", "1")
    monkeypatch.delenv("TRACK4_ISSUER_PUBLIC_KEY_B64", raising=False)


@pytest.fixture
def runtime_identities() -> Dict[str, tuple[bytes, bytes]]:
    """Generate fresh ML-DSA-65 identity keypairs at runtime."""
    return {
        "alice": sig_keygen(ml_dsa_65),
        "bob": sig_keygen(ml_dsa_65),
        "mallory": sig_keygen(ml_dsa_65),
    }


@pytest.fixture
def audit_log_path(tmp_path: Path) -> Path:
    return tmp_path / "crypto_audit.log"


@pytest.fixture
def crypto_audit_logger(audit_log_path: Path) -> AuditLogger:
    return AuditLogger("test-node", str(audit_log_path))


def read_audit_events(log_path: Path) -> List[Dict]:
    events: List[Dict] = []
    if not log_path.exists():
        return events
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        events.append(json.loads(line))
    return events


def extract_crypto_event(record: Dict) -> Dict:
    """Extract and assert all 11 required crypto event fields from an AuditLogger record."""
    meta = record.get("metadata", {})
    event = {
        "event_id": record.get("event_id"),
        "timestamp": meta.get("timestamp"),
        "actor": meta.get("actor"),
        "source_service": meta.get("source_service"),
        "target_service": meta.get("target_service"),
        "action": record.get("action"),
        "outcome": meta.get("outcome"),
        "session_id": meta.get("session_id"),
        "message_id": meta.get("message_id"),
        "reason": meta.get("reason"),
        "log_hash": record.get("entry_hash"),
    }
    required_keys = (
        "event_id",
        "timestamp",
        "actor",
        "source_service",
        "target_service",
        "action",
        "outcome",
        "session_id",
        "message_id",
        "reason",
        "log_hash",
    )
    for k in required_keys:
        assert k in event and event[k] is not None, f"Missing event field: {k}"
    assert str(event["timestamp"]).endswith("Z"), f"Timestamp not UTC ISO-8601: {event['timestamp']}"
    return event
