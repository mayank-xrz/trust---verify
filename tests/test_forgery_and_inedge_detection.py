"""Regression tests for whole-state/whole-log forgery and in-edge attacker detection."""

from __future__ import annotations
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

import track4_service
from src.audit.logger import AuditLogger, GENESIS_HASH
from src.audit.verifier import AuditLogVerifier
from src.detector.graph_lateral import LateralMovementGraph
from src.detector.rules import ContextRuleEngine

ROOT = Path(__file__).resolve().parents[1]


def test_whole_state_file_replacement_rejected_by_track4_service(tmp_path: Path) -> None:
    env = {**os.environ, "TRACK4_STATE_DIR": str(tmp_path)}

    def call(req):
        return subprocess.run(
            [sys.executable, str(ROOT / "track4_service.py")],
            input=json.dumps(req),
            text=True,
            capture_output=True,
            env=env,
        )

    assert call({
        "op": "setup",
        "owners": {"s1": "alice"},
        "contents": {"s1": "vault"},
        "disabled": [],
        "key_material": "k",
    }).returncode == 0

    assert call({
        "op": "read",
        "actor": "alice",
        "asset": "s1",
        "request_id": "r1",
    }).returncode == 0

    # Attacker replaces entire state.json with a freshly computed valid hash chain
    forged_body = {
        "seq": 0, "op": "setup", "actor": None, "asset": None,
        "request_id": None, "decision": "allow", "prev_hash": GENESIS_HASH,
    }
    h0 = hashlib.sha256(GENESIS_HASH.encode("ascii") + track4_service.canonical(forged_body)).hexdigest()
    forged_state = {
        "owners": {"s1": "attacker"},
        "contents": {},
        "disabled": [],
        "audit_log": [{**forged_body, "entry_hash": h0}],
        "used_challenges": {},
    }
    (tmp_path / "track4-local" / "state.json").write_text(json.dumps(forged_state), encoding="utf-8")

    # Next call must fail closed against the out-of-band audit anchor
    res = call({"op": "read", "actor": "attacker", "asset": "s1", "request_id": "r2"})
    assert res.returncode != 0


def test_whole_log_replacement_rejected_by_audit_verifier(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.log"
    anchor_path = tmp_path / "audit.anchor.json"

    logger = AuditLogger("node-a", str(log_path))
    logger.log_event("node-a", "REVOKE_KEY", "admin", "/keys/1", status="SUCCESS")
    AuditLogVerifier.save_anchor(str(log_path), str(anchor_path))

    # Attacker replaces entire audit.log with a freshly hashed benign-looking log
    log_path.unlink()
    forged_logger = AuditLogger("node-a", str(log_path))
    forged_logger.log_event("node-a", "ROUTINE_READ", "alice", "/public", status="SUCCESS")

    # Anchor catches whole-log replacement
    res = AuditLogVerifier().verify_file(str(log_path), anchor_path=str(anchor_path))
    assert not res.is_valid
    assert "Whole-log replacement" in (res.first_error or "")

    # Requiring signed checkpoint also rejects unsigned whole-file replacement
    res_sig = AuditLogVerifier(require_signed_checkpoint=True).verify_file(str(log_path))
    assert not res_sig.is_valid


def test_in_edge_high_risk_action_and_disallowed_edge_action_detected() -> None:
    g = LateralMovementGraph()
    # Allowed action on established edge succeeds
    assert g.check_call("node-a", "key-authority", action="VERIFY_KEY") is None

    # High-risk action inside established edge is flagged
    v1 = g.check_call("node-a", "key-authority", action="DUMP_ALL_KEYS")
    assert v1 is not None and "high-risk action" in v1.reason

    v2 = g.check_call("api-gateway", "node-a", action="EXFILTRATE_ARCHIVE")
    assert v2 is not None and "high-risk action" in v2.reason

    # Unlisted action on action-restricted edge is flagged
    v3 = g.check_call("node-a", "key-authority", action="UNLISTED_OP")
    assert v3 is not None and "Disallowed action" in v3.reason


def test_in_edge_identity_hop_velocity_detected() -> None:
    g = LateralMovementGraph(hop_window_sec=10.0, max_distinct_targets=3)
    assert g.check_call("api-gateway", "node-a", action="GET_STATUS", identity="svc-acct-1", timestamp_sec=100.0) is None
    assert g.check_call("node-a", "node-b", action="GET_STATUS", identity="svc-acct-1", timestamp_sec=101.0) is None
    v = g.check_call("node-b", "key-authority", action="VERIFY_KEY", identity="svc-acct-1", timestamp_sec=102.0)
    assert v is not None
    assert "hop velocity" in v.reason


def test_low_and_slow_sensitive_access_detected_below_burst_threshold() -> None:
    engine = ContextRuleEngine(burst_threshold=15, burst_window_sec=1.0, slow_sensitive_threshold=4, slow_window_sec=300.0)
    alerts = []
    for i in range(5):
        alerts.extend(
            engine.evaluate_event({
                "event_id": f"evt-{i}",
                "timestamp_ns": int((1_700_000_000 + i * 10) * 1_000_000_000),
                "action": "READ_SECRET",
                "subject": "compromised-svc",
                "service": "node-a",
                "resource": "/secrets/export",
                "status": "SUCCESS",
                "metadata": {"role": "admin"},
            })
        )
    assert any(a.rule_name == "LOW_AND_SLOW_SENSITIVE_ACCESS" for a in alerts)
