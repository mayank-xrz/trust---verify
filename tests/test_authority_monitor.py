"""Tests for new-authority behavioral monitoring, auto-revert on prior threat, and log integrity."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.audit.authority_monitor import (
    AuthorityMonitor,
    LogIntegrityError,
    SuspiciousAuthorityError,
)
from src.audit.verifier import AuditLogVerifier
from src.crypto import SecureCryptoSystem, TimezoneMismatchError
from tests.conftest import read_audit_events


def test_new_admin_suspicious_console_change_is_reverted_and_logged(tmp_path: Path) -> None:
    monitor = AuthorityMonitor(node_id="console-1", state_dir=tmp_path)
    monitor.grant_authority(user_id="bob", role="admin", granted_by="root-ops")

    # Routine non-sensitive UI banner update succeeds
    ok = monitor.execute_console_action(
        user_id="bob",
        action="UPDATE_BANNER",
        proposed_changes={"ui_banner": "Ops Console v2"},
    )
    assert ok["status"] == "applied"
    assert monitor.console_state["ui_banner"] == "Ops Console v2"

    # Newly assigned admin attempts suspicious console change (disable audit) -> prevented & reverted
    with pytest.raises(SuspiciousAuthorityError) as exc_info:
        monitor.execute_console_action(
            user_id="bob",
            action="DISABLE_AUDIT",
            proposed_changes={"audit_enabled": False},
        )

    assert exc_info.value.threat_record["case"] == "NEW_ADMIN_SUSPICIOUS_CONSOLE_ACTION_REVERTED"
    assert exc_info.value.threat_record["reverted"] is True
    assert monitor.console_state["audit_enabled"] is True

    # Subsequent change by the suspended/flagged user is also blocked & reverted
    with pytest.raises(SuspiciousAuthorityError) as exc_info2:
        monitor.execute_console_action(
            user_id="bob",
            action="UPDATE_BANNER",
            proposed_changes={"ui_banner": "Hacked Banner"},
        )
    assert exc_info2.value.threat_record["reverted"] is True
    assert monitor.console_state["ui_banner"] == "Ops Console v2"

    # Hash-chained audit log integrity stays intact and records the exact case
    assert AuditLogVerifier().verify_file(monitor.audit_logger.log_file_path).is_valid
    events = read_audit_events(Path(monitor.audit_logger.log_file_path))
    assert any(
        e["action"] == "NEW_ADMIN_SUSPICIOUS_CONSOLE_CHANGE"
        and e["metadata"]["case"] == "NEW_ADMIN_SUSPICIOUS_CONSOLE_ACTION_REVERTED"
        and e["metadata"]["reverted"] is True
        for e in events
    )


def test_prior_threat_blocks_and_reverts_next_console_change_on_system(tmp_path: Path) -> None:
    alice = SecureCryptoSystem(
        identity="alice",
        device="dev-a1",
        state_dir=tmp_path / "alice",
        timezone="Asia/Kolkata",
    )
    bob = SecureCryptoSystem(
        identity="bob",
        device="dev-b1",
        state_dir=tmp_path / "bob",
        timezone="Asia/Kolkata",
    )

    hello = bob.create_hello()
    init_msg, ak = alice.initiate_session(hello, bob.signing_public_key)
    bob.accept_session(init_msg, alice.signing_public_key)

    # Grant new admin authority to alice on Bob's authority monitor
    bob.authority_monitor.grant_authority(user_id="alice", role="admin", granted_by="root-ops")

    # Baseline login from Asia/Kolkata
    env_ok = alice.encrypt(ak.session_id, b"baseline-ok")
    assert bob.decrypt(env_ok, alice.signing_public_key, request_timezone="Asia/Kolkata") == b"baseline-ok"

    # Old/prior threat occurs: alice sends access request from anomalous timezone
    env = alice.encrypt(ak.session_id, b"tz-trigger")
    with pytest.raises(TimezoneMismatchError):
        bob.decrypt(env, alice.signing_public_key, request_timezone="America/New_York")

    # Now newly assigned admin alice goes to console to make even a benign-looking change ->
    # because old log was a threat, the next change MUST NOT happen (reverted) and is threat-logged!
    with pytest.raises(SuspiciousAuthorityError) as exc_info:
        bob.authority_monitor.execute_console_action(
            user_id="alice",
            action="UPDATE_BANNER",
            proposed_changes={"ui_banner": "Should Be Reverted"},
        )

    rec = exc_info.value.threat_record
    assert rec["case"] == "PRIOR_THREAT_ACTIVE_NEXT_CHANGE_REVERTED"
    assert rec["prior_threat_detected"] is True
    assert rec["prior_threat_case"] == "ANOMALOUS_TIMEZONE_ACCESS"
    assert rec["reverted"] is True
    assert bob.authority_monitor.console_state["ui_banner"] == "Trust-But-Verify Console"
    assert bob.authority_monitor.get_authority_status("alice")["status"] == "suspended"

    assert AuditLogVerifier().verify_file(bob.audit_logger.log_file_path).is_valid


def test_tampered_audit_log_fails_closed(tmp_path: Path) -> None:
    monitor = AuthorityMonitor(node_id="console-2", state_dir=tmp_path)
    monitor.grant_authority(user_id="bob", role="admin", granted_by="root-ops")

    # Tamper with the hash-chained audit log directly on disk
    log_path = Path(monitor.audit_logger.log_file_path)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[-1])
    entry["subject"] = "forged-admin"
    lines[-1] = json.dumps(entry)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    # Any console action must fail closed with LogIntegrityError
    with pytest.raises(LogIntegrityError):
        monitor.execute_console_action(
            user_id="bob",
            action="UPDATE_BANNER",
            proposed_changes={"ui_banner": "Blocked Due To Tamper"},
        )
