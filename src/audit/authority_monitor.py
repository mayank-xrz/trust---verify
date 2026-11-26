"""Authority Behavior Monitoring, Auto-Revert Guard, and Audit Log Integrity Enforcement.

Tracks newly granted elevated authorities (e.g. new admin), verifies audit hash-chain
integrity before/after actions, detects suspicious console changes, automatically reverts
or prevents mutations when a user performs a suspicious action or has a prior active threat,
and records an immutable hash-chained threat log describing the exact case.
"""

from __future__ import annotations

import copy
import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .logger import AuditLogger
from .verifier import AuditLogVerifier

SUSPICIOUS_CONSOLE_ACTIONS = {
    "DISABLE_AUDIT",
    "PURGE_LOGS",
    "DELETE_LOGS",
    "BYPASS_POLICY",
    "DISABLE_TIMEZONE_CHECK",
    "EXPORT_SECRETS",
    "MODIFY_SECURITY_POLICY",
    "BULK_REVOKE",
    "SELF_ESCALATE",
}

SENSITIVE_CONSOLE_KEYS = {
    "audit_enabled",
    "timezone_check_enabled",
    "max_devices_per_user",
    "max_file_size_bytes",
    "allow_insecure_fallback",
    "grace_cutoff_sec",
    "require_mfa",
}


class AuthorityMonitorError(Exception):
    """Base error for authority monitoring and log integrity."""
    reason = "authority_monitor_error"


class LogIntegrityError(AuthorityMonitorError):
    """Raised when SHA-256 audit log hash-chain verification fails."""
    reason = "log_integrity_violation"


class SuspiciousAuthorityError(AuthorityMonitorError):
    """Raised when a newly granted authority action is suspicious or follows a prior threat."""
    reason = "suspicious_authority_reverted"

    def __init__(self, message: str, threat_record: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.threat_record: Dict[str, Any] = threat_record or {}


class AuthorityMonitor:
    """Monitors newly granted authorities, protects console state via snapshot/revert, and enforces log integrity."""

    def __init__(
        self,
        *,
        node_id: str,
        state_dir: str | Path,
        audit_logger: Optional[AuditLogger] = None,
        initial_console_state: Optional[Dict[str, Any]] = None,
        new_authority_window_sec: float = 3600.0,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.node_id = node_id
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit_logger = audit_logger or AuditLogger(
            node_id,
            str(self.state_dir / "authority_audit.log"),
        )
        self.verifier = AuditLogVerifier()
        self.anchor_path = self.state_dir / ".authority_audit_anchor.json"
        self.new_authority_window_sec = new_authority_window_sec
        self.clock = clock
        self.db_path = self.state_dir / "authority_monitor.db"

        self.console_state: Dict[str, Any] = copy.deepcopy(
            initial_console_state
            if initial_console_state is not None
            else {
                "audit_enabled": True,
                "timezone_check_enabled": True,
                "max_devices_per_user": 1,
                "max_file_size_bytes": 20 * 1024 * 1024,
                "allow_insecure_fallback": False,
                "ui_banner": "Trust-But-Verify Console",
            }
        )
        self._state_history: List[Dict[str, Any]] = [copy.deepcopy(self.console_state)]
        self.threat_logs: List[Dict[str, Any]] = []

        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS authority_grants (
                    user_id TEXT PRIMARY KEY,
                    role TEXT NOT NULL,
                    granted_by TEXT NOT NULL,
                    granted_at REAL NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'suspended', 'revoked')),
                    has_active_threat INTEGER NOT NULL DEFAULT 0,
                    last_threat_case TEXT NOT NULL DEFAULT ''
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS authority_behavior_events (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    outcome TEXT NOT NULL,
                    case_label TEXT NOT NULL,
                    reverted INTEGER NOT NULL,
                    ts REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _state_digest(state: Dict[str, Any]) -> str:
        raw = json.dumps(state, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()

    def _save_anchor(self) -> None:
        if Path(self.audit_logger.log_file_path).exists():
            self.verifier.save_anchor(self.audit_logger.log_file_path, self.anchor_path)

    def _log_and_anchor(self, **kwargs: Any) -> Any:
        rec = self.audit_logger.log_event(**kwargs)
        self._save_anchor()
        return rec

    def verify_log_integrity(self) -> Dict[str, Any]:
        """Verify SHA-256 hash chain integrity of the audit log; fail closed on tampering."""
        anchor = self.anchor_path if self.anchor_path.exists() else None
        res = self.verifier.verify_file(self.audit_logger.log_file_path, anchor_path=anchor)
        if not res.is_valid:
            raise LogIntegrityError(
                f"Audit log integrity check failed: {res.first_error}"
            )
        return res.to_dict()

    def grant_authority(
        self,
        *,
        user_id: str,
        role: str,
        granted_by: str,
    ) -> Dict[str, Any]:
        """Grant elevated authority to user_id and place them under behavioral monitoring."""
        if not user_id or not role or not granted_by:
            raise ValueError("user_id, role, and granted_by must be non-empty")
        self.verify_log_integrity()
        now = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO authority_grants (user_id, role, granted_by, granted_at, status, has_active_threat, last_threat_case)
                VALUES (?, ?, ?, ?, 'active', 0, '')
                ON CONFLICT(user_id) DO UPDATE SET
                    role=excluded.role,
                    granted_by=excluded.granted_by,
                    granted_at=excluded.granted_at,
                    status='active',
                    has_active_threat=0,
                    last_threat_case=''
                """,
                (user_id, role, granted_by, now),
            )
        rec = self._log_and_anchor(
            service=self.node_id,
            action="AUTHORITY_GRANTED",
            subject=user_id,
            resource=f"role/{role}",
            status="SUCCESS",
            metadata={
                "granted_by": granted_by,
                "role": role,
                "monitored": True,
                "monitoring_window_sec": self.new_authority_window_sec,
            },
        )
        return {"user_id": user_id, "role": role, "granted_by": granted_by, "entry_hash": rec.entry_hash}

    def record_threat(
        self,
        *,
        user_id: str,
        case_label: str,
        description: str,
        severity: str = "HIGH",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Mark an active threat on user_id and append a hash-chained threat log."""
        self.verify_log_integrity()
        now = self.clock()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT user_id FROM authority_grants WHERE user_id=?", (user_id,)).fetchone()
            if row is not None:
                db.execute(
                    "UPDATE authority_grants SET has_active_threat=1, last_threat_case=? WHERE user_id=?",
                    (case_label, user_id),
                )
            else:
                db.execute(
                    """
                    INSERT INTO authority_grants (user_id, role, granted_by, granted_at, status, has_active_threat, last_threat_case)
                    VALUES (?, 'user', 'system', ?, 'active', 1, ?)
                    """,
                    (user_id, now, case_label),
                )
            db.execute(
                """
                INSERT INTO authority_behavior_events (user_id, action, outcome, case_label, reverted, ts)
                VALUES (?, 'EXTERNAL_THREAT_FLAGGED', 'THREAT', ?, 0, ?)
                """,
                (user_id, case_label, now),
            )

        meta = {
            "case": case_label,
            "severity": severity,
            "description": description,
            **(metadata or {}),
        }
        rec = self._log_and_anchor(
            service=self.node_id,
            action="AUTHORITY_THREAT_DETECTED",
            subject=user_id,
            resource="authority/monitor",
            status="SUSPICIOUS",
            metadata=meta,
        )
        threat_entry = {
            "event_id": rec.event_id,
            "entry_hash": rec.entry_hash,
            "user_id": user_id,
            "case": case_label,
            "severity": severity,
            "description": description,
            "reverted": False,
        }
        self.threat_logs.append(threat_entry)
        return threat_entry

    def get_authority_status(self, user_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as db:
            row = db.execute(
                "SELECT role, granted_by, granted_at, status, has_active_threat, last_threat_case FROM authority_grants WHERE user_id=?",
                (user_id,),
            ).fetchone()
            if row is None:
                return None
            return {
                "user_id": user_id,
                "role": row[0],
                "granted_by": row[1],
                "granted_at": row[2],
                "status": row[3],
                "has_active_threat": bool(row[4]),
                "last_threat_case": row[5],
            }

    def get_threat_logs(self) -> List[Dict[str, Any]]:
        return list(self.threat_logs)

    @staticmethod
    def _is_suspicious_change(action: str, proposed_changes: Dict[str, Any]) -> Optional[str]:
        upper_action = action.upper()
        if upper_action in SUSPICIOUS_CONSOLE_ACTIONS:
            return f"Prohibited/high-risk console action '{upper_action}'"
        for key, new_val in proposed_changes.items():
            if key in SENSITIVE_CONSOLE_KEYS:
                if key == "audit_enabled" and new_val is False:
                    return "Attempted to disable audit logging"
                if key == "timezone_check_enabled" and new_val is False:
                    return "Attempted to disable timezone anomaly enforcement"
                if key == "allow_insecure_fallback" and new_val is True:
                    return "Attempted to enable insecure classical fallback"
                if key == "max_devices_per_user" and isinstance(new_val, int) and new_val != 1:
                    return f"Attempted to weaken single-device limit to {new_val}"
                if key == "max_file_size_bytes" and isinstance(new_val, int) and new_val > 20 * 1024 * 1024:
                    return f"Attempted to raise file limit above 20 MB ({new_val})"
                return f"Attempted unapproved modification of sensitive security setting '{key}'"
        return None

    def execute_console_action(
        self,
        *,
        user_id: str,
        action: str,
        proposed_changes: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a console action while monitoring newly granted authorities.

        - Verifies audit log hash-chain integrity before proceeding.
        - Takes a pre-action state snapshot.
        - If the user has a prior active threat OR the action/changes are suspicious for a
          newly assigned authority:
            1) Does NOT apply / immediately reverts console_state back to snapshot.
            2) Suspends the elevated authority.
            3) Records a hash-chained threat log naming the exact case, prior threat, and revert proof.
        """
        self.verify_log_integrity()
        changes = dict(proposed_changes or {})
        now = self.clock()
        pre_snapshot = copy.deepcopy(self.console_state)
        pre_digest = self._state_digest(pre_snapshot)

        grant = self.get_authority_status(user_id)
        if grant is None:
            raise SuspiciousAuthorityError(
                f"User '{user_id}' has no authority grant",
                threat_record={"user_id": user_id, "case": "NO_AUTHORITY_GRANT", "reverted": True},
            )

        if grant["status"] != "active":
            case_label = "SUSPENDED_AUTHORITY_CONSOLE_ATTEMPT"
            rec = self._log_and_anchor(
                service=self.node_id,
                action="AUTHORITY_MUTATION_BLOCKED_AND_REVERTED",
                subject=user_id,
                resource="console/config",
                status="DENIED",
                metadata={
                    "case": case_label,
                    "attempted_action": action,
                    "authority_status": grant["status"],
                    "prior_threat_case": grant["last_threat_case"],
                    "reverted": True,
                    "restored_state_hash": pre_digest,
                },
            )
            threat = {
                "event_id": rec.event_id,
                "entry_hash": rec.entry_hash,
                "user_id": user_id,
                "case": case_label,
                "attempted_action": action,
                "reverted": True,
                "restored_state_hash": pre_digest,
            }
            self.threat_logs.append(threat)
            raise SuspiciousAuthorityError(f"Blocked '{action}': authority status is '{grant['status']}'", threat)

        is_new_authority = (now - float(grant["granted_at"])) <= self.new_authority_window_sec
        prior_threat = bool(grant["has_active_threat"])
        suspicious_reason = self._is_suspicious_change(action, changes)

        # If old log was a threat -> prevent/revert the next console change unconditionally.
        # Or if a newly assigned admin performs a suspicious change -> prevent/revert and flag threat.
        if prior_threat or (is_new_authority and suspicious_reason is not None):
            # Apply-then-revert simulation safety: ensure console_state is strictly identical to pre_snapshot
            self.console_state = copy.deepcopy(pre_snapshot)
            restored_digest = self._state_digest(self.console_state)
            assert restored_digest == pre_digest

            if prior_threat:
                case_label = "PRIOR_THREAT_ACTIVE_NEXT_CHANGE_REVERTED"
                detail = (
                    f"Blocked and reverted console change '{action}' by '{user_id}' ({grant['role']}) "
                    f"because a prior threat log was active (case='{grant['last_threat_case']}')."
                )
            else:
                case_label = "NEW_ADMIN_SUSPICIOUS_CONSOLE_ACTION_REVERTED"
                detail = (
                    f"Suspicious console change '{action}' by newly granted {grant['role']} '{user_id}': "
                    f"{suspicious_reason}. Change prevented/reverted to safe snapshot."
                )

            with self._connect() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    """
                    UPDATE authority_grants
                    SET status='suspended', has_active_threat=1, last_threat_case=?
                    WHERE user_id=?
                    """,
                    (case_label, user_id),
                )
                db.execute(
                    """
                    INSERT INTO authority_behavior_events (user_id, action, outcome, case_label, reverted, ts)
                    VALUES (?, ?, 'REVERTED', ?, 1, ?)
                    """,
                    (user_id, action, case_label, now),
                )

            rec = self._log_and_anchor(
                service=self.node_id,
                action="NEW_ADMIN_SUSPICIOUS_CONSOLE_CHANGE" if not prior_threat else "AUTHORITY_MUTATION_BLOCKED_AND_REVERTED",
                subject=user_id,
                resource="console/config",
                status="SUSPICIOUS",
                metadata={
                    "case": case_label,
                    "severity": "CRITICAL",
                    "role": grant["role"],
                    "attempted_action": action,
                    "attempted_keys": ",".join(sorted(changes.keys())),
                    "prior_threat_detected": prior_threat,
                    "prior_threat_case": grant["last_threat_case"],
                    "reverted": True,
                    "restored_state_hash": restored_digest,
                    "description": detail,
                },
            )
            # Re-verify audit hash chain integrity after writing the threat log
            self.verify_log_integrity()

            threat = {
                "event_id": rec.event_id,
                "entry_hash": rec.entry_hash,
                "user_id": user_id,
                "role": grant["role"],
                "case": case_label,
                "prior_threat_detected": prior_threat,
                "prior_threat_case": grant["last_threat_case"],
                "attempted_action": action,
                "attempted_changes": changes,
                "reverted": True,
                "restored_state_hash": restored_digest,
                "description": detail,
            }
            self.threat_logs.append(threat)
            raise SuspiciousAuthorityError(detail, threat_record=threat)

        # Legitimate non-suspicious action by authority with no prior threat
        for key, val in changes.items():
            self.console_state[key] = val
        self._state_history.append(copy.deepcopy(self.console_state))
        new_digest = self._state_digest(self.console_state)

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO authority_behavior_events (user_id, action, outcome, case_label, reverted, ts)
                VALUES (?, ?, 'ALLOWED', 'ROUTINE_ADMIN_ACTION', 0, ?)
                """,
                (user_id, action, now),
            )

        rec = self._log_and_anchor(
            service=self.node_id,
            action="CONSOLE_ACTION_APPLIED",
            subject=user_id,
            resource="console/config",
            status="SUCCESS",
            metadata={
                "case": "ROUTINE_ADMIN_ACTION",
                "role": grant["role"],
                "console_action": action,
                "state_hash": new_digest,
            },
        )
        self.verify_log_integrity()
        return {
            "status": "applied",
            "state_hash": new_digest,
            "entry_hash": rec.entry_hash,
            "console_state": copy.deepcopy(self.console_state),
        }
