"""Deterministic Context-Aware Privilege and Routine-vs-Suspicious Rules.

100% Explainable, deterministic rules without black-box AI/ML models.
"""

from __future__ import annotations
import collections
import dataclasses
import time
from typing import Dict, Any, List, Optional


@dataclasses.dataclass
class RuleAlert:
    alert_id: str
    rule_name: str
    severity: str  # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    timestamp_ns: int
    subject: str
    service: str
    resource: str
    description: str
    evidence: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class DetectionRules:
    """Set of deterministic security rules."""

    @staticmethod
    def check_unauthorized_admin(event: Dict[str, Any]) -> Optional[RuleAlert]:
        """Detects direct attempts to access admin endpoints without admin privileges."""
        resource = str(event.get("resource", ""))
        action = str(event.get("action", ""))
        metadata = event.get("metadata", {})
        role = metadata.get("role", "user")

        is_admin_resource = (
            "/admin" in resource
            or resource.startswith("/keys/rotate")
            or action in ("ROTATE_KEY", "REVOKE_KEY", "PURGE_LOGS")
        )

        if is_admin_resource and role != "admin":
            return RuleAlert(
                alert_id=f"alert-priv-{event.get('event_id', '')[:8]}",
                rule_name="UNAUTHORIZED_PRIVILEGE_ELEVATION",
                severity="CRITICAL",
                timestamp_ns=event.get("timestamp_ns", time.time_ns()),
                subject=event.get("subject", "unknown"),
                service=event.get("service", "unknown"),
                resource=resource,
                description=f"Non-admin subject '{event.get('subject')}' attempted privileged action '{action}' on '{resource}'",
                evidence={"role": role, "action": action, "resource": resource},
            )
        return None

    @staticmethod
    def check_crypto_tamper_or_replay(event: Dict[str, Any]) -> Optional[RuleAlert]:
        """Detects failed cryptographic envelope signatures, replay hits, or recipient binding swaps."""
        status = str(event.get("status", "")).upper()
        action = str(event.get("action", "")).upper()
        metadata = event.get("metadata", {})
        err = str(metadata.get("error", "")).upper()

        is_crypto_attack = (
            status in ("DENIED", "SUSPICIOUS")
            and (
                "REPLAY" in err
                or "DUPLICATE" in err
                or "RECIPIENT" in err
                or "MISMATCH" in err
                or "SIGNATURE" in err
                or "TAMPER" in err
                or "HIJACK" in err
                or "REPLAY" in action
                or "RECIPIENT" in action
                or "HIJACK" in action
            )
        )

        if is_crypto_attack:
            return RuleAlert(
                alert_id=f"alert-sec-{event.get('event_id', '')[:8]}",
                rule_name="CRYPTOGRAPHIC_ATTACK_DETECTED",
                severity="HIGH",
                timestamp_ns=event.get("timestamp_ns", time.time_ns()),
                subject=event.get("subject", "unknown"),
                service=event.get("service", "unknown"),
                resource=event.get("resource", "crypto"),
                description=f"Cryptographic attack detected on {event.get('service')}: {metadata.get('error', action)}",
                evidence=metadata,
            )
        return None


class ContextRuleEngine:
    """Stateful context engine tracking frequency bursts and routine vs suspicious transitions."""

    def __init__(self, burst_threshold: int = 15, burst_window_sec: float = 1.0):
        self.burst_threshold = burst_threshold
        self.burst_window_sec = burst_window_sec
        # subject -> deque of timestamps
        self.subject_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)

    def evaluate_event(self, event: Dict[str, Any]) -> List[RuleAlert]:
        """Evaluates single event against all explainable rules."""
        alerts = []

        # 1. Stateless privilege elevation check
        r1 = DetectionRules.check_unauthorized_admin(event)
        if r1:
            alerts.append(r1)

        # 2. Crypto attack / replay check
        r2 = DetectionRules.check_crypto_tamper_or_replay(event)
        if r2:
            alerts.append(r2)

        # 3. Burst frequency check (brute force / flood)
        subject = event.get("subject", "")
        if subject:
            now_sec = event.get("timestamp_ns", 0) / 1_000_000_000.0 or time.time()
            dq = self.subject_history[subject]
            dq.append(now_sec)

            # Prune old timestamps
            while dq and (now_sec - dq[0] > self.burst_window_sec):
                dq.popleft()

            if len(dq) >= self.burst_threshold:
                alerts.append(
                    RuleAlert(
                        alert_id=f"alert-burst-{event.get('event_id', '')[:8]}",
                        rule_name="ABNORMAL_FREQUENCY_BURST",
                        severity="MEDIUM",
                        timestamp_ns=event.get("timestamp_ns", time.time_ns()),
                        subject=subject,
                        service=event.get("service", ""),
                        resource=event.get("resource", ""),
                        description=f"Subject '{subject}' exceeded rate limit ({len(dq)} calls within {self.burst_window_sec}s)",
                        evidence={"call_count": len(dq), "window_sec": self.burst_window_sec},
                    )
                )

        return alerts
