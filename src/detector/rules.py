"""Deterministic Context-Aware Privilege and Routine-vs-Suspicious Rules.

100% Explainable, deterministic rules without black-box AI/ML models.
"""

from __future__ import annotations

import collections
import dataclasses
import time
from typing import Any, Dict, List, Optional

APPROVED_CHANGE_WINDOWS = frozenset({"approved", "active", "open", "scheduled"})


@dataclasses.dataclass(frozen=True)
class ChangeTicket:
    """A declared, approved change window that can suppress privilege alerts."""

    ticket_id: str
    subject: Optional[str] = None
    not_before_ns: int = 0
    not_after_ns: int = (1 << 63) - 1
    approved: bool = True

    def covers(self, subject: str, timestamp_ns: int) -> bool:
        if not self.approved:
            return False
        if self.subject is not None and self.subject != subject:
            return False
        return self.not_before_ns <= timestamp_ns <= self.not_after_ns


class ChangeTicketRegistry:
    """Authoritative registry of approved change tickets.

    The rule engine only needs the declared ``change_ticket`` /
    ``change_window`` metadata to be present.  When a registry is supplied, the
    ticket must additionally be registered, approved, owned by the subject, and
    inside its time window, so an arbitrary event cannot self-approve.
    """

    def __init__(self, tickets: Optional[List[ChangeTicket]] = None) -> None:
        self._tickets: Dict[str, ChangeTicket] = {}
        for ticket in tickets or []:
            self.register(ticket)

    def register(self, ticket: ChangeTicket) -> None:
        self._tickets[ticket.ticket_id] = ticket

    def revoke(self, ticket_id: str) -> None:
        self._tickets.pop(ticket_id, None)

    def is_approved(self, ticket_id: str, subject: str, timestamp_ns: int) -> bool:
        ticket = self._tickets.get(ticket_id)
        return ticket is not None and ticket.covers(subject, timestamp_ns)


def declared_approved_change(
    event: Dict[str, Any],
    registry: Optional[ChangeTicketRegistry] = None,
) -> Optional[Dict[str, Any]]:
    """Return change-ticket evidence iff the event is inside an approved window."""
    metadata = event.get("metadata") or {}
    ticket_id = str(metadata.get("change_ticket", "")).strip()
    window = str(metadata.get("change_window", "")).strip().lower()
    if not ticket_id or window not in APPROVED_CHANGE_WINDOWS:
        return None
    subject = str(event.get("subject", ""))
    timestamp_ns = int(event.get("timestamp_ns", 0))
    if registry is not None and not registry.is_approved(ticket_id, subject, timestamp_ns):
        return None
    return {"change_ticket": ticket_id, "change_window": window}



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

    def __init__(
        self,
        burst_threshold: int = 15,
        burst_window_sec: float = 1.0,
        change_tickets: Optional[ChangeTicketRegistry] = None,
        slow_sensitive_threshold: int = 4,
        slow_window_sec: float = 300.0,
    ):
        self.burst_threshold = burst_threshold
        self.burst_window_sec = burst_window_sec
        self.change_tickets = change_tickets
        self.slow_sensitive_threshold = slow_sensitive_threshold
        self.slow_window_sec = slow_window_sec
        # subject -> deque of timestamps
        self.subject_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self.sensitive_history: Dict[str, collections.deque] = collections.defaultdict(collections.deque)

    def evaluate_event(self, event: Dict[str, Any]) -> List[RuleAlert]:
        """Evaluates single event against all explainable rules."""
        alerts = []

        # 1. Stateless privilege elevation check, unless the event is covered by
        # an approved declared-change window (e.g. an approved deploy bot).
        change = declared_approved_change(event, self.change_tickets)
        if change is None:
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

            # 4. Low-and-slow sensitive access check (catches attackers staying below burst threshold on allowed edges)
            act_u = str(event.get("action", "")).upper()
            res_l = str(event.get("resource", "")).lower()
            is_sensitive = (
                any(tok in act_u for tok in ("SECRET", "EXPORT", "DUMP", "KEY_ACCESS"))
                or "/secrets" in res_l
                or "/keys/" in res_l
            )
            if is_sensitive:
                sdq = self.sensitive_history[subject]
                sdq.append(now_sec)
                while sdq and (now_sec - sdq[0] > self.slow_window_sec):
                    sdq.popleft()
                if len(sdq) >= self.slow_sensitive_threshold:
                    alerts.append(
                        RuleAlert(
                            alert_id=f"alert-slow-{event.get('event_id', '')[:8]}",
                            rule_name="LOW_AND_SLOW_SENSITIVE_ACCESS",
                            severity="HIGH",
                            timestamp_ns=event.get("timestamp_ns", time.time_ns()),
                            subject=subject,
                            service=event.get("service", ""),
                            resource=event.get("resource", ""),
                            description=f"Subject '{subject}' made {len(sdq)} sensitive access calls within {self.slow_window_sec}s",
                            evidence={"sensitive_count": len(sdq), "window_sec": self.slow_window_sec},
                        )
                    )

        return alerts
