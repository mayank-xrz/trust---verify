"""
Deterministic, explainable security detector (no AI/ML):
1. Clock-skew / out-of-order buffering with explicit uncertainty flagging.
2. Routine vs. suspicious privilege/data-access rules.
3. Graph-based lateral movement detection across services.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from .audit_logger import post_to_xerj

PRIVILEGE_RANK = {
    "guest": 0,
    "user": 1,
    "service": 2,
    "admin": 3,
    "root": 4,
}

# Expected service-to-service transitions in normal operation.
ALLOWED_SERVICE_HOPS: Set[Tuple[str, str]] = {
    ("auth-gateway", "file-vault"),
    ("auth-gateway", "msg-relay"),
    ("file-vault", "backup-store"),
}


def parse_iso_utc(ts: str) -> datetime:
    """Parse an ISO-8601 timestamp into timezone-aware UTC."""
    normalized = ts.replace("Z", "+00:00")
    dt = datetime.fromisoformat(normalized)
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


class SecurityDetector:
    """Rule + graph detector with clock-skew awareness."""

    def __init__(
        self,
        max_skew_seconds: int = 30,
        lateral_window_seconds: int = 300,
        xerj_url: Optional[str] = None,
        xerj_alert_index: str = "track4-alerts",
    ):
        self.max_skew = timedelta(seconds=max_skew_seconds)
        self.lateral_window = timedelta(seconds=lateral_window_seconds)
        self.xerj_url = xerj_url
        self.xerj_alert_index = xerj_alert_index

    def order_events_with_skew(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Handle out-of-order / clock-skewed events.
        Flags `order_uncertain=True` when two events for the same actor fall within
        `2 * max_skew` or arrive out of order beyond `max_skew`.
        """
        enriched: List[Dict[str, Any]] = []
        max_seen_time: Optional[datetime] = None

        for arrival_idx, ev in enumerate(events):
            ev_copy = dict(ev)
            ev_dt = parse_iso_utc(ev["event_time"])
            ev_copy["_dt"] = ev_dt
            ev_copy["_arrival"] = arrival_idx
            ev_copy["order_uncertain"] = False

            if max_seen_time is not None and (max_seen_time - ev_dt) > self.max_skew:
                ev_copy["order_uncertain"] = True
            if max_seen_time is None or ev_dt > max_seen_time:
                max_seen_time = ev_dt

            enriched.append(ev_copy)

        enriched.sort(key=lambda x: (x["_dt"], x["_arrival"]))

        last_by_actor: Dict[str, Dict[str, Any]] = {}
        skew_gap = self.max_skew * 2
        for ev in enriched:
            actor = ev["actor_id"]
            prev = last_by_actor.get(actor)
            if prev is not None and (ev["_dt"] - prev["_dt"]) <= skew_gap and ev["_arrival"] < prev["_arrival"]:
                ev["order_uncertain"] = True
                prev["order_uncertain"] = True
            last_by_actor[actor] = ev

        return enriched

    def analyze(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Run rule + graph checks and return explainable alerts."""
        ordered = self.order_events_with_skew(events)
        alerts: List[Dict[str, Any]] = []

        # Per-actor recent service path: list of (dt, service, event_id, order_uncertain)
        actor_paths: Dict[str, List[Tuple[datetime, str, str, bool]]] = defaultdict(list)

        for ev in ordered:
            actor = ev["actor_id"]
            service = ev["service"]
            action = ev["action"]
            meta = ev.get("metadata") or {}
            ev_id = ev.get("event_id", "")
            ev_dt = ev["_dt"]
            uncertain = bool(ev.get("order_uncertain", False))

            # 1. Privilege escalation check (distinguish approved admin ticket vs suspicious)
            before_rank = PRIVILEGE_RANK.get(ev.get("privilege_before", "user"), 1)
            after_rank = PRIVILEGE_RANK.get(ev.get("privilege_after", "user"), 1)
            has_approval = bool(meta.get("ticket_id")) and meta.get("mfa_verified") == "true"

            if after_rank > before_rank and not has_approval:
                alerts.append(
                    self._make_alert(
                        alert_type="suspicious_privilege_escalation",
                        severity="high",
                        identity=actor,
                        services=[service],
                        event_ids=[ev_id],
                        rule_or_path=f"rule:unapproved_escalation({ev.get('privilege_before')}->{ev.get('privilege_after')})",
                        order_uncertain=uncertain,
                        detected_at=ev["event_time"],
                    )
                )

            # 2. Access using revoked key or bulk export without approval
            if action == "key_use" and ev.get("status") == "revoked":
                alerts.append(
                    self._make_alert(
                        alert_type="revoked_key_attempt",
                        severity="critical",
                        identity=actor,
                        services=[service],
                        event_ids=[ev_id],
                        rule_or_path="rule:revoked_key_usage",
                        order_uncertain=uncertain,
                        detected_at=ev["event_time"],
                    )
                )

            if action == "bulk_export" and not has_approval:
                alerts.append(
                    self._make_alert(
                        alert_type="suspicious_bulk_export",
                        severity="high",
                        identity=actor,
                        services=[service],
                        event_ids=[ev_id],
                        rule_or_path="rule:unapproved_bulk_export",
                        order_uncertain=uncertain,
                        detected_at=ev["event_time"],
                    )
                )

            # 3. Graph-based lateral movement path check (even with valid credentials)
            history = [item for item in actor_paths[actor] if (ev_dt - item[0]) <= self.lateral_window]
            if history:
                prev_dt, prev_service, prev_id, prev_uncertain = history[-1]
                if prev_service != service and (prev_service, service) not in ALLOWED_SERVICE_HOPS:
                    services_seq = [h[1] for h in history] + [service]
                    event_seq = [h[2] for h in history] + [ev_id]
                    alerts.append(
                        self._make_alert(
                            alert_type="lateral_movement",
                            severity="high",
                            identity=actor,
                            services=services_seq,
                            event_ids=event_seq,
                            rule_or_path=f"graph:disallowed_hop({' -> '.join(services_seq)})",
                            order_uncertain=uncertain or prev_uncertain,
                            detected_at=ev["event_time"],
                        )
                    )

            history.append((ev_dt, service, ev_id, uncertain))
            actor_paths[actor] = history

        return alerts

    def _make_alert(
        self,
        alert_type: str,
        severity: str,
        identity: str,
        services: List[str],
        event_ids: List[str],
        rule_or_path: str,
        order_uncertain: bool,
        detected_at: str,
    ) -> Dict[str, Any]:
        alert = {
            "alert_id": f"alt-{'-'.join(event_ids)}",
            "alert_type": alert_type,
            "severity": severity,
            "identity": identity,
            "services": services,
            "event_ids": event_ids,
            "rule_or_path": rule_or_path,
            "order_uncertain": order_uncertain,
            "detected_at": detected_at,
        }
        if self.xerj_url:
            post_to_xerj(self.xerj_url, self.xerj_alert_index, alert["alert_id"], alert)
        return alert
