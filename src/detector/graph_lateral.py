"""Service-to-Service Access Graph for Lateral Movement & In-Edge Anomaly Detection."""

from __future__ import annotations

import collections
import dataclasses
import time
from typing import Any, Dict, List, Optional, Set, Tuple

HIGH_RISK_ACTION_KEYWORDS = (
    "DUMP",
    "EXFILTRATE",
    "EXPORT_SECRET",
    "PURGE_LOG",
    "DISABLE_AUDIT",
    "BYPASS",
)


@dataclasses.dataclass
class GraphViolation:
    violation_id: str
    source_service: str
    target_service: str
    action: str
    reason: str
    timestamp_ns: int
    identity: str = ""
    services: List[str] = dataclasses.field(default_factory=list)
    event_ids: List[str] = dataclasses.field(default_factory=list)
    rule_id: str = ""
    velocity: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        data = dataclasses.asdict(self)
        # Only include the velocity block when the hop-velocity window fired.
        if data.get("velocity") is None:
            data.pop("velocity", None)
        return data


class LateralMovementGraph:
    """Enforces authorized service topology (DAG), per-edge action policies, and identity hop velocity."""

    def __init__(
        self,
        velocity_threshold: int = 5,
        velocity_window_sec: float = 60.0,
        clock: Any = None,
        hop_window_sec: float = 10.0,
        max_distinct_targets: int = 3,
    ):
        # source_service -> Set of allowed target_services
        self.allowed_edges: Dict[str, Set[str]] = {}
        # (source_service, target_service) -> Set of allowed actions (if specified)
        self.allowed_edge_actions: Dict[Tuple[str, str], Set[str]] = {}
        # Dynamic tracking of observed edges: (src, dst) -> count
        self.observed_edges: Dict[Tuple[str, str], int] = {}
        self.velocity_threshold = velocity_threshold
        self.velocity_window_sec = velocity_window_sec
        self._clock = clock or time.time_ns
        # identity -> deque[(timestamp_ns, event_id, target_service)]
        self._violation_history: Dict[str, collections.deque] = collections.defaultdict(
            collections.deque
        )
        self._hop_seq = 0
        # Identity hop tracking: identity -> deque of (ts_sec, target_service)
        self.hop_window_sec = hop_window_sec
        self.max_distinct_targets = max_distinct_targets
        self.identity_hops: Dict[str, collections.deque] = collections.defaultdict(collections.deque)
        self._set_default_topology()

    def _set_default_topology(self) -> None:
        """Sets standard microservice boundary policy."""
        self.allowed_edges = {
            "api-gateway": {"auth-service", "node-1", "node-2", "node-a", "node-b", "node-c", "detector-service"},
            "auth-service": {"key-store", "audit-service"},
            "node-1": {"node-2", "audit-service", "key-store"},
            "node-2": {"node-1", "audit-service", "key-store"},
            "node-a": {"node-b", "node-c", "audit-service", "key-authority", "detector"},
            "node-b": {"node-a", "node-c", "audit-service", "key-authority", "detector"},
            "node-c": {"node-a", "node-b", "audit-service", "key-authority", "detector"},
            "detector-service": {"audit-service"},
            "key-store": {"audit-service"},
            "audit-service": set(),  # Sink: does not initiate downstream service calls
        }
        self.allowed_edge_actions = {
            ("node-a", "key-authority"): {"VERIFY_KEY", "CHECK_REVOCATION", "GET_PUBLIC_KEY", "ROTATE_KEY"},
            ("node-b", "key-authority"): {"VERIFY_KEY", "CHECK_REVOCATION", "GET_PUBLIC_KEY", "ROTATE_KEY"},
            ("node-c", "key-authority"): {"VERIFY_KEY", "CHECK_REVOCATION", "GET_PUBLIC_KEY", "ROTATE_KEY"},
        }

    def allow_edge(self, source: str, target: str, allowed_actions: Optional[Set[str]] = None) -> None:
        if source not in self.allowed_edges:
            self.allowed_edges[source] = set()
        self.allowed_edges[source].add(target)
        if allowed_actions is not None:
            self.allowed_edge_actions[(source, target)] = set(allowed_actions)

    def check_call(
        self,
        source_service: str,
        target_service: str,
        action: str = "",
        identity: str = "",
        timestamp_sec: Optional[float] = None,
    ) -> Optional[GraphViolation]:
        """Checks topology, per-edge action policy, high-risk in-edge actions, and identity hop velocity."""
        edge = (source_service, target_service)
        self.observed_edges[edge] = self.observed_edges.get(edge, 0) + 1

        allowed_targets = self.allowed_edges.get(source_service)
        if allowed_targets is None or target_service not in allowed_targets:
            now_ns = int(self._clock())
            self._hop_seq += 1
            violation_id = f"viol-{source_service[:4]}-{target_service[:4]}"
            event_id = f"{violation_id}#{self._hop_seq}"

            history = self._violation_history[source_service]
            history.append((now_ns, event_id, target_service))
            window_ns = int(self.velocity_window_sec * 1_000_000_000)
            while history and now_ns - history[0][0] > window_ns:
                history.popleft()

            velocity = None
            if len(history) >= self.velocity_threshold:
                velocity = {
                    "hop_count": len(history),
                    "threshold": self.velocity_threshold,
                    "window_sec": self.velocity_window_sec,
                }

            services = sorted({source_service} | {target for _, _, target in history})
            event_ids = [eid for _, eid, _ in history]
            rule_id = "LATERAL_MOVEMENT_VELOCITY" if velocity else "UNAUTHORIZED_LATERAL_HOP"
            reason = (
                f"Unauthorized lateral movement path: '{source_service}' is not authorized "
                f"to call '{target_service}'"
            )
            if velocity:
                reason += (
                    f"; hop velocity {velocity['hop_count']} in "
                    f"{self.velocity_window_sec}s exceeds threshold {self.velocity_threshold}"
                )

            return GraphViolation(
                violation_id=violation_id,
                source_service=source_service,
                target_service=target_service,
                action=action,
                reason=reason,
                timestamp_ns=now_ns,
                identity=source_service,
                services=services,
                event_ids=event_ids,
                rule_id=rule_id,
                velocity=velocity,
            )

        if action:
            upper_act = action.upper()
            if any(kw in upper_act for kw in HIGH_RISK_ACTION_KEYWORDS):
                return GraphViolation(
                    violation_id=f"viol-act-{source_service[:4]}-{target_service[:4]}",
                    source_service=source_service,
                    target_service=target_service,
                    action=action,
                    reason=f"Suspicious high-risk action '{action}' detected within established edge {source_service} -> {target_service}.",
                    timestamp_ns=time.time_ns(),
                )
            edge_actions = self.allowed_edge_actions.get(edge)
            if edge_actions is not None and action not in edge_actions:
                return GraphViolation(
                    violation_id=f"viol-pol-{source_service[:4]}-{target_service[:4]}",
                    source_service=source_service,
                    target_service=target_service,
                    action=action,
                    reason=f"Disallowed action '{action}' on established edge {source_service} -> {target_service}.",
                    timestamp_ns=time.time_ns(),
                )

        if identity:
            now = time.time() if timestamp_sec is None else timestamp_sec
            dq = self.identity_hops[identity]
            dq.append((now, target_service))
            while dq and (now - dq[0][0] > self.hop_window_sec):
                dq.popleft()
            distinct_targets = {tgt for _, tgt in dq}
            if len(distinct_targets) >= self.max_distinct_targets:
                return GraphViolation(
                    violation_id=f"viol-hop-{identity[:6]}",
                    source_service=source_service,
                    target_service=target_service,
                    action=action,
                    reason=(
                        f"Anomalous in-edge hop velocity for '{identity}': "
                        f"reached {len(distinct_targets)} distinct services within {self.hop_window_sec}s."
                    ),
                    timestamp_ns=time.time_ns(),
                )
        return None
