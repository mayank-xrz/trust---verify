"""Service-to-Service Access Graph for Lateral Movement Detection."""

from __future__ import annotations

import collections
import dataclasses
import time
from typing import Any, Dict, List, Optional, Set, Tuple


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
    """Enforces authorized service topology (DAG) and flags anomalous lateral hops."""

    def __init__(
        self,
        velocity_threshold: int = 5,
        velocity_window_sec: float = 60.0,
        clock: Any = None,
    ):
        # source_service -> Set of allowed target_services
        self.allowed_edges: Dict[str, Set[str]] = {}
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

    def allow_edge(self, source: str, target: str) -> None:
        if source not in self.allowed_edges:
            self.allowed_edges[source] = set()
        self.allowed_edges[source].add(target)

    def check_call(self, source_service: str, target_service: str, action: str = "") -> Optional[GraphViolation]:
        """Checks if service-to-service invocation is permitted by policy."""
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

        return None
