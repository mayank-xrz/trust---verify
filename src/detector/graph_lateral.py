"""Service-to-Service Access Graph for Lateral Movement Detection."""

from __future__ import annotations
import dataclasses
import time
from typing import Dict, Any, Set, List, Optional, Tuple


@dataclasses.dataclass
class GraphViolation:
    violation_id: str
    source_service: str
    target_service: str
    action: str
    reason: str
    timestamp_ns: int

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class LateralMovementGraph:
    """Enforces authorized service topology (DAG) and flags anomalous lateral hops."""

    def __init__(self):
        # source_service -> Set of allowed target_services
        self.allowed_edges: Dict[str, Set[str]] = {}
        # Dynamic tracking of observed edges: (src, dst) -> count
        self.observed_edges: Dict[Tuple[str, str], int] = {}
        self._set_default_topology()

    def _set_default_topology(self) -> None:
        """Sets standard microservice boundary policy."""
        self.allowed_edges = {
            "api-gateway": {"auth-service", "node-1", "node-2", "detector-service"},
            "auth-service": {"key-store", "audit-service"},
            "node-1": {"node-2", "audit-service", "key-store"},
            "node-2": {"node-1", "audit-service", "key-store"},
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
            return GraphViolation(
                violation_id=f"viol-{source_service[:4]}-{target_service[:4]}",
                source_service=source_service,
                target_service=target_service,
                action=action,
                reason=f"Unauthorized lateral movement path: '{source_service}' is not authorized to call '{target_service}'",
                timestamp_ns=time.time_ns(),
            )

        return None
