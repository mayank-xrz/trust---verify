"""Cross-Node Revocation Broadcast & Propagation Latency Tracker."""

from __future__ import annotations

import collections
import dataclasses
import secrets
import time
from typing import Any, Dict, List, Optional, Set


@dataclasses.dataclass
class RevocationEvent:
    revocation_id: str
    key_id: str
    target_node_id: str
    revoked_by: str
    reason: str
    timestamp_ns: int
    signature_b64: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class RevocationCoordinator:
    """Manages revocation broadcasts across multi-node topology and measures propagation latency."""

    def __init__(self, node_id: str):
        self.node_id = node_id
        # revocation_id -> RevocationEvent
        self.revocation_events: Dict[str, RevocationEvent] = {}
        # key_id -> revocation_id
        self.revoked_keys: Dict[str, str] = {}
        # revocation_id -> {node_id: ack_timestamp}
        self.delivery_acks: Dict[str, Dict[str, float]] = collections.defaultdict(dict)
        # Cluster node directory
        self.cluster_nodes: Set[str] = set()

    def register_cluster_nodes(self, node_ids: List[str]) -> None:
        self.cluster_nodes.update(node_ids)

    def create_revocation(
        self,
        key_id: str,
        target_node_id: str,
        reason: str,
        signer: Optional[Any] = None,
    ) -> RevocationEvent:
        """Originates a signed revocation event."""
        rev_id = f"rev-{secrets.token_hex(8)}"
        timestamp_ns = time.time_ns()
        event = RevocationEvent(
            revocation_id=rev_id,
            key_id=key_id,
            target_node_id=target_node_id,
            revoked_by=self.node_id,
            reason=reason,
            timestamp_ns=timestamp_ns,
        )

        if signer:
            payload = f"{rev_id}:{key_id}:{target_node_id}:{timestamp_ns}".encode("utf-8")
            sig = signer.sign(payload)
            import base64
            event.signature_b64 = base64.b64encode(sig).decode("ascii")

        self.revocation_events[rev_id] = event
        self.revoked_keys[key_id] = rev_id
        # Mark local ack immediately
        self.delivery_acks[rev_id][self.node_id] = time.time()
        return event

    def receive_revocation(self, event: RevocationEvent, from_node_id: str) -> bool:
        """Processes an incoming revocation from another cluster node."""
        if event.revocation_id in self.revocation_events:
            return False  # Already processed

        self.revocation_events[event.revocation_id] = event
        self.revoked_keys[event.key_id] = event.revocation_id
        self.delivery_acks[event.revocation_id][self.node_id] = time.time()
        return True

    def acknowledge_revocation(self, revocation_id: str, acknowledging_node_id: str) -> None:
        """Records acknowledgment timestamp from a recipient node."""
        if revocation_id in self.revocation_events:
            self.delivery_acks[revocation_id][acknowledging_node_id] = time.time()

    def is_revoked(self, key_id: str) -> bool:
        """Returns True if the key is currently revoked."""
        return key_id in self.revoked_keys

    def compute_propagation_metrics(self, revocation_id: str) -> Dict[str, Any]:
        """Calculates propagation latency and cluster coverage percentage."""
        event = self.revocation_events.get(revocation_id)
        if not event:
            return {"error": "Revocation ID not found"}

        origin_time_sec = event.timestamp_ns / 1_000_000_000.0
        acks = self.delivery_acks.get(revocation_id, {})

        latencies_ms = [
            max(0.0, (ack_time - origin_time_sec) * 1000.0)
            for nid, ack_time in acks.items()
            if nid != event.revoked_by
        ]

        ack_count = len(acks)

        return {
            "revocation_id": revocation_id,
            "key_id": event.key_id,
            "total_nodes": len(self.cluster_nodes) or ack_count,
            "acknowledged_nodes": ack_count,
            "coverage_pct": (ack_count / max(1, len(self.cluster_nodes))) * 100.0 if self.cluster_nodes else 100.0,
            "min_latency_ms": min(latencies_ms) if latencies_ms else 0.0,
            "mean_latency_ms": (sum(latencies_ms) / len(latencies_ms)) if latencies_ms else 0.0,
            "max_latency_ms": max(latencies_ms) if latencies_ms else 0.0,
        }
