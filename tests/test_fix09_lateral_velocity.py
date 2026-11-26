"""FIX-09 regression tests: lateral hop-velocity aggregation.

Objective 7 previously had no hop-velocity window, and `GraphViolation` lacked
the required `identity`, `services`, `event_ids`, and `rule_id` fields.
"""

from __future__ import annotations

import src.detector.graph_lateral as gl


def test_velocity_window_aggregates_disallowed_hops() -> None:
    now = [0]

    def clock() -> int:
        return now[0]

    graph = gl.LateralMovementGraph(
        velocity_threshold=5, velocity_window_sec=60.0, clock=clock
    )

    violations = []
    for i in range(5):
        now[0] += 1_000_000_000  # 1s apart, all inside 60s
        violation = graph.check_call("node-a", f"rogue-{i}", "lateral")
        assert violation is not None
        violations.append(violation)

    for violation in violations:
        data = violation.to_dict()
        assert {"identity", "services", "event_ids", "rule_id"}.issubset(data.keys())
        assert data["identity"] == "node-a"
        assert data["rule_id"] in ("UNAUTHORIZED_LATERAL_HOP", "LATERAL_MOVEMENT_VELOCITY")

    last = violations[-1].to_dict()
    assert last["rule_id"] == "LATERAL_MOVEMENT_VELOCITY"
    assert last["velocity"]["hop_count"] == 5
    assert set(last["services"]) == {"node-a", "rogue-0", "rogue-1", "rogue-2", "rogue-3", "rogue-4"}
    assert len(last["event_ids"]) == 5


def test_hops_outside_window_do_not_aggregate() -> None:
    now = [0]

    def clock() -> int:
        return now[0]

    graph = gl.LateralMovementGraph(
        velocity_threshold=5, velocity_window_sec=10.0, clock=clock
    )

    for i in range(5):
        now[0] += 20_000_000_000  # 20s apart, always outside the 10s window
        violation = graph.check_call("node-b", f"rogue-{i}", "lateral")
        assert violation is not None
        assert violation.velocity is None
        assert violation.rule_id == "UNAUTHORIZED_LATERAL_HOP"


def test_allowed_edge_returns_no_violation() -> None:
    graph = gl.LateralMovementGraph(clock=lambda: 0)
    assert graph.check_call("node-a", "node-b", "replicate") is None


def test_velocity_only_counts_disallowed_hops() -> None:
    now = [0]

    def clock() -> int:
        return now[0]

    graph = gl.LateralMovementGraph(
        velocity_threshold=3, velocity_window_sec=60.0, clock=clock
    )
    for _ in range(10):
        now[0] += 1_000_000_000
        assert graph.check_call("node-a", "node-b", "replicate") is None

    now[0] += 1_000_000_000
    violation = graph.check_call("node-a", "database", "read")
    assert violation is not None
    assert violation.velocity is None
    assert violation.event_ids == [violation.event_ids[0]]
