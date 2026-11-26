"""Detector Benchmark and Evaluation Test:
- Precision, Recall, F1 >= 0.90
- MTTA (Mean Time To Alert) measurement
- False Positives per 1k events
- Clock Skew tolerance
- Lateral movement graph violations
"""

import time
import unittest
from src.detector.clock_sync import ClockSyncBuffer, SkewStatus
from src.detector.rules import ContextRuleEngine
from src.detector.graph_lateral import LateralMovementGraph
from src.detector.metrics import compute_f1_mtta


class TestDetectorEval(unittest.TestCase):

    def test_detector_f1_and_mtta_benchmark(self):
        """Runs a synthetic labeled evaluation suite and verifies F1 >= 0.90 and low MTTA."""
        engine = ContextRuleEngine(burst_threshold=20)
        evaluations = []
        alert_latencies_ms = []

        base_time = 1_700_000_000.0

        # 100 Routine events (negative class) spread across distinct sessions
        for i in range(100):
            evt = {
                "event_id": f"evt-normal-{i}",
                "timestamp_ns": int((base_time + i * 2.0) * 1_000_000_000),
                "subject": f"user-{i % 25}",
                "service": "api-gateway",
                "resource": f"/items/{i}",
                "action": "GET_ITEM",
                "status": "SUCCESS",
                "metadata": {"role": "user"},
            }
            t0 = time.perf_counter()
            alerts = engine.evaluate_event(evt)
            evaluations.append({"is_attack": False, "detected": len(alerts) > 0})

        # 25 Attack events (positive class: unauthorized admin & crypto tamper)
        for i in range(25):
            is_admin_attempt = (i % 2 == 0)
            evt = {
                "event_id": f"evt-attack-{i}",
                "timestamp_ns": int((base_time + 500.0 + i) * 1_000_000_000),
                "subject": f"attacker-{i}",
                "service": "api-gateway",
                "resource": "/admin/keys/rotate" if is_admin_attempt else "/api/v1/message",
                "action": "ROTATE_KEY" if is_admin_attempt else "REPLAY_BLOCKED",
                "status": "DENIED",
                "metadata": {"role": "guest", "error": "Replay detected: duplicate message"},
            }
            t0 = time.perf_counter()
            alerts = engine.evaluate_event(evt)
            lat_ms = (time.perf_counter() - t0) * 1000.0

            is_detected = len(alerts) > 0
            evaluations.append({"is_attack": True, "detected": is_detected})
            if is_detected:
                alert_latencies_ms.append(lat_ms)

        metrics = compute_f1_mtta(evaluations, alert_latencies_ms)

        self.assertGreaterEqual(metrics.precision, 0.90, f"Precision too low: {metrics.precision}")
        self.assertGreaterEqual(metrics.recall, 0.90, f"Recall too low: {metrics.recall}")
        self.assertGreaterEqual(metrics.f1_score, 0.90, f"F1 Score must be >= 0.90, got {metrics.f1_score}")
        self.assertLess(metrics.mtta_ms, 50.0, f"MTTA too high: {metrics.mtta_ms} ms")
        self.assertEqual(metrics.false_alerts_per_1k, 0.0)

    def test_clock_skew_buffering_and_uncertainty(self):
        """Verify clock sync buffer attaches uncertainty flags and sorts out-of-order events."""
        buffer = ClockSyncBuffer(hold_window_seconds=0.01, max_skew_ms=1000.0, uncertainty_skew_ms=300.0)
        now_ns = time.time_ns()

        # Event 1: Normal timing
        e1 = buffer.ingest({"event_id": "e1", "timestamp_ns": now_ns + 10_000_000})
        # Event 2: Older event arriving later (out of order)
        e2 = buffer.ingest({"event_id": "e2", "timestamp_ns": now_ns - 50_000_000})
        # Event 3: Skewed event (+1500 ms)
        e3 = buffer.ingest({"event_id": "e3", "timestamp_ns": now_ns + 1_500_000_000})

        self.assertEqual(e1.skew_status, SkewStatus.NORMAL)
        self.assertEqual(e3.skew_status, SkewStatus.CLOCK_SKEW_EXCEEDED)

        time.sleep(0.02)
        popped = buffer.pop_ready_events(force_all=True)
        # Ensure chronological order was restored
        self.assertEqual([e.event_id for e in popped], ["e2", "e1", "e3"])

    def test_lateral_movement_policy(self):
        """Verify lateral movement graph blocks unauthorized microservice calls."""
        graph = LateralMovementGraph()

        # Authorized call: gateway -> node-1
        self.assertIsNone(graph.check_call("api-gateway", "node-1"))

        # Unauthorized lateral hop: audit-service -> node-2 (sink initiating outbound call)
        viol = graph.check_call("audit-service", "node-2")
        self.assertIsNotNone(viol)
        self.assertIn("Unauthorized lateral movement", viol.reason)


if __name__ == "__main__":
    unittest.main()
