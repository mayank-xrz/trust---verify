"""Regression scenarios for detector decisions, timing and policy boundaries."""

import time
import unittest

from src.detector.clock_sync import ClockSyncBuffer, SkewStatus
from src.detector.graph_lateral import LateralMovementGraph
from src.detector.metrics import compute_f1_mtta
from src.detector.rules import ChangeTicket, ChangeTicketRegistry, ContextRuleEngine


class TestDetectorEval(unittest.TestCase):

    def test_mixed_operational_trace(self):
        base_ns = 1_800_000_000 * 1_000_000_000
        second = 1_000_000_000
        tickets = ChangeTicketRegistry([
            ChangeTicket("CHG-42", "deploy-bot", base_ns, base_ns + 60 * second),
        ])
        engine = ContextRuleEngine(change_tickets=tickets)
        change = {"role": "user", "change_ticket": "CHG-42", "change_window": "approved"}

        def event(offset, subject, resource, action, status="SUCCESS", metadata=None):
            return {
                "event_id": f"event-{offset}-{subject}",
                "timestamp_ns": base_ns + offset * second,
                "subject": subject,
                "service": "api-gateway",
                "resource": resource,
                "action": action,
                "status": status,
                "metadata": metadata or {},
            }

        # Interleave activity that shares the same routes, actions and identities.
        # Each label identifies the expected rule at that point in the trace.
        trace = [
            ("approved maintenance", event(5, "deploy-bot", "/keys/rotate", "ROTATE_KEY",
                                          metadata=change), []),
            ("copied ticket", event(6, "worker", "/keys/rotate", "ROTATE_KEY", "DENIED", change),
             ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]),
            ("ordinary denial", event(9, "worker", "/receive", "RECEIVE", "DENIED",
                                      {"error": "Credential expired"}), []),
            ("message replay", event(12, "worker", "/receive", "RECEIVE", "DENIED",
                                     {"error": "Duplicate message"}), ["CRYPTOGRAPHIC_ATTACK_DETECTED"]),
            ("first sensitive read", event(15, "reader", "/keys/export", "EXPORT_KEY"), []),
            ("authorized peer traffic", event(35, "peer", "/receive", "RECEIVE"), []),
            ("second sensitive read", event(45, "reader", "/keys/export", "EXPORT_KEY"), []),
            ("expired maintenance window", event(61, "deploy-bot", "/keys/rotate", "ROTATE_KEY",
                                                 "DENIED", change), ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]),
            ("third sensitive read", event(85, "reader", "/keys/export", "EXPORT_KEY"), []),
            ("isolated sensitive read", event(95, "peer", "/keys/export", "EXPORT_KEY"), []),
            ("low-and-slow threshold", event(125, "reader", "/keys/export", "EXPORT_KEY"),
             ["LOW_AND_SLOW_SENSITIVE_ACCESS"]),
            ("sensitive history expired", event(450, "reader", "/keys/export", "EXPORT_KEY"), []),
        ]
        for label, audit_event, expected_rules in trace:
            with self.subTest(label=label):
                alerts = engine.evaluate_event(audit_event)
                self.assertEqual([alert.rule_name for alert in alerts], expected_rules)
                for alert in alerts:
                    self.assertEqual(alert.subject, audit_event["subject"])
                    self.assertEqual(alert.resource, audit_event["resource"])

    def test_median_and_false_alerts_per_benign_event(self):
        metrics = compute_f1_mtta(
            [{"is_attack": False, "detected": True}, {"is_attack": True, "detected": True}],
            [1, 2, 100],
        )
        self.assertEqual(metrics.median_time_to_alert_ms, 2)
        self.assertEqual(metrics.false_alerts_per_1k, 1000)

    def test_clock_skew_buffering_and_uncertainty(self):
        """Verify clock sync buffer attaches uncertainty flags and sorts out-of-order events."""
        buffer = ClockSyncBuffer(hold_window_seconds=0.01, max_skew_ms=1000.0, uncertainty_skew_ms=300.0)
        now_ns = time.time_ns()

        # Event 1: Normal timing
        e1 = buffer.ingest({"event_id": "e1", "timestamp_ns": now_ns + 10_000_000})
        # Event 2: Older event arriving later (out of order)
        _e2 = buffer.ingest({"event_id": "e2", "timestamp_ns": now_ns - 50_000_000})
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
