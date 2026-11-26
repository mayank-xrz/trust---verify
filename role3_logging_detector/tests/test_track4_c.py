import json
import tempfile
import unittest
from pathlib import Path

from src.audit_logger import TamperEvidentLogger, verify_log_file
from src.metrics import evaluate_detector

from src.detector import SecurityDetector


class TestTrack4Role3(unittest.TestCase):
    def test_log_injection_is_neutralized(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            logger = TamperEvidentLogger(log_path)
            logger.log_event(
                actor_id="eve\n{\"actor_id\":\"admin\"}",
                service="auth-gateway",
                action="login",
                target="note\r\ninjected",
            )
            lines = [line for line in log_path.read_text(encoding="utf-8").splitlines() if line.strip()]
            self.assertEqual(len(lines), 1)
            rec = json.loads(lines[0])
            self.assertNotIn("\n", rec["actor_id"])
            self.assertNotIn("\n", rec["target"])
            ok, count, _ = verify_log_file(log_path)
            self.assertTrue(ok)
            self.assertEqual(count, 1)

    def test_tamper_detection_catches_modified_line(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = Path(tmp) / "audit.jsonl"
            logger = TamperEvidentLogger(log_path)
            logger.log_event("alice", "auth-gateway", "login")
            logger.log_event("bob", "file-vault", "read")

            ok, _, _ = verify_log_file(log_path)
            self.assertTrue(ok)

            # Tamper with actor_id on line 1
            text = log_path.read_text(encoding="utf-8").replace("alice", "mallory")
            log_path.write_text(text, encoding="utf-8")

            ok_after, _, msg = verify_log_file(log_path)
            self.assertFalse(ok_after)
            self.assertIn("Tampered record at line 1", msg)

    def test_routine_vs_suspicious_and_lateral_movement_with_clock_skew(self):
        events = [
            {
                "event_id": "e1",
                "event_time": "2026-11-26T10:00:00Z",
                "actor_id": "admin-bob",
                "service": "auth-gateway",
                "action": "role_change",
                "privilege_before": "user",
                "privilege_after": "admin",
                "metadata": {"ticket_id": "CHG-1", "mfa_verified": "true"},
                "label": "benign",
            },
            {
                "event_id": "e2",
                "event_time": "2026-11-26T10:02:45Z",
                "actor_id": "eve",
                "service": "msg-relay",
                "action": "read",
                "privilege_before": "user",
                "privilege_after": "user",
                "metadata": {},
                "label": "malicious",
            },
            {
                # Arrives AFTER e2 even though its timestamp is 15s earlier (clock skew)
                "event_id": "e3",
                "event_time": "2026-11-26T10:02:30Z",
                "actor_id": "eve",
                "service": "backup-store",
                "action": "bulk_export",
                "privilege_before": "user",
                "privilege_after": "user",
                "metadata": {},
                "label": "malicious",
            },
        ]

        detector = SecurityDetector(max_skew_seconds=30)
        alerts = detector.analyze(events)
        alert_types = {a["alert_type"] for a in alerts}
        self.assertIn("suspicious_bulk_export", alert_types)
        self.assertIn("lateral_movement", alert_types)
        # Routine admin change with ticket + MFA should NOT alert
        self.assertFalse(any(a["identity"] == "admin-bob" for a in alerts))
        # Out-of-order skew within 2*max_skew must flag order_uncertain
        lat = [a for a in alerts if a["alert_type"] == "lateral_movement"][0]
        self.assertTrue(lat["order_uncertain"])
        self.assertEqual(lat["identity"], "eve")
        self.assertIn("backup-store", lat["services"])
        self.assertIn("msg-relay", lat["services"])

        metrics = evaluate_detector(events, alerts)
        self.assertEqual(metrics["f1"], 1.0)
        self.assertEqual(metrics["false_alerts_per_1000_benign"], 0.0)


if __name__ == "__main__":
    unittest.main()
