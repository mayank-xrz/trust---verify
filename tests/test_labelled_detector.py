from scripts.evaluate_detector import CHALLENGE, evaluate
from src.detector.rules import ContextRuleEngine


def test_labelled_detector_metrics():
    result = evaluate()
    assert result.true_negatives + result.false_positives >= 1000
    assert result.true_positives + result.false_negatives >= 30
    assert result.f1_score >= 0.95
    assert result.median_time_to_alert_ms < 50
    assert result.false_alerts_per_1k <= 1


def test_recent_stale_key_context_and_repeat():
    engine = ContextRuleEngine()
    event = {
        "event_id": "stale-1", "subject": "alice", "service": "node-b",
        "status": "DENIED", "action": "RECEIVE", "metadata": {
            "error": "Recipient key is expired", "recipient_key_state": "expired",
            "seconds_since_cutoff": 0.1, "authenticated_sender": True,
            "source_service": "node-a", "target_service": "node-b",
        },
    }
    alert, = engine.evaluate_event(event)
    assert alert.severity == "LOW"
    assert alert.evidence["identity"] == "alice"
    assert alert.evidence["services"] == ["node-a", "node-b"]
    assert alert.evidence["event_ids"] == ["stale-1"]
    assert alert.evidence["rule_id"] == "RECENT_ROTATION_STALE_KEY"
    assert engine.evaluate_event(event)[0].severity == "HIGH"
    event["metadata"]["recipient_key_state"] = "revoked"
    event["metadata"]["error"] = "Recipient key is revoked"
    assert ContextRuleEngine().evaluate_event(event)[0].severity == "HIGH"


def test_archive_export_rule_distinguishes_entitlement_context():
    rule = "UNAUTHORIZED_REPORT_ARCHIVE_EXPORT"
    event = {
        "event_id": "archive-1",
        "action": "DOWNLOAD_REPORT_ARCHIVE",
        "status": "SUCCESS",
        "subject": "operator",
        "resource": "/reports/archive",
    }
    engine = ContextRuleEngine()
    for metadata in ({}, {"archive_export_authorized": True}):
        assert not engine.evaluate_event({**event, "metadata": metadata})
    alert, = engine.evaluate_event({**event, "metadata": {"archive_export_authorized": False}})
    assert alert.evidence["rule_id"] == rule
    assert not ContextRuleEngine().evaluate_event({
        **event, "status": "DENIED", "metadata": {"archive_export_authorized": False},
    })


def test_contextual_challenge_preserves_non_low_false_positive_rate():
    result = evaluate(CHALLENGE)
    assert result.true_positives == 36
    assert result.false_negatives == 0
    assert result.false_positives == 0
