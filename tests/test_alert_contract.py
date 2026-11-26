"""Regression tests for the alert contract (P1-6): event_id and services[]."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

import src.detector.rules as rules
from demo.node.server import create_app

BASE_NS = 1_800_000_000 * 1_000_000_000


def _event(**overrides):
    event = {
        "event_id": "evt-alert-0001",
        "timestamp_ns": BASE_NS,
        "subject": "mallory",
        "service": "api-gateway",
        "action": "ROTATE_KEY",
        "resource": "/keys/rotate",
        "status": "DENIED",
        "metadata": {"role": "user"},
    }
    event.update(overrides)
    return event


def test_privilege_alert_carries_event_id_and_services() -> None:
    alerts = rules.ContextRuleEngine().evaluate_event(_event())
    assert len(alerts) == 1
    payload = alerts[0].to_dict()
    assert payload["event_id"] == "evt-alert-0001"
    assert payload["services"] == ["api-gateway"]


def test_crypto_alert_carries_event_id_and_services() -> None:
    event = _event(
        event_id="evt-crypto-0002",
        action="RECEIVE_MESSAGE",
        resource="/receive",
        metadata={"error": "replay detected"},
    )
    alerts = rules.ContextRuleEngine().evaluate_event(event)
    crypto = [a for a in alerts if a.rule_name == "CRYPTOGRAPHIC_ATTACK_DETECTED"]
    assert len(crypto) == 1
    payload = crypto[0].to_dict()
    assert payload["event_id"] == "evt-crypto-0002"
    assert payload["services"] == ["api-gateway"]


def test_burst_alert_carries_event_id_and_services() -> None:
    engine = rules.ContextRuleEngine(burst_threshold=2, burst_window_sec=60.0)
    first = engine.evaluate_event(
        _event(event_id="evt-burst-1", action="RESOURCE_READ", resource="/brief", status="SUCCESS")
    )
    second = engine.evaluate_event(
        _event(event_id="evt-burst-2", action="RESOURCE_READ", resource="/brief", status="SUCCESS")
    )
    assert first == []
    burst = [a for a in second if a.rule_name == "ABNORMAL_FREQUENCY_BURST"]
    assert len(burst) == 1
    payload = burst[0].to_dict()
    assert payload["event_id"] == "evt-burst-2"
    assert payload["services"] == ["api-gateway"]


def test_demo_node_privilege_alert_obeys_contract(tmp_path: Path) -> None:
    client = TestClient(
        create_app(
            node_id="node-a",
            data_dir=str(tmp_path),
            cluster_key=b"k" * 32,
        )
    )
    resp = client.post("/keys/rotate", json={"role": "guest"})
    assert resp.status_code == 403

    metrics = client.get("/metrics")
    assert metrics.status_code == 200
    alerts = metrics.json()["alerts"]
    assert alerts, "expected the rejected rotation to produce an alert"
    alert = alerts[-1]
    assert alert["rule_name"] == "UNAUTHORIZED_PRIVILEGE_ELEVATION"
    assert alert["event_id"]
    assert alert["services"] == ["node-a"]
