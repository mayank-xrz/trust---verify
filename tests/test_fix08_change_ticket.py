"""FIX-08 regression tests: approved change-ticket suppression.

Objective 6 previously had no change-ticket/window concept: an approved
deploy bot rotating a key was alerted as `UNAUTHORIZED_PRIVILEGE_ELEVATION`.
"""

from __future__ import annotations

import src.detector.rules as rules

BASE_NS = 1_800_000_000 * 1_000_000_000


def _rotate_event(*, subject: str = "deploy-bot", metadata=None, ts: int = BASE_NS):
    return {
        "event_id": "evt-change-1",
        "timestamp_ns": ts,
        "subject": subject,
        "service": "api-gateway",
        "action": "ROTATE_KEY",
        "resource": "/keys/rotate",
        "status": "SUCCESS",
        "metadata": metadata or {},
    }


def test_approved_change_ticket_suppresses_privilege_alert() -> None:
    engine = rules.ContextRuleEngine()
    alerts = engine.evaluate_event(
        _rotate_event(metadata={"role": "user", "change_ticket": "CHG-1234", "change_window": "approved"})
    )
    assert alerts == []


def test_missing_or_unapproved_ticket_still_alerts() -> None:
    engine = rules.ContextRuleEngine()
    no_ticket = engine.evaluate_event(_rotate_event(metadata={"role": "user"}))
    assert [a.rule_name for a in no_ticket] == ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]

    pending = engine.evaluate_event(
        _rotate_event(metadata={"role": "user", "change_ticket": "CHG-9", "change_window": "pending"})
    )
    assert [a.rule_name for a in pending] == ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]


def test_registry_validates_ticket_owner_and_window() -> None:
    registry = rules.ChangeTicketRegistry(
        [
            rules.ChangeTicket(
                ticket_id="CHG-OK",
                subject="deploy-bot",
                not_before_ns=BASE_NS - 1000,
                not_after_ns=BASE_NS + 1000,
            )
        ]
    )
    engine = rules.ContextRuleEngine(change_tickets=registry)

    covered = engine.evaluate_event(
        _rotate_event(metadata={"role": "user", "change_ticket": "CHG-OK", "change_window": "active"})
    )
    assert covered == []

    # Same ticket, wrong owner -> not covered.
    wrong_owner = engine.evaluate_event(
        _rotate_event(
            subject="mallory",
            metadata={"role": "user", "change_ticket": "CHG-OK", "change_window": "active"},
        )
    )
    assert [a.rule_name for a in wrong_owner] == ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]

    # Unknown ticket -> not covered.
    unknown = engine.evaluate_event(
        _rotate_event(metadata={"role": "user", "change_ticket": "CHG-UNKNOWN", "change_window": "approved"})
    )
    assert [a.rule_name for a in unknown] == ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]

    # Expired window -> not covered.
    expired = engine.evaluate_event(
        _rotate_event(
            ts=BASE_NS + 5000,
            metadata={"role": "user", "change_ticket": "CHG-OK", "change_window": "approved"},
        )
    )
    assert [a.rule_name for a in expired] == ["UNAUTHORIZED_PRIVILEGE_ELEVATION"]


def test_change_window_does_not_suppress_crypto_attack() -> None:
    engine = rules.ContextRuleEngine()
    event = _rotate_event(
        metadata={
            "role": "user",
            "change_ticket": "CHG-1234",
            "change_window": "approved",
            "error": "REPLAY_DETECTED",
        }
    )
    event["status"] = "DENIED"
    alerts = engine.evaluate_event(event)
    assert [a.rule_name for a in alerts] == ["CRYPTOGRAPHIC_ATTACK_DETECTED"]
