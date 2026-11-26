"""Regression tests for the admin + sandbox gate on arm-crash (P1-3)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from src.identity_keys.api import create_app

ADMIN_TOKEN = "test-admin-token"
HEADERS = {"X-Admin-Enroll-Token": ADMIN_TOKEN}


def _client(monkeypatch: pytest.MonkeyPatch, *, sandbox: bool) -> TestClient:
    monkeypatch.setenv("ADMIN_ENROLL_TOKEN", ADMIN_TOKEN)
    if sandbox:
        monkeypatch.setenv("SANDBOX_MODE", "1")
    else:
        monkeypatch.delenv("SANDBOX_MODE", raising=False)
    return TestClient(create_app(node_id="node-a", database_url="sqlite+pysqlite:///:memory:"))


def test_arm_crash_requires_sandbox_mode(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, sandbox=False)
    resp = client.post("/internal/test/arm-crash", json={"crash_point": None}, headers=HEADERS)
    assert resp.status_code == 403
    assert "SANDBOX_MODE" in resp.json()["detail"]


def test_arm_crash_requires_admin_token(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, sandbox=True)
    assert client.post("/internal/test/arm-crash", json={"crash_point": None}).status_code == 401
    wrong = {"X-Admin-Enroll-Token": "wrong"}
    assert client.post("/internal/test/arm-crash", json={"crash_point": None}, headers=wrong).status_code == 401


def test_arm_crash_admin_token_fails_closed_when_env_unset(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, sandbox=True)
    monkeypatch.delenv("ADMIN_ENROLL_TOKEN", raising=False)
    assert client.post("/internal/test/arm-crash", json={"crash_point": None}, headers=HEADERS).status_code == 401


def test_arm_crash_admin_in_sandbox_can_arm(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, sandbox=True)
    resp = client.post("/internal/test/arm-crash", json={"crash_point": None}, headers=HEADERS)
    assert resp.status_code == 200
    assert resp.json() == {"armed": None}


def test_arm_crash_rejects_unknown_point(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _client(monkeypatch, sandbox=True)
    resp = client.post(
        "/internal/test/arm-crash",
        json={"crash_point": "not.a.real.point"},
        headers=HEADERS,
    )
    assert resp.status_code == 403
    assert "Unknown crash point" in resp.json()["detail"]
