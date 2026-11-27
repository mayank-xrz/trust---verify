import secrets

import pytest
from fastapi.testclient import TestClient

from demo.node.server import create_app
from src.identity_keys.api import create_app as create_identity_app


@pytest.mark.parametrize(("path", "body"), [
    ("/lifecycle/rotate", {}),
    ("/lifecycle/revoke-and-reenroll", {}),
    ("/resilience/crash-recovery", {}),
    ("/resilience/backup", {}),
    ("/audit/tamper", {}),
])
def test_sandbox_actions_require_flag_and_operator(tmp_path, monkeypatch, path, body):
    token = secrets.token_urlsafe(32)
    headers = {"Authorization": f"Bearer {token}"}
    path = "/api/sandbox" + path
    monkeypatch.delenv("DEMO_SANDBOX_ENABLED", raising=False)
    with TestClient(create_app(data_dir=str(tmp_path / "off"), operator_token=token)) as client:
        assert client.post(path, json=body, headers=headers).status_code == 404
        assert client.get("/api/sandbox/state", headers=headers).status_code == 404

    monkeypatch.setenv("DEMO_SANDBOX_ENABLED", "1")
    with TestClient(create_app(data_dir=str(tmp_path / "on"), operator_token=token)) as client:
        assert client.post(path, json=body).status_code == 401
        assert client.get("/api/sandbox/state").status_code == 401
        assert client.get("/api/sandbox/state", headers=headers).status_code == 200
        assert client.post(path, json=body, headers=headers).status_code == 200


def test_demo_operator_routes_and_security_headers(tmp_path):
    operator = secrets.token_urlsafe(32)
    peer = secrets.token_urlsafe(32)
    headers = {"Authorization": f"Bearer {operator}"}
    app = create_app(data_dir=str(tmp_path), operator_token=operator, peer_enroll_token=peer)
    with TestClient(app) as client:
        for path in ("/api/info", "/metrics", "/logs/verify"):
            assert client.get(path).status_code == 401
        assert client.get("/logs/verify", headers=headers).status_code == 200
        assert client.get("/metrics", headers=headers).status_code == 200
        assert client.get("/api/info", headers=headers).status_code == 200
        for path, payload in (("/enroll", {"node_id": "node-b"}), ("/send", {"recipient_id": "node-a", "payload": {}})):
            response = client.post(path, json=payload)
            assert response.status_code == 401
            assert client.post(path, json=payload, headers={"Authorization": f"Bearer {peer}"}).status_code == 401
            assert response.headers["X-Content-Type-Options"] == "nosniff"
            assert response.headers["X-Frame-Options"] == "DENY"
            assert response.headers["Referrer-Policy"] == "no-referrer"
            assert response.headers["Cache-Control"] == "no-store"
        assert client.post("/enroll", json={"node_id": "node-b"}, headers=headers).status_code == 200
        assert client.get("/").status_code == 200


def test_arm_crash_requires_sandbox_mode_and_authentication(tmp_path, monkeypatch):
    app = create_identity_app(database_url=f"sqlite+pysqlite:///{tmp_path / 'identity.db'}")
    token = app.state.token_authority.issue("test-actor", "test-device")
    headers = {"Authorization": f"Bearer {token}"}
    path = "/internal/test/arm-crash"
    with TestClient(app) as client:
        monkeypatch.delenv("SANDBOX_MODE", raising=False)
        assert client.post(path, json={}, headers=headers).status_code == 404
        monkeypatch.setenv("SANDBOX_MODE", "1")
        assert client.post(path, json={}).status_code == 401
        assert client.post(path, json={}, headers=headers).status_code == 403
        crash_token = secrets.token_urlsafe(32)
        monkeypatch.setenv("SANDBOX_CRASH_TOKEN", crash_token)
        assert client.post(path, json={}, headers=headers).status_code == 403
        assert client.post(
            path, json={}, headers={**headers, "X-Sandbox-Crash-Token": crash_token}
        ).status_code == 200
