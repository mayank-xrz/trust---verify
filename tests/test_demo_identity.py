"""Regression tests for demo-node identity fail-closed behaviour (P1-1)."""

from __future__ import annotations

import base64
import shutil
import tempfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from demo.node.crypto_provider import MLDSASignature, SecureMessaging
from demo.node.server import create_app

CLUSTER_KEY = b"K" * 32


def _app(tmpdir: str) -> TestClient:
    return TestClient(create_app(node_id="node-b", data_dir=tmpdir, cluster_key=CLUSTER_KEY))


def test_unknown_sender_is_rejected_without_default_key() -> None:
    tmpdir = tempfile.mkdtemp(prefix="tbv_identity_")
    try:
        client = _app(tmpdir)
        # A validly-signed envelope from an identity this node never enrolled.
        attacker_signer = MLDSASignature()
        attacker_signer.generate_keypair()
        envelope = SecureMessaging("mallory").pack_envelope(
            sender_id="mallory",
            recipient_id="node-b",
            plaintext=b'{"action": "STEAL"}',
            shared_key=CLUSTER_KEY,
            signer=attacker_signer,
        )

        resp = client.post("/receive", json=envelope)
        assert resp.status_code == 403
        assert "not enrolled" in resp.json()["detail"]

        log = Path(tmpdir) / "node-b_audit.log"
        assert "UNKNOWN_SENDER_BLOCKED" in log.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_default_placeholder_keys_are_gone() -> None:
    source = Path("demo/node/server.py").read_text(encoding="utf-8")
    assert "DEFAULT-PUBKEY" not in source
    assert "DEFAULT-DEMO-SHARED-KEY" not in source
    assert "peer_public_keys[sender_id]" in source


def test_enroll_rejects_malformed_public_key() -> None:
    tmpdir = tempfile.mkdtemp(prefix="tbv_identity_")
    try:
        client = _app(tmpdir)
        resp = client.post("/enroll", json={"node_id": "node-a", "public_key_b64": "abc"})
        assert resp.status_code == 422
        assert "valid base64" in resp.json()["detail"]
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_cluster_key_env_is_required_to_be_32_bytes(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DEMO_CLUSTER_KEY_B64", base64.b64encode(b"short").decode())
    with pytest.raises(ValueError, match="32 bytes"):
        create_app(node_id="node-x", data_dir=tempfile.mkdtemp(prefix="tbv_identity_"))


def test_demo_script_generates_ephemeral_cluster_key() -> None:
    script = Path("scripts/run_demo.sh").read_text(encoding="utf-8")
    assert "DEMO_CLUSTER_KEY_B64" in script
    assert "secrets.token_bytes(32)" in script
    assert "export DEMO_CLUSTER_KEY_B64" in script
