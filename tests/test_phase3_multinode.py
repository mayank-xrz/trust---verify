"""Phase 3 tests: Three-node consistency, /healthz, /node/status, and protected_read."""

from __future__ import annotations

import uuid
from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient

from scripts.measure_revocation import run_scenario
from scripts.seed_sandbox import seed_database
from src.identity_keys.api import create_app
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import (
    b64d,
    b64e,
    ed25519_sign,
    generate_ed25519_keypair,
    hmac_sha256_hex,
)
from src.identity_keys.db import create_db_engine, create_session_factory
from track4_service import dispatch

REPO_ROOT = Path(__file__).resolve().parent.parent


def test_three_nodes_status_and_consistent_authorization(tmp_path: Path, monkeypatch) -> None:
    db_path = tmp_path / "three_nodes.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    users = seed_database(sf, seed=42)
    clock = FakeClock()

    # Share deterministic token signing seed across all 3 nodes
    _, seed_priv = generate_ed25519_keypair()
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", b64e(seed_priv))
    # Enrollment is admin-gated (P0-1); this multi-node test uses the admin path.
    monkeypatch.setenv("ADMIN_ENROLL_TOKEN", "multi-node-admin-token")
    admin_headers = {"X-Admin-Enroll-Token": "multi-node-admin-token"}

    clients = {
        nid: TestClient(create_app(node_id=nid, database_url=db_url, clock=clock))
        for nid in ("node-a", "node-b", "node-c")
    }

    for nid, client in clients.items():
        assert client.get("/healthz").json()["status"] == "ok"
        st = client.get("/node/status").json()
        assert st["node_id"] == nid
        assert st["status"] == "online"

    # Enroll device on node-a, verify on node-b, authorize on all 3 nodes
    pub, priv = generate_ed25519_keypair()
    start = clients["node-a"].post(
        f"/api/v1/enroll/start?user_id={users['alice']}", headers=admin_headers
    ).json()
    pop = ed25519_sign(priv, start["nonce"].encode("utf-8"))
    dev = clients["node-a"].post(
        "/api/v1/enroll",
        headers=admin_headers,
        json={
            "enrollment_id": start["enrollment_id"],
            "nonce": start["nonce"],
            "label": "alice-multi",
            "public_key_b64": b64e(pub),
            "proof_of_possession_b64": b64e(pop),
        },
    ).json()

    ch = clients["node-b"].post(f"/api/v1/auth/challenge?device_id={dev['device_id']}").json()
    sig = ed25519_sign(priv, ch["challenge"].encode("utf-8"))
    tok = clients["node-b"].post(
        "/api/v1/auth/verify",
        json={"device_id": dev["device_id"], "challenge": ch["challenge"], "signature_b64": b64e(sig)},
    ).json()["access_token"]

    decisions = [
        client.post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        ).json()["allowed"]
        for client in clients.values()
    ]
    assert decisions == [True, True, True]


def test_revocation_benchmark_measures_denial_and_sync_on_every_node() -> None:
    result = run_scenario(name="smoke", m_runs=1, push_sync=True, pull_interval_ms=250, seed=42)

    assert set(result["per_node"]) == {"node-a", "node-b", "node-c"}
    for per_node, last_node in (("per_node", "overall_last_node"), ("watermark_per_node", "watermark_last_node")):
        assert all(sample["count"] == 1 for sample in result[per_node].values())
        assert result[last_node]["max_ms"] == max(
            sample["max_ms"] for sample in result[per_node].values()
        )


def test_adapter_protected_read_ml_kem_768(tmp_path: Path, monkeypatch) -> None:
    import pqcrypto.kem.ml_kem_768 as ml_kem

    monkeypatch.setenv("TRACK4_STATE_DIR", str(tmp_path))
    assert dispatch({
        "op": "setup",
        "owners": {"brief": "maya"},
        "contents": {"brief": "demo note"},
        "disabled": [],
        "key_material": "synthetic-only",
    }) == {"ready": True}

    pk, sk = ml_kem.keygen() if hasattr(ml_kem, "keygen") else ml_kem.generate_keypair()
    challenge = str(uuid.uuid4())
    res = dispatch({
        "op": "protected_read",
        "actor": "maya",
        "asset": "brief",
        "challenge": challenge,
        "public_key": b64e(pk),
    })
    ct = b64d(res["ciphertext"])
    ss = ml_kem.decaps(sk, ct) if hasattr(ml_kem, "decaps") else ml_kem.decrypt(sk, ct)
    assert res["proof"] == hmac_sha256_hex(ss, (challenge + "demo note").encode("utf-8"))
