"""Regression tests for /readyz, auth rate limits, and the challenge sweeper (P1-7)."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path

import pytest
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select

from alembic import command
from scripts.seed_sandbox import seed_database
from src.identity_keys.api import create_app
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import b64e, ed25519_sign, generate_ed25519_keypair
from src.identity_keys.db import create_db_engine, create_session_factory
from src.identity_keys.errors import NotAuthorized
from src.identity_keys.models import AuthChallenge
from src.identity_keys.services import (
    AUTH_CHALLENGE_LIMIT_PER_WINDOW,
    CHALLENGE_RETENTION_SECONDS,
    IdentityService,
)
from src.identity_keys.tokens import TokenAuthority

REPO_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def identity_env(tmp_path: Path):
    db_url = f"sqlite+pysqlite:///{tmp_path / 'p17.db'}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    engine = create_db_engine(db_url)
    sf = create_session_factory(engine)
    clock = FakeClock()
    emitter = AuditEmitter(node_id="node-a", clock=clock)
    svc = IdentityService(sf, clock, emitter, TokenAuthority(clock))
    users = seed_database(sf, seed=42)

    pub, priv = generate_ed25519_keypair()
    start = svc.start_enrollment(user_id=users["alice"], ttl_seconds=60)
    pop = ed25519_sign(priv, start["nonce"].encode("utf-8"))
    device_id = svc.enroll_device(
        enrollment_id=start["enrollment_id"],
        nonce=start["nonce"],
        label="p17-phone",
        public_key_b64=b64e(pub),
        proof_of_possession_b64=b64e(pop),
    )["device_id"]
    return {"db_url": db_url, "sf": sf, "clock": clock, "svc": svc, "device_id": device_id}


def test_auth_challenge_is_rate_limited(identity_env) -> None:
    svc = identity_env["svc"]
    device_id = identity_env["device_id"]
    for _ in range(AUTH_CHALLENGE_LIMIT_PER_WINDOW):
        svc.issue_challenge(device_id)
    with pytest.raises(NotAuthorized, match="Rate limit exceeded") as exc:
        svc.issue_challenge(device_id)
    assert exc.value.reason_code == "RATE_LIMITED"


def test_challenge_sweeper_deletes_only_expired_rows(identity_env) -> None:
    svc = identity_env["svc"]
    clock = identity_env["clock"]
    device_id = identity_env["device_id"]
    fresh = svc.issue_challenge(device_id)
    stale = svc.issue_challenge(device_id)

    from src.identity_keys.db import tx_session

    now = clock.now()
    with tx_session(identity_env["sf"]) as session:
        row = session.get(AuthChallenge, stale["challenge_id"])
        assert row is not None
        row.expires_at = now - timedelta(seconds=CHALLENGE_RETENTION_SECONDS + 1)

    assert svc.sweep_expired_challenges(now) == 1
    with identity_env["sf"]() as session:
        remaining = {r.challenge_id for r in session.execute(select(AuthChallenge)).scalars()}
    assert remaining == {fresh["challenge_id"]}


def test_readyz_ok_when_database_and_wrap_key_are_available(
    monkeypatch: pytest.MonkeyPatch, identity_env
) -> None:
    import base64

    monkeypatch.setenv("WRAP_MASTER_KEY_B64", base64.b64encode(b"k" * 32).decode())
    client = TestClient(create_app(node_id="node-a", database_url=identity_env["db_url"]))
    resp = client.get("/readyz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ready"
    assert body["checks"] == {"database": "ok", "wrap_key": "ok"}


def test_readyz_fails_closed_without_wrap_key(
    monkeypatch: pytest.MonkeyPatch, identity_env
) -> None:
    monkeypatch.delenv("WRAP_MASTER_KEY_B64", raising=False)
    monkeypatch.delenv("WRAP_MASTER_KEY_FILE", raising=False)
    client = TestClient(create_app(node_id="node-a", database_url=identity_env["db_url"]))
    resp = client.get("/readyz")
    assert resp.status_code == 503
    assert resp.json()["checks"]["wrap_key"] == "error"
