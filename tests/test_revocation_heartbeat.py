"""Periodic revocation heartbeat and enforcement delta.

Objective 2 previously had no periodic heartbeat/poll thread: `pull_revocations()`
was manual/on-demand, so a node only converged when a push notification arrived
or an operator called it. No per-node enforcement delta was recorded either.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.models import AuditOutbox, Revocation
from src.identity_keys.revocation import NodeSyncManager

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def sync_env(tmp_path: Path):
    db_path = tmp_path / "sync.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")
    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    return {"sf": sf, "clock": clock, "emitter": emitter}


def _insert_revocation(sf, clock: FakeClock, seq: int, target: str) -> None:
    with tx_session(sf) as session:
        session.add(
            Revocation(
                revocation_id=str(uuid.uuid4()),
                target_type="device",
                target_id=target,
                user_id=None,
                revoked_by_actor="admin",
                reason_code="DEVICE_LOST",
                committed_at=clock.now(),
                commit_seq=seq,
            )
        )


def test_pull_records_enforcement_delta_and_audit(sync_env) -> None:
    sf, clock, emitter = sync_env["sf"], sync_env["clock"], sync_env["emitter"]
    _insert_revocation(sf, clock, 1, "device-1")
    _insert_revocation(sf, clock, 2, "device-2")

    manager = NodeSyncManager(sf, clock, node_id="node-b", audit_emitter=emitter)
    watermark = manager.pull_revocations()

    assert watermark == 2
    assert set(manager.enforcement_deltas) == {1, 2}
    assert all(delta >= 0.0 for delta in manager.enforcement_deltas.values())

    with tx_session(sf) as session:
        events = (
            session.execute(
                select(AuditOutbox).order_by(AuditOutbox.created_at.asc())
            )
            .scalars()
            .all()
        )
    enforced = [e.payload for e in events if e.payload.get("action") == "revocation.enforced"]
    assert len(enforced) == 2
    for payload in enforced:
        meta = payload["metadata"]
        assert meta["node_id"] == "node-b"
        assert meta["commit_seq"] in (1, 2)
        assert "delta_ms" in meta
        assert payload["target"] in ("device-1", "device-2")


def test_heartbeat_polls_without_push_and_stops(sync_env) -> None:
    sf, clock = sync_env["sf"], sync_env["clock"]
    manager = NodeSyncManager(
        sf, clock, node_id="node-c", heartbeat_interval_ms=20, audit_emitter=sync_env["emitter"]
    )
    assert manager.start_heartbeat() is True
    assert manager.heartbeat_status()["heartbeat_running"] is True

    # No manual pull and no push: the background thread must converge.
    _insert_revocation(sf, clock, 1, "device-hb")

    deadline = time.monotonic() + 3.0
    while (
        manager.heartbeat_count < 1 or manager.watermark < 1
    ) and time.monotonic() < deadline:
        time.sleep(0.01)

    assert manager.watermark == 1
    assert manager.heartbeat_count >= 1
    assert manager.last_heartbeat_at is not None
    assert manager.enforcement_deltas[1] >= 0.0

    manager.stop_heartbeat()
    assert manager.heartbeat_status()["heartbeat_running"] is False


def test_heartbeat_is_opt_in_when_interval_missing(sync_env) -> None:
    manager = NodeSyncManager(sync_env["sf"], sync_env["clock"], node_id="node-a")
    assert manager.start_heartbeat() is False
    assert manager.heartbeat_status()["heartbeat_running"] is False
