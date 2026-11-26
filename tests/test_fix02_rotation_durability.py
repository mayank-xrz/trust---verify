"""FIX-02 regression tests: durable rotation journal and retry after abort."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import select

from scripts.seed_sandbox import seed_database
from src.identity_keys import rotation as rotation_module
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import b64e
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.errors import Conflict
from src.identity_keys.models import KeyVersion, Rotation
from src.identity_keys.rotation import RotationService
from src.identity_keys.tokens import ActorContext

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fix02_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WRAP_MASTER_KEY_B64", b64e(os.urandom(32)))
    monkeypatch.setenv("CLUSTER_SYNC_SECRET", "fix02-cluster-secret")
    db_url = f"sqlite+pysqlite:///{tmp_path / 'fix02.db'}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    svc = RotationService(sf, clock, emitter, node_id="node-a")
    svc.create_initial_key_set("ks-auth", "auth")
    admin_ctx = ActorContext(users["carol"], "dev-carol", "jti-admin")
    return {
        "db_url": db_url,
        "sf": sf,
        "clock": clock,
        "emitter": emitter,
        "svc": svc,
        "admin_ctx": admin_ctx,
        "users": users,
    }


def _crash_after_pending(env) -> None:
    script = (
        "from src.identity_keys.db import create_db_engine, create_session_factory; "
        "from src.identity_keys.clock import SystemClock; "
        "from src.identity_keys.audit_outbox import AuditEmitter; "
        "from src.identity_keys.rotation import RotationService; "
        "from src.identity_keys.tokens import ActorContext; "
        f"sf = create_session_factory(create_db_engine({env['db_url']!r})); "
        "c = SystemClock(); e = AuditEmitter('node-a', c); "
        "r = RotationService(sf, c, e, 'node-a'); "
        "r.create_initial_key_set('ks-auth', 'auth'); "
        f"r.initiate_rotation(key_set_id='ks-auth', grace_seconds=30, "
        f"idempotency_key='first-rotation', "
        f"actor_ctx=ActorContext({env['users']['carol']!r}, 'dev-carol', 'jti-crash'))"
    )
    run_env = os.environ.copy()
    run_env["CRASH_AT"] = "rotate.after_pending_persisted"
    proc = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(REPO_ROOT),
        env=run_env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode != 0, proc.stderr


def _versions(sf) -> list[tuple[int, str]]:
    with tx_session(sf) as session:
        rows = session.execute(
            select(KeyVersion).where(KeyVersion.key_set_id == "ks-auth")
        ).scalars().all()
    return sorted((kv.version, kv.state) for kv in rows)


def test_rotation_retry_after_abort_recovers_without_manual_repair(fix02_env) -> None:
    env = fix02_env
    _crash_after_pending(env)

    assert _versions(env["sf"]) == [(1, "ACTIVE"), (2, "PENDING")]

    actions = env["svc"].recover_rotations()
    assert any(a["action"] == "aborted" for a in actions)
    # The never-active PENDING version is removed so version 2 can be reused.
    assert _versions(env["sf"]) == [(1, "ACTIVE")]

    retry_id = env["svc"].initiate_rotation(
        key_set_id="ks-auth",
        grace_seconds=30,
        idempotency_key="retry-new-idem",
        actor_ctx=env["admin_ctx"],
    )
    meta = env["svc"].get_key_set_metadata("ks-auth")
    assert meta["current_version"] == 2
    assert sum(1 for v in meta["versions"] if v["state"] == "ACTIVE") == 1
    assert _versions(env["sf"]) == [(1, "GRACE"), (2, "ACTIVE")]

    # A committed rotation is still idempotent for its own key.
    assert (
        env["svc"].initiate_rotation(
            key_set_id="ks-auth",
            grace_seconds=30,
            idempotency_key="retry-new-idem",
            actor_ctx=env["admin_ctx"],
        )
        == retry_id
    )


def test_aborted_idempotency_key_is_not_false_success(fix02_env) -> None:
    env = fix02_env
    _crash_after_pending(env)
    env["svc"].recover_rotations()

    with pytest.raises(Conflict) as excinfo:
        env["svc"].initiate_rotation(
            key_set_id="ks-auth",
            grace_seconds=30,
            idempotency_key="first-rotation",
            actor_ctx=env["admin_ctx"],
        )
    assert excinfo.value.reason_code == "ROTATION_ABORTED"

    meta = env["svc"].get_key_set_metadata("ks-auth")
    assert meta["current_version"] == 1
    with tx_session(env["sf"]) as session:
        rotations = session.execute(select(Rotation)).scalars().all()
    assert [r.status for r in rotations] == ["ABORTED"]


def test_rotation_journal_fsyncs_before_atomic_rename(fix02_env, monkeypatch) -> None:
    env = fix02_env
    events: list[str] = []
    real_fsync = rotation_module.os.fsync
    real_replace = rotation_module.os.replace

    def recording_fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    def recording_replace(src, dst):
        events.append("rename")
        return real_replace(src, dst)

    monkeypatch.setattr(rotation_module.os, "fsync", recording_fsync)
    monkeypatch.setattr(rotation_module.os, "replace", recording_replace)

    env["svc"].initiate_rotation(
        key_set_id="ks-auth",
        grace_seconds=30,
        idempotency_key="journal-rot",
        actor_ctx=env["admin_ctx"],
    )

    first_rename = events.index("rename")
    assert "fsync" in events[:first_rename]
    # intent marker is written before the DB commit and committed marker after
    assert events.count("rename") >= 2
