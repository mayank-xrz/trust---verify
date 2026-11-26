"""Phase 1 tests: Alembic upgrade/downgrade and DB-level constraint & trigger enforcement."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError as SAIntegrityError
from sqlalchemy.exc import OperationalError

from alembic import command
from alembic.config import Config

REPO_ROOT = Path(__file__).resolve().parent.parent


def _alembic_cfg(db_url: str) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    return cfg


def test_alembic_upgrade_downgrade_roundtrip(tmp_path: Path) -> None:
    db_path = tmp_path / "phase1_roundtrip.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = _alembic_cfg(db_url)

    command.upgrade(cfg, "head")
    engine = create_engine(db_url)
    tables = set(inspect(engine).get_table_names())
    expected = {
        "users", "devices", "roles", "permissions", "role_permissions", "user_roles",
        "resources", "resource_grants", "key_versions", "revocations", "rotations",
        "outbox", "node_sync_state", "audit_outbox", "enrollments",
        "recovery_credentials", "backups", "auth_challenges",
    }
    assert expected.issubset(tables)

    command.downgrade(cfg, "base")
    tables_after = set(inspect(engine).get_table_names())
    assert not (expected & tables_after)

    command.upgrade(cfg, "head")
    tables_reup = set(inspect(engine).get_table_names())
    assert expected.issubset(tables_reup)


def test_db_constraints_and_triggers_enforced(tmp_path: Path) -> None:
    db_path = tmp_path / "phase1_constraints.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    command.upgrade(_alembic_cfg(db_url), "head")
    engine = create_engine(db_url)
    now = datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)

    with engine.begin() as conn:
        # 1. Partial unique index rejects two ACTIVE rows in the same key_set_id
        conn.execute(
            text(
                "INSERT INTO key_versions (key_version_id, scope, key_set_id, version, state, created_at) "
                "VALUES (:id, 'data', 'set-1', 1, 'ACTIVE', :ts)"
            ),
            {"id": str(uuid.uuid4()), "ts": now},
        )
    with pytest.raises(SAIntegrityError):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO key_versions (key_version_id, scope, key_set_id, version, state, created_at) "
                    "VALUES (:id, 'data', 'set-1', 2, 'ACTIVE', :ts)"
                ),
                {"id": str(uuid.uuid4()), "ts": now},
            )

    # 2. CHECK constraint rejects revoked device without revoked_at
    uid = str(uuid.uuid4())
    eid = str(uuid.uuid4())
    did = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text("INSERT INTO users (user_id, handle, status, created_at) VALUES (:id, 'alice', 'active', :ts)"),
            {"id": uid, "ts": now},
        )
        conn.execute(
            text(
                "INSERT INTO enrollments (enrollment_id, user_id, kind, status, nonce, expires_at, created_at) "
                "VALUES (:eid, :uid, 'first', 'completed', 'n1', :ts, :ts)"
            ),
            {"eid": eid, "uid": uid, "ts": now},
        )

    with pytest.raises(SAIntegrityError):
        with engine.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO devices (device_id, user_id, label, status, public_key, public_key_alg, "
                    "public_key_fingerprint, enrollment_id) "
                    "VALUES (:did, :uid, 'laptop', 'revoked', X'0102', 'Ed25519', 'fp1', :eid)"
                ),
                {"did": did, "uid": uid, "eid": eid},
            )

    # 3. Trigger rejects transitioning a revoked device back to enrolled
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO devices (device_id, user_id, label, status, public_key, public_key_alg, "
                "public_key_fingerprint, revoked_at, enrollment_id) "
                "VALUES (:did, :uid, 'laptop', 'revoked', X'0102', 'Ed25519', 'fp1', :ts, :eid)"
            ),
            {"did": did, "uid": uid, "ts": now, "eid": eid},
        )
    with pytest.raises((SAIntegrityError, OperationalError)):
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE devices SET status = 'enrolled' WHERE device_id = :did"),
                {"did": did},
            )

    # 4. Trigger rejects UPDATE and DELETE on revocations (append-only)
    rid = str(uuid.uuid4())
    with engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO revocations (revocation_id, target_type, target_id, user_id, "
                "revoked_by_actor, reason_code, committed_at) "
                "VALUES (:rid, 'device', :did, :uid, 'admin', 'lost', :ts)"
            ),
            {"rid": rid, "did": did, "uid": uid, "ts": now},
        )
    with pytest.raises((SAIntegrityError, OperationalError)):
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE revocations SET reason_code = 'tampered' WHERE revocation_id = :rid"),
                {"rid": rid},
            )
    with pytest.raises((SAIntegrityError, OperationalError)):
        with engine.begin() as conn:
            conn.execute(
                text("DELETE FROM revocations WHERE revocation_id = :rid"),
                {"rid": rid},
            )
