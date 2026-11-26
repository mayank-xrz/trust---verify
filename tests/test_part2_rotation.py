"""Part 2 tests: Key state machine, grace boundaries, envelope encryption, concurrency, and crash matrix."""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import select

from alembic import command
from scripts.seed_sandbox import seed_database
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import b64e
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.errors import (
    Conflict,
    IllegalTransition,
)
from src.identity_keys.errors import (
    IntegrityError as DomainIntegrityError,
)
from src.identity_keys.key_lifecycle import (
    EnvelopeEncryptionService,
    is_key_acceptable,
    transition_key,
    unwrap_key_material,
)
from src.identity_keys.models import KeyVersion, Rotation
from src.identity_keys.rotation import RotationService
from src.identity_keys.services import AuthzService
from src.identity_keys.tokens import ActorContext

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def p2_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WRAP_MASTER_KEY_B64", b64e(os.urandom(32)))
    monkeypatch.setenv("CLUSTER_SYNC_SECRET", "test-cluster-secret-part2")
    db_path = tmp_path / "part2.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    engine = create_db_engine(db_url)
    sf = create_session_factory(engine)
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    rot_svc = RotationService(sf, clock, emitter, node_id="node-a")
    env_svc = EnvelopeEncryptionService(sf, clock, emitter)
    authz_svc = AuthzService(sf, clock, emitter, node_id="node-a", max_cache_staleness_ms=500)
    admin_ctx = ActorContext(user_id=users["carol"], device_id="dev-carol", token_jti="jti-1")
    return {
        "db_url": db_url,
        "sf": sf,
        "clock": clock,
        "emitter": emitter,
        "users": users,
        "rot_svc": rot_svc,
        "env_svc": env_svc,
        "authz_svc": authz_svc,
        "admin_ctx": admin_ctx,
    }


def test_state_machine_all_transitions_and_terminal_revoked(p2_env) -> None:
    sf = p2_env["sf"]
    now = p2_env["clock"].now()
    legal = {
        ("PENDING", "ACTIVE"),
        ("PENDING", "RETIRED"),
        ("PENDING", "REVOKED"),
        ("ACTIVE", "GRACE"),
        ("ACTIVE", "RETIRED"),
        ("ACTIVE", "REVOKED"),
        ("GRACE", "RETIRED"),
        ("GRACE", "REVOKED"),
        ("RETIRED", "REVOKED"),
    }
    states = ["PENDING", "ACTIVE", "GRACE", "RETIRED", "REVOKED"]
    with tx_session(sf) as session:
        session.add(
            Rotation(
                rotation_id="rot-1",
                key_set_id="set-sm",
                from_version=1,
                to_version=2,
                status="STARTED",
                idempotency_key="sm-rot-1",
                grace_seconds=30,
                created_at=now,
                updated_at=now,
            )
        )
    for src in states:
        for dst in states:
            kv_id = str(uuid.uuid4())
            with tx_session(sf) as session:
                session.add(
                    KeyVersion(
                        key_version_id=kv_id,
                        scope="auth",
                        key_set_id=f"set-{src}-{dst}",
                        version=1,
                        state=src,
                        created_at=now,
                        rotation_id="rot-1",
                    )
                )
            if (src, dst) in legal:
                with tx_session(sf) as session:
                    kv = transition_key(session, kv_id, dst, "rot-1", now)
                    assert kv.state == dst
            elif src == dst and src in ("ACTIVE", "GRACE", "RETIRED"):
                with tx_session(sf) as session:
                    kv = transition_key(session, kv_id, dst, "rot-1", now)
                    assert kv.state == dst
            else:
                with pytest.raises(IllegalTransition):
                    with tx_session(sf) as session:
                        transition_key(session, kv_id, dst, "rot-1", now)


def test_grace_boundary_zero_grace_and_revoked_grace_key(p2_env) -> None:
    rot_svc: RotationService = p2_env["rot_svc"]
    clock: FakeClock = p2_env["clock"]
    authz_svc: AuthzService = p2_env["authz_svc"]
    sf = p2_env["sf"]
    alice = p2_env["users"]["alice"]

    v1_id = rot_svc.create_initial_key_set("auth-main", "auth")
    rot_svc.initiate_rotation(
        key_set_id="auth-main",
        grace_seconds=30,
        idempotency_key="idem-grace-1",
        actor_ctx=p2_env["admin_ctx"],
    )

    with tx_session(sf) as session:
        v1 = session.get(KeyVersion, v1_id)
        assert v1 is not None and v1.state == "GRACE" and v1.grace_until is not None
        grace_until = v1.grace_until

    # Accepted at grace_until - 1 microsecond
    ok, reason = is_key_acceptable(v1, grace_until - timedelta(microseconds=1), purpose="auth")
    assert ok is True and reason == "KEY_GRACE_VALID"

    # Rejected at exact grace_until
    ok2, reason2 = is_key_acceptable(v1, grace_until, purpose="auth")
    assert ok2 is False and reason2 == "KEY_RETIRED"

    # Integration with AuthzService: rejected after cutoff emits key.rejected_after_cutoff
    clock.advance(seconds=31)
    with tx_session(sf) as session:
        alice_dev = session.execute(
            select(KeyVersion)  # dummy unused
        )
        _ = alice_dev
    from src.identity_keys.models import Device

    with tx_session(sf) as session:
        dev = session.execute(select(Device).where(Device.user_id == alice)).scalar_one()
        alice_ctx = ActorContext(user_id=alice, device_id=dev.device_id, token_jti="jti-a")

    dec = authz_svc.authorize(alice_ctx, "brief-alpha", "resource:read", key_version_id=v1_id)
    assert dec.allowed is False
    assert dec.reason_code == "KEY_RETIRED"

    # Zero grace rejects immediately at commit instant
    v2_id = rot_svc.get_key_set_metadata("auth-main")["active_key_version_id"]
    rot_svc.initiate_rotation(
        key_set_id="auth-main",
        grace_seconds=0,
        idempotency_key="idem-zero-grace",
        actor_ctx=p2_env["admin_ctx"],
    )
    dec_zero = authz_svc.authorize(alice_ctx, "brief-alpha", "resource:read", key_version_id=v2_id)
    assert dec_zero.allowed is False and dec_zero.reason_code == "KEY_RETIRED"

    # Revoked GRACE key rejected even inside grace window
    v3_id = rot_svc.get_key_set_metadata("auth-main")["active_key_version_id"]
    rot_svc.initiate_rotation(
        key_set_id="auth-main",
        grace_seconds=60,
        idempotency_key="idem-rev-grace",
        actor_ctx=p2_env["admin_ctx"],
    )
    with tx_session(sf) as session:
        transition_key(session, v3_id, "REVOKED", None, clock.now(), revoke_reason="compromised")
        v3 = session.get(KeyVersion, v3_id)
        assert v3 is not None
        ok3, r3 = is_key_acceptable(v3, clock.now(), purpose="auth")
        assert ok3 is False and r3 == "KEY_REVOKED"


def test_envelope_encryption_rewrap_destroy_and_aad_binding(p2_env) -> None:
    rot_svc: RotationService = p2_env["rot_svc"]
    env_svc: EnvelopeEncryptionService = p2_env["env_svc"]
    sf = p2_env["sf"]
    alice = p2_env["users"]["alice"]

    v1_id = rot_svc.create_initial_key_set("data-main", "data")
    used_kv = env_svc.encrypt_resource(
        resource_id="res-env-1",
        owner_user_id=alice,
        plaintext=b"classified-pqc-payload",
        key_set_id="data-main",
    )
    assert used_kv == v1_id

    # Rotate data key with grace=0 (v1 becomes RETIRED immediately)
    rot_svc.initiate_rotation(
        key_set_id="data-main",
        grace_seconds=0,
        idempotency_key="idem-data-1",
        actor_ctx=p2_env["admin_ctx"],
    )
    # Old data remains decryptable after old data key is RETIRED
    assert env_svc.decrypt_resource("res-env-1") == b"classified-pqc-payload"

    # DESTROY refused while DEK still references v1
    with pytest.raises(Conflict, match="still wrapped"):
        env_svc.destroy_key_version(v1_id, p2_env["admin_ctx"])

    # Re-wrap under v2, then DESTROY v1 succeeds
    rewrap_res = env_svc.rewrap_resource("res-env-1", p2_env["admin_ctx"])
    assert rewrap_res["from_key_version_id"] == v1_id
    destroyed = env_svc.destroy_key_version(v1_id, p2_env["admin_ctx"])
    assert destroyed["key_version_id"] == v1_id
    assert env_svc.decrypt_resource("res-env-1") == b"classified-pqc-payload"

    # AAD binding: swapping wrapped_private_material between rows fails unwrap
    from src.identity_keys.key_lifecycle import load_wrap_master_key

    v2_id = rewrap_res["to_key_version_id"]
    master = load_wrap_master_key()
    with tx_session(sf) as session:
        kv2 = session.get(KeyVersion, v2_id)
        assert kv2 is not None
        kv_fake = KeyVersion(
            key_version_id=str(uuid.uuid4()),
            scope="data",
            key_set_id="data-main",
            version=99,
            state="ACTIVE",
            wrapped_private_material=kv2.wrapped_private_material,
            wrap_nonce=kv2.wrap_nonce,
            created_at=p2_env["clock"].now(),
        )
        with pytest.raises(DomainIntegrityError, match="AAD/GCM"):
            unwrap_key_material(master, kv_fake)


def test_idempotency_and_concurrent_rotations(p2_env) -> None:
    rot_svc: RotationService = p2_env["rot_svc"]
    rot_svc.create_initial_key_set("auth-conc", "auth")

    r1 = rot_svc.initiate_rotation(
        key_set_id="auth-conc",
        grace_seconds=30,
        idempotency_key="same-key-1",
        actor_ctx=p2_env["admin_ctx"],
    )
    r2 = rot_svc.initiate_rotation(
        key_set_id="auth-conc",
        grace_seconds=30,
        idempotency_key="same-key-1",
        actor_ctx=p2_env["admin_ctx"],
    )
    assert r1 == r2

    # Concurrent rotations with distinct idempotency keys: only one succeeds per version
    def _try_rot(idx: int) -> str:
        try:
            return rot_svc.initiate_rotation(
                key_set_id="auth-conc",
                grace_seconds=30,
                idempotency_key=f"conc-{idx}",
                actor_ctx=p2_env["admin_ctx"],
            )
        except Exception as exc:
            return f"err:{type(exc).__name__}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        results = list(pool.map(_try_rot, range(6)))
    assert any(not r.startswith("err:") for r in results)
    meta = rot_svc.get_key_set_metadata("auth-conc")
    active_count = sum(1 for v in meta["versions"] if v["state"] == "ACTIVE")
    assert active_count == 1


@pytest.mark.parametrize(
    ("crash_name", "expected_version", "expected_recovery"),
    [
        ("rotate.before_start", 1, "none"),
        ("rotate.after_pending_persisted", 1, "aborted"),
        ("rotate.before_commit", 1, "aborted"),
        ("rotate.after_commit", 2, "rolled_forward"),
        ("rotate.during_sync", 2, "none"),
    ],
)
def test_crash_matrix_subprocess_and_recovery_guarantees(
    tmp_path: Path, crash_name: str, expected_version: int, expected_recovery: str
) -> None:
    db_path = tmp_path / f"crash_{crash_name.replace('.', '_')}.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    master_b64 = b64e(os.urandom(32))
    env = os.environ.copy()
    env["WRAP_MASTER_KEY_B64"] = master_b64
    env["CLUSTER_SYNC_SECRET"] = "test-cluster-secret"
    env["DATABASE_URL"] = db_url
    env["CRASH_AT"] = crash_name

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    old_master = os.environ.get("WRAP_MASTER_KEY_B64")
    os.environ["WRAP_MASTER_KEY_B64"] = master_b64
    try:
        rot_svc = RotationService(
            sf,
            clock,
            emitter,
            node_id="node-a",
            peer_urls={"node-b": "http://127.0.0.1:9", "node-c": "http://127.0.0.1:9"},
        )
        rot_svc.create_initial_key_set("data-crash", "data")
        env_svc = EnvelopeEncryptionService(sf, clock, emitter)
        env_svc.encrypt_resource(
            resource_id="res-crash",
            owner_user_id=users["alice"],
            plaintext=b"survive-crash",
            key_set_id="data-crash",
        )

        # Spawn subprocess that executes initiate_rotation and hits crash_point -> os._exit(1)
        script = (
            "import os; from src.identity_keys.db import create_db_engine, create_session_factory; "
            "from src.identity_keys.clock import SystemClock; "
            "from src.identity_keys.audit_outbox import AuditEmitter; "
            "from src.identity_keys.rotation import RotationService; "
            "from src.identity_keys.tokens import ActorContext; "
            f"sf = create_session_factory(create_db_engine({db_url!r})); "
            "c = SystemClock(); e = AuditEmitter('node-a', c); "
            "r = RotationService(sf, c, e, 'node-a', {'node-b': 'http://127.0.0.1:9', 'node-c': 'http://127.0.0.1:9'}); "
            f"r.initiate_rotation(key_set_id='data-crash', grace_seconds=30, idempotency_key='crash-idem', actor_ctx=ActorContext({users['carol']!r}, 'd1', 'j1'))"
        )
        proc = subprocess.run([sys.executable, "-c", script], cwd=str(REPO_ROOT), env=env)
        assert proc.returncode != 0

        # Restart & recover using ONLY DB state
        rec_actions = rot_svc.recover_rotations(correlation_id="corr-rec-1")
        if expected_recovery != "none":
            assert any(a["action"] == expected_recovery for a in rec_actions)

        meta = rot_svc.get_key_set_metadata("data-crash")
        assert meta["current_version"] == expected_version
        assert sum(1 for v in meta["versions"] if v["state"] == "ACTIVE") == 1
        assert env_svc.decrypt_resource("res-crash") == b"survive-crash"

        # Pending key (if any) is never ACTIVE and cannot be used for auth/wrap
        for v in meta["versions"]:
            assert v["state"] != "PENDING"
    finally:
        if old_master is None:
            os.environ.pop("WRAP_MASTER_KEY_B64", None)
        else:
            os.environ["WRAP_MASTER_KEY_B64"] = old_master
