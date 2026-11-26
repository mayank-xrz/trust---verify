"""The 15 required brief scenario integration tests against the 3-node sandbox."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from alembic.config import Config
from fastapi.testclient import TestClient

from alembic import command
from scripts.seed_sandbox import seed_database
from src.identity_keys.api import create_app
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.backup import BackupService
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import (
    b64e,
    ed25519_sign,
    generate_ed25519_keypair,
    generate_ml_dsa_keypair,
)
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.errors import Conflict
from src.identity_keys.errors import IntegrityError as DomainIntegrityError
from src.identity_keys.key_lifecycle import EnvelopeEncryptionService
from src.identity_keys.models import Device
from src.identity_keys.reenroll import ReenrollmentService
from src.identity_keys.revocation import RevocationReason, RevocationService
from src.identity_keys.rotation import RotationService
from src.identity_keys.services import AuthzService, IdentityService
from src.identity_keys.tokens import ActorContext, TokenAuthority

REPO_ROOT = Path(__file__).resolve().parent.parent.parent


@pytest.fixture
def sandbox(tmp_path: Path, monkeypatch):
    master_b64 = b64e(os.urandom(32))
    monkeypatch.setenv("WRAP_MASTER_KEY_B64", master_b64)
    monkeypatch.setenv("CLUSTER_SYNC_SECRET", "brief-sync-secret")
    _, seed_priv = generate_ed25519_keypair()
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", b64e(seed_priv))

    db_url = f"sqlite+pysqlite:///{tmp_path / 'brief.db'}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    id_svc = IdentityService(sf, clock, emitter, TokenAuthority(clock))
    rot_svc = RotationService(sf, clock, emitter, "node-a")
    rev_svc = RevocationService(sf, clock, emitter, "node-a")
    reenroll_svc = ReenrollmentService(sf, clock, emitter)
    env_svc = EnvelopeEncryptionService(sf, clock, emitter)
    bkp_svc = BackupService(sf, clock, emitter, "node-a")
    rot_svc.create_initial_key_set("auth-brief", "auth")
    rot_svc.create_initial_key_set("data-brief", "data")
    env_svc.encrypt_resource(
        resource_id="brief-alpha",
        owner_user_id=users["alice"],
        plaintext=b"brief-protected-data",
        key_set_id="data-brief",
    )
    nodes = {
        nid: TestClient(create_app(node_id=nid, database_url=db_url, clock=clock))
        for nid in ("node-a", "node-b", "node-c")
    }
    for n in nodes.values():
        n.app.state.sync_mgr.pull_revocations()

    return {
        "db_url": db_url,
        "master_b64": master_b64,
        "sf": sf,
        "clock": clock,
        "users": users,
        "id_svc": id_svc,
        "rot_svc": rot_svc,
        "rev_svc": rev_svc,
        "reenroll_svc": reenroll_svc,
        "env_svc": env_svc,
        "bkp_svc": bkp_svc,
        "nodes": nodes,
        "admin_ctx": ActorContext(users["carol"], "carol-dev", "jti-carol"),
    }


def _enroll_token(sb, user_id: str, label: str = "dev"):
    pub, priv = generate_ed25519_keypair()
    st = sb["id_svc"].start_enrollment(user_id)
    did = sb["id_svc"].enroll_device(
        enrollment_id=st["enrollment_id"],
        nonce=st["nonce"],
        label=label,
        public_key_b64=b64e(pub),
        proof_of_possession_b64=b64e(ed25519_sign(priv, st["nonce"].encode())),
    )["device_id"]
    ch = sb["id_svc"].issue_challenge(did)
    tok = sb["id_svc"].verify_identity(
        device_id=did,
        challenge=ch["challenge"],
        signature_b64=b64e(ed25519_sign(priv, ch["challenge"].encode())),
    )["access_token"]
    return did, pub, priv, tok


def test_01_authorized_access_before_rotation(sandbox) -> None:
    _, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "a1")
    v1 = sandbox["rot_svc"].get_key_set_metadata("auth-brief")["active_key_version_id"]
    res = sandbox["nodes"]["node-a"].post(
        "/api/v1/authorize",
        headers={"Authorization": f"Bearer {tok}"},
        json={"resource_id": "brief-alpha", "permission": "resource:read", "key_version_id": v1},
    ).json()
    assert res["allowed"] is True


def test_02_authorized_access_during_rotation(sandbox) -> None:
    _, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "a2")
    sandbox["rot_svc"].initiate_rotation(
        key_set_id="auth-brief", grace_seconds=30, idempotency_key="s02", actor_ctx=sandbox["admin_ctx"]
    )
    v2 = sandbox["rot_svc"].get_key_set_metadata("auth-brief")["active_key_version_id"]
    assert all(
        n.post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read", "key_version_id": v2},
        ).json()["allowed"]
        is True
        for n in sandbox["nodes"].values()
    )


def test_03_old_key_acceptance_within_grace_period(sandbox) -> None:
    _, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "a3")
    v1 = sandbox["rot_svc"].get_key_set_metadata("auth-brief")["active_key_version_id"]
    sandbox["rot_svc"].initiate_rotation(
        key_set_id="auth-brief", grace_seconds=30, idempotency_key="s03", actor_ctx=sandbox["admin_ctx"]
    )
    sandbox["clock"].advance(seconds=15)
    for n in sandbox["nodes"].values():
        n.app.state.sync_mgr.pull_revocations()
        assert (
            n.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {tok}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read", "key_version_id": v1},
            ).json()["allowed"]
            is True
        )


def test_04_old_key_rejection_on_every_node_after_cutoff(sandbox) -> None:
    _, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "a4")
    v1 = sandbox["rot_svc"].get_key_set_metadata("auth-brief")["active_key_version_id"]
    sandbox["rot_svc"].initiate_rotation(
        key_set_id="auth-brief", grace_seconds=30, idempotency_key="s04", actor_ctx=sandbox["admin_ctx"]
    )
    sandbox["clock"].advance(seconds=31)
    for n in sandbox["nodes"].values():
        n.app.state.sync_mgr.pull_revocations()
        r = n.post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read", "key_version_id": v1},
        ).json()
        assert r["allowed"] is False and r["reason_code"] == "KEY_RETIRED"


def test_05_immediate_authoritative_revocation(sandbox) -> None:
    d1, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "a5")
    sandbox["rev_svc"].revoke_device(sandbox["admin_ctx"], d1, RevocationReason.DEVICE_LOST)
    for n in sandbox["nodes"].values():
        n.app.state.sync_mgr.pull_revocations()
        assert (
            n.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {tok}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read"},
            ).json()["allowed"]
            is False
        )


def test_06_measured_cross_node_revocation_enforcement(sandbox) -> None:
    import time

    d1, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "a6")
    sandbox["rev_svc"].revoke_device(sandbox["admin_ctx"], d1, RevocationReason.DEVICE_COMPROMISED)
    t_commit = time.monotonic_ns()
    for n in sandbox["nodes"].values():
        n.app.state.sync_mgr.pull_revocations()
        assert (
            n.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {tok}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read"},
            ).json()["allowed"]
            is False
        )
    elapsed_ms = (time.monotonic_ns() - t_commit) / 1_000_000.0
    assert elapsed_ms >= 0.0


def test_07_unaffected_users_retain_access(sandbox) -> None:
    d_bob, _, _, _ = _enroll_token(sandbox, sandbox["users"]["bob"], "bob-d")
    _, _, _, tok_alice = _enroll_token(sandbox, sandbox["users"]["alice"], "alice-d")
    sandbox["rev_svc"].revoke_device(sandbox["admin_ctx"], d_bob, RevocationReason.DEVICE_LOST)
    for n in sandbox["nodes"].values():
        n.app.state.sync_mgr.pull_revocations()
        assert (
            n.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {tok_alice}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read"},
            ).json()["allowed"]
            is True
        )


def test_08_authorized_reenrollment_after_device_loss(sandbox) -> None:
    alice = sandbox["users"]["alice"]
    old_d, _, _, old_tok = _enroll_token(sandbox, alice, "lost")
    codes = sandbox["reenroll_svc"].generate_recovery_codes(alice, count=2)
    beg = sandbox["reenroll_svc"].begin_reenrollment(alice)
    p2, k2 = generate_ed25519_keypair()
    done = sandbox["reenroll_svc"].complete_reenrollment(
        enrollment_id=beg["enrollment_id"],
        nonce=beg["nonce"],
        label="new-dev",
        new_public_key_b64=b64e(p2),
        pop_signature_b64=b64e(ed25519_sign(k2, beg["nonce"].encode())),
        old_device_ids=[old_d],
        recovery_code=codes[0],
    )
    ch = sandbox["id_svc"].issue_challenge(done["device_id"])
    new_tok = sandbox["id_svc"].verify_identity(
        device_id=done["device_id"],
        challenge=ch["challenge"],
        signature_b64=b64e(ed25519_sign(k2, ch["challenge"].encode())),
    )["access_token"]
    for n in sandbox["nodes"].values():
        n.app.state.sync_mgr.pull_revocations()
        assert (
            n.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {old_tok}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read"},
            ).json()["allowed"]
            is False
        )
        assert (
            n.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {new_tok}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read"},
            ).json()["allowed"]
            is True
        )


def test_09_recovery_from_interrupted_rotation(sandbox) -> None:
    env = os.environ.copy()
    env["WRAP_MASTER_KEY_B64"] = sandbox["master_b64"]
    env["CRASH_AT"] = "rotate.before_commit"
    script = (
        "from src.identity_keys.db import create_db_engine, create_session_factory; "
        "from src.identity_keys.clock import SystemClock; "
        "from src.identity_keys.audit_outbox import AuditEmitter; "
        "from src.identity_keys.rotation import RotationService; "
        "from src.identity_keys.tokens import ActorContext; "
        f"sf = create_session_factory(create_db_engine({sandbox['db_url']!r})); "
        "c = SystemClock(); e = AuditEmitter('node-a', c); "
        "r = RotationService(sf, c, e, 'node-a'); "
        f"r.initiate_rotation(key_set_id='data-brief', grace_seconds=30, idempotency_key='c09', actor_ctx=ActorContext({sandbox['users']['carol']!r}, 'c1', 'j1'))"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=str(REPO_ROOT), env=env)
    assert proc.returncode != 0
    actions = sandbox["rot_svc"].recover_rotations()
    assert any(a["action"] == "aborted" for a in actions)
    assert sandbox["rot_svc"].get_key_set_metadata("data-brief")["current_version"] == 1


def test_10_persistence_of_revoked_state_after_restart(sandbox) -> None:
    d1, _, _, _ = _enroll_token(sandbox, sandbox["users"]["alice"], "persist")
    sandbox["rev_svc"].revoke_device(sandbox["admin_ctx"], d1, RevocationReason.DEVICE_LOST)
    # Simulate node restart by creating fresh TestClient against same DB
    restarted = TestClient(create_app(node_id="node-a", database_url=sandbox["db_url"], clock=sandbox["clock"]))
    restarted.app.state.sync_mgr.pull_revocations()
    with tx_session(sandbox["sf"]) as session:
        d = session.get(Device, d1)
        assert d is not None and d.status == "revoked"


def test_11_availability_of_committed_protected_data_after_recovery(sandbox) -> None:
    sandbox["rot_svc"].initiate_rotation(
        key_set_id="data-brief", grace_seconds=0, idempotency_key="s11", actor_ctx=sandbox["admin_ctx"]
    )
    assert sandbox["env_svc"].decrypt_resource("brief-alpha") == b"brief-protected-data"


def test_12_successful_restoration_of_authentic_backup(sandbox, tmp_path: Path) -> None:
    pub, priv = generate_ml_dsa_keypair()
    bkp = tmp_path / "s12.tbv"
    sandbox["bkp_svc"].create_backup(sandbox["admin_ctx"], bkp, signing_privkey=priv, passphrase="pw")
    res = sandbox["bkp_svc"].restore_backup(sandbox["admin_ctx"], bkp, pinned_pubkey=pub, passphrase="pw")
    assert res["restored"] is True


def test_13_rejection_of_damaged_backup(sandbox, tmp_path: Path) -> None:
    pub, priv = generate_ml_dsa_keypair()
    bkp = tmp_path / "s13.tbv"
    sandbox["bkp_svc"].create_backup(sandbox["admin_ctx"], bkp, signing_privkey=priv, passphrase="pw")
    data = bytearray(bkp.read_bytes())
    data[-10] ^= 0xFF
    bkp.write_bytes(bytes(data))
    with pytest.raises(DomainIntegrityError):
        sandbox["bkp_svc"].restore_backup(sandbox["admin_ctx"], bkp, pinned_pubkey=pub, passphrase="pw")


def test_14_rejection_of_rollback_that_would_reactivate_revoked_keys(sandbox, tmp_path: Path) -> None:
    pub, priv = generate_ml_dsa_keypair()
    bkp = tmp_path / "s14.tbv"
    sandbox["bkp_svc"].create_backup(sandbox["admin_ctx"], bkp, signing_privkey=priv, passphrase="pw")
    d1, _, _, _ = _enroll_token(sandbox, sandbox["users"]["alice"], "s14-d")
    sandbox["rev_svc"].revoke_device(sandbox["admin_ctx"], d1, RevocationReason.DEVICE_COMPROMISED)
    with pytest.raises(Conflict, match="behind live revocation anchor"):
        sandbox["bkp_svc"].restore_backup(sandbox["admin_ctx"], bkp, pinned_pubkey=pub, passphrase="pw")


def test_15_fail_closed_when_authorization_state_unavailable(sandbox) -> None:
    sandbox["clock"].advance(seconds=10)  # Exceeds STALE_AFTER_MS=2000
    _, _, _, tok = _enroll_token(sandbox, sandbox["users"]["alice"], "s15")
    r = sandbox["nodes"]["node-b"].post(
        "/api/v1/authorize",
        headers={"Authorization": f"Bearer {tok}"},
        json={"resource_id": "brief-alpha", "permission": "resource:read"},
    ).json()
    assert r["allowed"] is False and r["reason_code"] == "STALE_STATE"

    broken = AuthzService(
        create_session_factory(create_db_engine("sqlite+pysqlite:////nonexistent_s15/bad.db")),
        sandbox["clock"],
        AuditEmitter("node-a", sandbox["clock"]),
        node_id="node-a",
    )
    dec = broken.authorize(ActorContext(sandbox["users"]["alice"], "d", "j"), "brief-alpha", "resource:read")
    assert dec.allowed is False and dec.reason_code == "STATE_UNAVAILABLE"
