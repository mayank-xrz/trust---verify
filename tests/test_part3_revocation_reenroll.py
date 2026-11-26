"""Part 3 tests: Cross-node revocation, stale nodes, crash points, and secure re-enrollment."""

from __future__ import annotations

import concurrent.futures
import os
import subprocess
import sys
import uuid
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
from src.identity_keys.crypto import (
    b64e,
    ed25519_sign,
    generate_ed25519_keypair,
    public_key_fingerprint,
)
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.errors import NotAuthorized, Revoked
from src.identity_keys.key_lifecycle import is_key_acceptable
from src.identity_keys.models import AuditOutbox, Device, KeyVersion, ResourceGrant
from src.identity_keys.reenroll import ReenrollmentService
from src.identity_keys.revocation import RevocationReason, RevocationService
from src.identity_keys.rotation import RotationService
from src.identity_keys.services import IdentityService
from src.identity_keys.tokens import ActorContext, TokenAuthority

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def p3_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WRAP_MASTER_KEY_B64", b64e(os.urandom(32)))
    monkeypatch.setenv("CLUSTER_SYNC_SECRET", "part3-sync-secret")
    _, seed_priv = generate_ed25519_keypair()
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", b64e(seed_priv))

    db_path = tmp_path / "part3.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    token_auth = TokenAuthority(clock=clock)
    id_svc = IdentityService(sf, clock, emitter, token_auth)
    rev_svc = RevocationService(sf, clock, emitter, node_id="node-a")
    reenroll_svc = ReenrollmentService(sf, clock, emitter)
    rot_svc = RotationService(sf, clock, emitter, node_id="node-a")
    clients = {
        nid: TestClient(create_app(node_id=nid, database_url=db_url, clock=clock))
        for nid in ("node-a", "node-b", "node-c")
    }
    for c in clients.values():
        c.app.state.sync_mgr.pull_revocations()

    return {
        "db_url": db_url,
        "sf": sf,
        "clock": clock,
        "users": users,
        "id_svc": id_svc,
        "rev_svc": rev_svc,
        "reenroll_svc": reenroll_svc,
        "rot_svc": rot_svc,
        "clients": clients,
        "admin_ctx": ActorContext(users["carol"], "carol-dev", "jti-carol"),
    }


def _enroll_and_token(p3_env, user_id: str, label: str = "d1"):
    pub, priv = generate_ed25519_keypair()
    st = p3_env["id_svc"].start_enrollment(user_id=user_id, ttl_seconds=60)
    pop = ed25519_sign(priv, st["nonce"].encode())
    dev = p3_env["id_svc"].enroll_device(
        enrollment_id=st["enrollment_id"],
        nonce=st["nonce"],
        label=label,
        public_key_b64=b64e(pub),
        proof_of_possession_b64=b64e(pop),
    )
    ch = p3_env["id_svc"].issue_challenge(dev["device_id"])
    sig = ed25519_sign(priv, ch["challenge"].encode())
    tok = p3_env["id_svc"].verify_identity(
        device_id=dev["device_id"], challenge=ch["challenge"], signature_b64=b64e(sig)
    )["access_token"]
    return dev["device_id"], pub, priv, tok


def test_revocation_across_three_nodes_scope_isolation_and_idempotency(p3_env) -> None:
    alice = p3_env["users"]["alice"]
    bob = p3_env["users"]["bob"]
    d1, _, _, tok1 = _enroll_and_token(p3_env, alice, "alice-laptop")
    d2, _, _, tok2 = _enroll_and_token(p3_env, alice, "alice-phone")

    # Revoke d1 only; d2 stays active; idempotent replay returns same revocation_id
    r1 = p3_env["rev_svc"].revoke_device(p3_env["admin_ctx"], d1, RevocationReason.DEVICE_LOST)
    r2 = p3_env["rev_svc"].revoke_device(p3_env["admin_ctx"], d1, RevocationReason.DEVICE_LOST)
    assert r1["revocation_id"] == r2["revocation_id"]
    assert r2["idempotent_replay"] is True

    for c in p3_env["clients"].values():
        c.app.state.sync_mgr.pull_revocations()
        res1 = c.post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok1}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        ).json()
        assert res1["allowed"] is False

        res2 = c.post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok2}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        ).json()
        assert res2["allowed"] is True

    # Grant and revoke permission for bob
    gid = str(uuid.uuid4())
    with tx_session(p3_env["sf"]) as session:
        session.add(
            ResourceGrant(
                grant_id=gid,
                resource_id="brief-alpha",
                grantee_user_id=bob,
                permission="resource:read",
                granted_by=alice,
                granted_at=p3_env["clock"].now(),
            )
        )
    _, _, _, bob_tok = _enroll_and_token(p3_env, bob, "bob-dev")
    assert (
        p3_env["clients"]["node-b"]
        .post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {bob_tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        )
        .json()["allowed"]
        is True
    )
    p3_env["rev_svc"].revoke_permission(p3_env["admin_ctx"], bob, gid, RevocationReason.POLICY_VIOLATION)
    assert (
        p3_env["clients"]["node-c"]
        .post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {bob_tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        )
        .json()["allowed"]
        is False
    )


def test_emergency_rotate_and_stale_node_fail_closed(p3_env) -> None:
    v1_id = p3_env["rot_svc"].create_initial_key_set("auth-emerg", "auth")
    em = p3_env["rev_svc"].emergency_rotate(
        key_set_id="auth-emerg", idempotency_key="emerg-1", actor_ctx=p3_env["admin_ctx"]
    )
    assert em["emergency"] is True
    with tx_session(p3_env["sf"]) as session:
        v1 = session.get(KeyVersion, v1_id)
        assert v1 is not None and v1.state == "REVOKED"
        ok, reason = is_key_acceptable(v1, p3_env["clock"].now(), purpose="auth")
        assert ok is False and reason == "KEY_REVOKED"

    # Stale node check: advance clock past STALE_AFTER_MS -> node-c denies with STALE_STATE
    alice = p3_env["users"]["alice"]
    _, _, _, tok = _enroll_and_token(p3_env, alice, "alice-stale")
    p3_env["clock"].advance(seconds=5)
    stale_res = (
        p3_env["clients"]["node-c"]
        .post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        )
        .json()
    )
    assert stale_res["allowed"] is False
    assert stale_res["reason_code"] == "STALE_STATE"

    # Reconnect & sync -> becomes ready and allows
    p3_env["clients"]["node-c"].app.state.sync_mgr.pull_revocations()
    st = p3_env["clients"]["node-c"].get("/node/sync-status").json()
    assert st["stale"] is False
    ready_res = (
        p3_env["clients"]["node-c"]
        .post(
            "/api/v1/authorize",
            headers={"Authorization": f"Bearer {tok}"},
            json={"resource_id": "brief-alpha", "permission": "resource:read"},
        )
        .json()
    )
    assert ready_res["allowed"] is True


def test_revocation_is_irreversible_in_codebase() -> None:
    # Grep-enforced check: no code in src/identity_keys transitions away from revoked/REVOKED
    pkg_dir = REPO_ROOT / "src" / "identity_keys"
    for py_file in pkg_dir.glob("*.py"):
        text = py_file.read_text(encoding="utf-8")
        assert '"revoked": {"enrolled"' not in text
        assert '"REVOKED": {"ACTIVE"' not in text


def test_reenroll_recovery_code_admin_approval_and_security(p3_env) -> None:
    alice = p3_env["users"]["alice"]
    old_dev, old_pub, old_priv, old_tok = _enroll_and_token(p3_env, alice, "alice-lost")
    codes = p3_env["reenroll_svc"].generate_recovery_codes(alice, count=10)
    assert len(codes) == 10

    # Re-enroll with recovery code
    beg = p3_env["reenroll_svc"].begin_reenrollment(alice)
    new_pub, new_priv = generate_ed25519_keypair()
    pop = ed25519_sign(new_priv, beg["nonce"].encode())
    done = p3_env["reenroll_svc"].complete_reenrollment(
        enrollment_id=beg["enrollment_id"],
        nonce=beg["nonce"],
        label="alice-replacement",
        new_public_key_b64=b64e(new_pub),
        pop_signature_b64=b64e(pop),
        old_device_ids=[old_dev],
        recovery_code=codes[0],
    )
    assert old_dev in done["revoked_devices"]

    # Old device rejected on all 3 nodes; replaced_by_device_id linked
    with tx_session(p3_env["sf"]) as session:
        od = session.get(Device, old_dev)
        assert od is not None and od.status == "revoked"
        assert od.replaced_by_device_id == done["device_id"]

    for c in p3_env["clients"].values():
        c.app.state.sync_mgr.pull_revocations()
        assert (
            c.post(
                "/api/v1/authorize",
                headers={"Authorization": f"Bearer {old_tok}"},
                json={"resource_id": "brief-alpha", "permission": "resource:read"},
            ).json()["allowed"]
            is False
        )

    # Reused recovery code and wrong recovery code produce identical error
    beg2 = p3_env["reenroll_svc"].begin_reenrollment(alice)
    p2, k2 = generate_ed25519_keypair()
    with pytest.raises(NotAuthorized) as e_reused:
        p3_env["reenroll_svc"].complete_reenrollment(
            enrollment_id=beg2["enrollment_id"],
            nonce=beg2["nonce"],
            label="reuse-code",
            new_public_key_b64=b64e(p2),
            pop_signature_b64=b64e(ed25519_sign(k2, beg2["nonce"].encode())),
            recovery_code=codes[0],
        )
    with pytest.raises(NotAuthorized) as e_wrong:
        p3_env["reenroll_svc"].complete_reenrollment(
            enrollment_id=beg2["enrollment_id"],
            nonce=beg2["nonce"],
            label="wrong-code",
            new_public_key_b64=b64e(p2),
            pop_signature_b64=b64e(ed25519_sign(k2, beg2["nonce"].encode())),
            recovery_code="0" * 32,
        )
    assert str(e_reused.value) == str(e_wrong.value)

    # Re-registering revoked old_pub rejected
    with pytest.raises(Revoked, match="revoked"):
        p3_env["reenroll_svc"].complete_reenrollment(
            enrollment_id=beg2["enrollment_id"],
            nonce=beg2["nonce"],
            label="reuse-old-pk",
            new_public_key_b64=b64e(old_pub),
            pop_signature_b64=b64e(ed25519_sign(old_priv, beg2["nonce"].encode())),
            recovery_code=codes[1],
        )

    # Admin approval path + tampered PK rejection
    beg3 = p3_env["reenroll_svc"].begin_reenrollment(alice)
    p3, k3 = generate_ed25519_keypair()
    approval = p3_env["reenroll_svc"].create_admin_approval(
        p3_env["admin_ctx"],
        user_id=alice,
        new_pk_fingerprint=public_key_fingerprint(p3),
        enrollment_id=beg3["enrollment_id"],
    )
    p_tampered, k_tampered = generate_ed25519_keypair()
    with pytest.raises(NotAuthorized, match="mismatch"):
        p3_env["reenroll_svc"].complete_reenrollment(
            enrollment_id=beg3["enrollment_id"],
            nonce=beg3["nonce"],
            label="tampered",
            new_public_key_b64=b64e(p_tampered),
            pop_signature_b64=b64e(ed25519_sign(k_tampered, beg3["nonce"].encode())),
            admin_approval=approval,
        )


def test_reenroll_rate_limit_lockout_and_concurrency(p3_env) -> None:
    alice = p3_env["users"]["alice"]
    codes = p3_env["reenroll_svc"].generate_recovery_codes(alice, count=2)
    beg = p3_env["reenroll_svc"].begin_reenrollment(alice)

    # Brute-force attempts from one source hit rate limit + ALERT audit event
    for i in range(6):
        p3_env["clock"].advance(seconds=10)
        p_i, k_i = generate_ed25519_keypair()
        with pytest.raises(NotAuthorized):
            p3_env["reenroll_svc"].complete_reenrollment(
                enrollment_id=beg["enrollment_id"],
                nonce=beg["nonce"],
                label=f"bf-{i}",
                new_public_key_b64=b64e(p_i),
                pop_signature_b64=b64e(ed25519_sign(k_i, beg["nonce"].encode())),
                recovery_code="f" * 32,
                source_id="10.0.0.99",
            )

    with tx_session(p3_env["sf"]) as session:
        alerts = session.execute(select(AuditOutbox)).scalars().all()
        assert any(a.payload.get("action", "").startswith("ALERT.") for a in alerts)

    # Concurrent completions for one enrollment -> exactly one wins
    p3_env["clock"].advance(seconds=7200)
    beg_conc = p3_env["reenroll_svc"].begin_reenrollment(alice)
    p_c, k_c = generate_ed25519_keypair()
    pop_c = b64e(ed25519_sign(k_c, beg_conc["nonce"].encode()))

    def _complete(_idx: int) -> str:
        try:
            res = p3_env["reenroll_svc"].complete_reenrollment(
                enrollment_id=beg_conc["enrollment_id"],
                nonce=beg_conc["nonce"],
                label="conc",
                new_public_key_b64=b64e(p_c),
                pop_signature_b64=pop_c,
                recovery_code=codes[0],
                source_id=f"10.0.1.{_idx}",
            )
            return res["device_id"]
        except Exception as exc:
            return f"err:{type(exc).__name__}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = list(pool.map(_complete, [1, 2]))
    assert sum(1 for o in outcomes if not o.startswith("err:")) == 1


@pytest.mark.parametrize(
    ("crash_name", "expect_revoked"),
    [
        ("revoke.before_commit", False),
        ("revoke.after_commit", True),
    ],
)
def test_revoke_crash_matrix(tmp_path: Path, crash_name: str, expect_revoked: bool) -> None:
    db_path = tmp_path / f"rev_crash_{crash_name.replace('.', '_')}.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    id_svc = IdentityService(sf, clock, emitter, TokenAuthority(clock))
    pub, priv = generate_ed25519_keypair()
    st = id_svc.start_enrollment(users["alice"])
    dev_id = id_svc.enroll_device(
        enrollment_id=st["enrollment_id"],
        nonce=st["nonce"],
        label="crash-dev",
        public_key_b64=b64e(pub),
        proof_of_possession_b64=b64e(ed25519_sign(priv, st["nonce"].encode())),
    )["device_id"]

    env = os.environ.copy()
    env["CRASH_AT"] = crash_name
    script = (
        "from src.identity_keys.db import create_db_engine, create_session_factory; "
        "from src.identity_keys.clock import SystemClock; "
        "from src.identity_keys.audit_outbox import AuditEmitter; "
        "from src.identity_keys.revocation import RevocationService, RevocationReason; "
        "from src.identity_keys.tokens import ActorContext; "
        f"sf = create_session_factory(create_db_engine({db_url!r})); "
        "c = SystemClock(); e = AuditEmitter('node-a', c); "
        "r = RevocationService(sf, c, e, 'node-a'); "
        f"r.revoke_device(ActorContext({users['carol']!r}, 'c1', 'j1'), {dev_id!r}, RevocationReason.DEVICE_LOST)"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=str(REPO_ROOT), env=env)
    assert proc.returncode != 0

    with tx_session(sf) as session:
        d = session.get(Device, dev_id)
        assert d is not None
        assert (d.status == "revoked") is expect_revoked
