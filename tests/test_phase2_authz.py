"""Phase 2 & 4 tests: Enrollment, Identity Verification, Fail-Closed Authz, Spoofing, and Audit Outbox."""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest
pytest.importorskip("src.identity_keys.db", reason="src.identity_keys removed in upstream c1f170e")
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import select

from src.audit.verifier import AuditLogVerifier
from src.identity_keys.api import create_app
from src.identity_keys.audit_outbox import AuditDispatcher, AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import b64e, ed25519_sign, generate_ed25519_keypair
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.errors import Conflict, NotAuthorized, Revoked
from src.identity_keys.models import AuditOutbox, Device, Resource, ResourceGrant, User
from src.identity_keys.services import AuthzService, IdentityService, KeyMetadataService, transition_device_status
from src.identity_keys.tokens import ActorContext, TokenAuthority
from scripts.seed_sandbox import seed_database

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def env(tmp_path: Path):
    db_path = tmp_path / "phase2.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    engine = create_db_engine(db_url)
    sf = create_session_factory(engine)
    clock = FakeClock()
    emitter = AuditEmitter(node_id="node-a", clock=clock)
    token_auth = TokenAuthority(clock=clock)
    id_svc = IdentityService(sf, clock, emitter, token_auth)
    authz_svc = AuthzService(sf, clock, emitter, node_id="node-a")
    meta_svc = KeyMetadataService(sf)
    log_path = str(tmp_path / "node-a_audit.log")
    dispatcher = AuditDispatcher(sf, clock, node_id="node-a", log_file_path=log_path)
    users = seed_database(sf, seed=42)
    return {
        "db_url": db_url,
        "engine": engine,
        "sf": sf,
        "clock": clock,
        "id_svc": id_svc,
        "authz_svc": authz_svc,
        "meta_svc": meta_svc,
        "token_auth": token_auth,
        "dispatcher": dispatcher,
        "log_path": log_path,
        "users": users,
    }


def _enroll_new_device(env, user_id: str, label: str = "dev-1"):
    pub, priv = generate_ed25519_keypair()
    start = env["id_svc"].start_enrollment(user_id=user_id, ttl_seconds=60)
    pop = ed25519_sign(priv, start["nonce"].encode("utf-8"))
    res = env["id_svc"].enroll_device(
        enrollment_id=start["enrollment_id"],
        nonce=start["nonce"],
        label=label,
        public_key_b64=b64e(pub),
        proof_of_possession_b64=b64e(pop),
    )
    return res["device_id"], pub, priv, start


def test_enrollment_security_controls(env) -> None:
    alice = env["users"]["alice"]
    bob = env["users"]["bob"]
    dev_id, pub, priv, start = _enroll_new_device(env, alice, "alice-phone")

    # 1. Replayed nonce rejected
    with pytest.raises(NotAuthorized, match="invalid or already used"):
        env["id_svc"].enroll_device(
            enrollment_id=start["enrollment_id"],
            nonce=start["nonce"],
            label="replay",
            public_key_b64=b64e(pub),
            proof_of_possession_b64=b64e(ed25519_sign(priv, start["nonce"].encode())),
        )

    # 2. Expired nonce rejected
    s2 = env["id_svc"].start_enrollment(user_id=alice, ttl_seconds=10)
    env["clock"].advance(seconds=15)
    pub2, priv2 = generate_ed25519_keypair()
    with pytest.raises(NotAuthorized, match="expired"):
        env["id_svc"].enroll_device(
            enrollment_id=s2["enrollment_id"],
            nonce=s2["nonce"],
            label="exp",
            public_key_b64=b64e(pub2),
            proof_of_possession_b64=b64e(ed25519_sign(priv2, s2["nonce"].encode())),
        )

    # 3. Wrong proof-of-possession rejected
    s3 = env["id_svc"].start_enrollment(user_id=alice, ttl_seconds=60)
    _, wrong_priv = generate_ed25519_keypair()
    with pytest.raises(NotAuthorized, match="proof-of-possession"):
        env["id_svc"].enroll_device(
            enrollment_id=s3["enrollment_id"],
            nonce=s3["nonce"],
            label="bad-pop",
            public_key_b64=b64e(pub2),
            proof_of_possession_b64=b64e(ed25519_sign(wrong_priv, s3["nonce"].encode())),
        )

    # 4. Duplicate public key rejected
    s4 = env["id_svc"].start_enrollment(user_id=bob, ttl_seconds=60)
    with pytest.raises(Conflict, match="Duplicate"):
        env["id_svc"].enroll_device(
            enrollment_id=s4["enrollment_id"],
            nonce=s4["nonce"],
            label="dup",
            public_key_b64=b64e(pub),
            proof_of_possession_b64=b64e(ed25519_sign(priv, s4["nonce"].encode())),
        )

    # 5. Re-registering a revoked fingerprint permanently rejected
    with tx_session(env["sf"]) as session:
        d = session.get(Device, dev_id)
        assert d is not None
        transition_device_status(d, "revoked", env["clock"].now(), "lost")

    s5 = env["id_svc"].start_enrollment(user_id=bob, ttl_seconds=60)
    with pytest.raises(Revoked, match="revoked device"):
        env["id_svc"].enroll_device(
            enrollment_id=s5["enrollment_id"],
            nonce=s5["nonce"],
            label="reuse-revoked",
            public_key_b64=b64e(pub),
            proof_of_possession_b64=b64e(ed25519_sign(priv, s5["nonce"].encode())),
        )


def test_verify_identity_controls(env) -> None:
    alice = env["users"]["alice"]
    dev_id, _, priv, _ = _enroll_new_device(env, alice, "alice-yubi")

    # Valid verification
    ch1 = env["id_svc"].issue_challenge(dev_id)
    sig1 = ed25519_sign(priv, ch1["challenge"].encode("utf-8"))
    tok = env["id_svc"].verify_identity(device_id=dev_id, challenge=ch1["challenge"], signature_b64=b64e(sig1))
    assert tok["verified"] is True
    ctx = env["token_auth"].verify(tok["access_token"])
    assert ctx.user_id == alice and ctx.device_id == dev_id

    # Replayed challenge rejected
    with pytest.raises(NotAuthorized, match="already used"):
        env["id_svc"].verify_identity(device_id=dev_id, challenge=ch1["challenge"], signature_b64=b64e(sig1))

    # Bad signature rejected
    ch2 = env["id_svc"].issue_challenge(dev_id)
    _, wrong_priv = generate_ed25519_keypair()
    with pytest.raises(NotAuthorized, match="Invalid challenge signature"):
        env["id_svc"].verify_identity(
            device_id=dev_id,
            challenge=ch2["challenge"],
            signature_b64=b64e(ed25519_sign(wrong_priv, ch2["challenge"].encode())),
        )

    # Disabled user rejected
    with tx_session(env["sf"]) as session:
        u = session.get(User, alice)
        assert u is not None
        u.status = "disabled"
    ch3 = env["id_svc"].issue_challenge(dev_id)
    with pytest.raises(Revoked, match="disabled"):
        env["id_svc"].verify_identity(
            device_id=dev_id,
            challenge=ch3["challenge"],
            signature_b64=b64e(ed25519_sign(priv, ch3["challenge"].encode())),
        )

    # Re-enable user, revoke device -> rejected
    with tx_session(env["sf"]) as session:
        u = session.get(User, alice)
        assert u is not None
        u.status = "active"
        d = session.get(Device, dev_id)
        assert d is not None
        transition_device_status(d, "revoked", env["clock"].now(), "compromised")
    ch4 = env["id_svc"].issue_challenge(dev_id)
    with pytest.raises(Revoked, match="revoked"):
        env["id_svc"].verify_identity(
            device_id=dev_id,
            challenge=ch4["challenge"],
            signature_b64=b64e(ed25519_sign(priv, ch4["challenge"].encode())),
        )


@pytest.mark.parametrize(
    ("role_user", "perm", "expected_allow"),
    [
        ("alice", "resource:read", True),     # editor + owner
        ("alice", "resource:write", True),    # editor + owner
        ("alice", "key:rotate", False),       # editor lacks key:rotate
        ("bob", "resource:read", False),      # viewer non-owner without grant
        ("carol", "resource:read", False),    # admin non-owner without grant
    ],
)
def test_authorize_role_permission_matrix(env, role_user: str, perm: str, expected_allow: bool) -> None:
    uid = env["users"][role_user]
    dev_id, _, _, _ = _enroll_new_device(env, uid, f"{role_user}-dev")
    ctx = ActorContext(user_id=uid, device_id=dev_id, token_jti=str(uuid.uuid4()))
    dec = env["authz_svc"].authorize(ctx, "brief-alpha", perm)
    assert dec.allowed is expected_allow


def test_authorize_grants_unaffected_peer_and_fail_closed(env) -> None:
    alice = env["users"]["alice"]
    bob = env["users"]["bob"]
    alice_dev, _, _, _ = _enroll_new_device(env, alice, "alice-d")
    bob_dev, _, _, _ = _enroll_new_device(env, bob, "bob-d")

    bob_ctx = ActorContext(user_id=bob, device_id=bob_dev, token_jti=str(uuid.uuid4()))
    assert env["authz_svc"].authorize(bob_ctx, "brief-alpha", "resource:read").allowed is False

    # Grant resource:read to bob
    grant_id = str(uuid.uuid4())
    with tx_session(env["sf"]) as session:
        session.add(
            ResourceGrant(
                grant_id=grant_id,
                resource_id="brief-alpha",
                grantee_user_id=bob,
                permission="resource:read",
                granted_by=alice,
                granted_at=env["clock"].now(),
            )
        )
    assert env["authz_svc"].authorize(bob_ctx, "brief-alpha", "resource:read").allowed is True

    # Revoking alice's device leaves bob unaffected
    with tx_session(env["sf"]) as session:
        d = session.get(Device, alice_dev)
        assert d is not None
        transition_device_status(d, "revoked", env["clock"].now(), "lost")
    assert env["authz_svc"].authorize(bob_ctx, "brief-alpha", "resource:read").allowed is True

    # Revoking bob's grant denies bob
    with tx_session(env["sf"]) as session:
        g = session.get(ResourceGrant, grant_id)
        assert g is not None
        g.revoked_at = env["clock"].now()
    assert env["authz_svc"].authorize(bob_ctx, "brief-alpha", "resource:read").allowed is False

    # DB outage fails closed with STATE_UNAVAILABLE
    env["engine"].dispose()
    broken_authz = AuthzService(
        create_session_factory(create_db_engine("sqlite+pysqlite:////nonexistent_dir_xyz/bad.db")),
        env["clock"],
        AuditEmitter("node-a", env["clock"]),
        node_id="node-a",
    )
    outage_dec = broken_authz.authorize(bob_ctx, "brief-alpha", "resource:read")
    assert outage_dec.allowed is False
    assert outage_dec.reason_code == "STATE_UNAVAILABLE"


def test_actor_spoofing_ignored_and_audit_outbox_injection_proof(env) -> None:
    alice = env["users"]["alice"]
    bob = env["users"]["bob"]
    bob_dev, _, bob_priv, _ = _enroll_new_device(env, bob, 'bob\n{"actor":"alice"}')

    app = create_app(node_id="node-a", database_url=env["db_url"], clock=env["clock"])
    client = TestClient(app)

    ch = client.post(f"/api/v1/auth/challenge?device_id={bob_dev}").json()
    sig = ed25519_sign(bob_priv, ch["challenge"].encode("utf-8"))
    tok = client.post(
        "/api/v1/auth/verify",
        json={"device_id": bob_dev, "challenge": ch["challenge"], "signature_b64": b64e(sig)},
    ).json()["access_token"]

    # Bob tries to spoof actor_id=alice in body; server must use authenticated Bob and deny
    resp = client.post(
        "/api/v1/authorize",
        headers={"Authorization": f"Bearer {tok}"},
        json={"resource_id": "brief-alpha", "permission": "resource:read", "actor_id": alice},
    )
    assert resp.status_code == 200
    assert resp.json()["allowed"] is False

    # Transactional outbox: events persisted in DB before dispatch, survive restart, and pass verifier
    with tx_session(env["sf"]) as session:
        pending = session.execute(select(AuditOutbox).where(AuditOutbox.delivered_at.is_(None))).scalars().all()
        assert len(pending) >= 2

    delivered = env["dispatcher"].dispatch_pending()
    assert delivered >= 2
    ver = AuditLogVerifier().verify_file(env["log_path"])
    assert ver.is_valid is True
    assert ver.total_records == delivered
