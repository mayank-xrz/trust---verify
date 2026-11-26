"""FIX-01 regression tests: signed rotation cutoffs, clock high-water, key_version binding."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest
from pqcrypto.sign import ml_dsa_65
from sqlalchemy import select, text

from alembic import command
from alembic.config import Config
from scripts.seed_sandbox import seed_database
from src.crypto._pqcrypto_compat import sig_keygen
from src.crypto.envelope import (
    AEADFailedError,
    SignatureInvalidError,
    open_envelope,
    seal_envelope,
)
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import b64e
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.models import AuditOutbox, Device
from src.identity_keys.rotation import RotationService
from src.identity_keys.services import AuthzService
from src.identity_keys.tokens import ActorContext

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fix01_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WRAP_MASTER_KEY_B64", b64e(os.urandom(32)))
    monkeypatch.setenv("CLUSTER_SYNC_SECRET", "fix01-cluster-secret")
    db_url = f"sqlite+pysqlite:///{tmp_path / 'fix01.db'}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    rot_svc = RotationService(sf, clock, emitter, node_id="node-a")
    authz_svc = AuthzService(sf, clock, emitter, node_id="node-a")
    admin_ctx = ActorContext(users["carol"], "dev-carol", "jti-admin")
    with tx_session(sf) as session:
        dev = session.execute(select(Device).where(Device.user_id == users["alice"])).scalars().first()
    alice_ctx = ActorContext(users["alice"], dev.device_id, "jti-alice")
    return {
        "sf": sf,
        "clock": clock,
        "users": users,
        "rot_svc": rot_svc,
        "authz_svc": authz_svc,
        "admin_ctx": admin_ctx,
        "alice_ctx": alice_ctx,
    }


def _rotate(env) -> str:
    old_id = env["rot_svc"].create_initial_key_set("ks-auth", "auth")
    env["rot_svc"].initiate_rotation(
        key_set_id="ks-auth",
        grace_seconds=30,
        idempotency_key="fix01-rot-1",
        actor_ctx=env["admin_ctx"],
    )
    return old_id


def test_clock_rewind_after_cutoff_is_rejected(fix01_env) -> None:
    env = fix01_env
    old_id = _rotate(env)

    env["clock"].advance(seconds=31)
    after_cutoff = env["authz_svc"].authorize(
        env["alice_ctx"], "brief-alpha", "resource:read", key_version_id=old_id
    )
    assert after_cutoff.allowed is False
    assert after_cutoff.reason_code == "KEY_RETIRED"

    # Attacker/operator rewinds the wall clock to before the signed cutoff.
    env["clock"].advance(seconds=-20)
    rewound = env["authz_svc"].authorize(
        env["alice_ctx"], "brief-alpha", "resource:read", key_version_id=old_id
    )
    assert rewound.allowed is False
    assert rewound.reason_code == "CLOCK_ROLLBACK_DETECTED"

    with tx_session(env["sf"]) as session:
        events = [
            e
            for e in session.execute(select(AuditOutbox)).scalars().all()
            if e.payload.get("action") == "clock.rollback_detected"
        ]
    assert events, "clock rollback must be recorded in the audit outbox"


def test_grace_requires_valid_signed_cutoff(fix01_env) -> None:
    env = fix01_env
    old_id = _rotate(env)

    with tx_session(env["sf"]) as session:
        row = session.execute(
            text(
                "SELECT signature, signer_key_id FROM rotation_cutoffs "
                "WHERE key_version_id = :kv"
            ),
            {"kv": old_id},
        ).first()
        assert row is not None
        assert row.signature
        assert row.signer_key_id

    env["clock"].advance(seconds=15)
    inside_grace = env["authz_svc"].authorize(
        env["alice_ctx"], "brief-alpha", "resource:read", key_version_id=old_id
    )
    assert inside_grace.allowed is True

    # Removing the signed cutoff must fail closed, even inside the grace window.
    with tx_session(env["sf"]) as session:
        session.execute(
            text("DELETE FROM rotation_cutoffs WHERE key_version_id = :kv"), {"kv": old_id}
        )
    unsigned = env["authz_svc"].authorize(
        env["alice_ctx"], "brief-alpha", "resource:read", key_version_id=old_id
    )
    assert unsigned.allowed is False
    assert unsigned.reason_code == "KEY_CUTOFF_UNSIGNED"


def test_tampered_cutoff_body_is_rejected(fix01_env) -> None:
    env = fix01_env
    old_id = _rotate(env)

    with tx_session(env["sf"]) as session:
        row = session.execute(
            text("SELECT body_json FROM rotation_cutoffs WHERE key_version_id = :kv"),
            {"kv": old_id},
        ).first()
        assert row is not None
        body = json.loads(row.body_json)
        body["grace_until"] = "2099-01-01T00:00:00+00:00"
        session.execute(
            text("UPDATE rotation_cutoffs SET body_json = :body WHERE key_version_id = :kv"),
            {"body": json.dumps(body, sort_keys=True, separators=(",", ":")), "kv": old_id},
        )

    env["clock"].advance(seconds=15)
    tampered = env["authz_svc"].authorize(
        env["alice_ctx"], "brief-alpha", "resource:read", key_version_id=old_id
    )
    assert tampered.allowed is False
    assert tampered.reason_code in {"KEY_CUTOFF_INVALID", "KEY_CUTOFF_MISMATCH"}


def test_authz_audit_metadata_contains_key_version(fix01_env) -> None:
    env = fix01_env
    old_id = _rotate(env)
    env["clock"].advance(seconds=15)
    decision = env["authz_svc"].authorize(
        env["alice_ctx"], "brief-alpha", "resource:read", key_version_id=old_id
    )
    assert decision.allowed is True
    with tx_session(env["sf"]) as session:
        event = next(
            (
                e
                for e in session.execute(select(AuditOutbox)).scalars().all()
                if e.payload.get("action") == "authz.resource:read"
            ),
            None,
        )
    assert event is not None
    metadata = event.payload["metadata"]
    assert metadata["key_version"] == old_id
    assert metadata["key_version_id"] == old_id


def test_envelope_binds_key_version() -> None:
    public_key, secret_key = sig_keygen(ml_dsa_65)
    session_key = os.urandom(32)
    envelope = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-1",
        session_key=session_key,
        signing_secret_key=secret_key,
        plaintext=b"bound message",
        counter=1,
        key_version="kv-old",
    )
    assert envelope["key_version"] == "kv-old"
    aad = json.loads(base64.b64decode(envelope["aad"]))
    assert aad["key_version"] == "kv-old"

    plaintext = open_envelope(
        envelope,
        local_identity="bob",
        local_device="dev-b",
        session_key=session_key,
        sender_public_key=public_key,
        check_replay=False,
    )
    assert plaintext == b"bound message"

    tampered = dict(envelope)
    tampered["key_version"] = "kv-new"
    with pytest.raises((SignatureInvalidError, AEADFailedError)):
        open_envelope(
            tampered,
            local_identity="bob",
            local_device="dev-b",
            session_key=session_key,
            sender_public_key=public_key,
            check_replay=False,
        )
