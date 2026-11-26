"""Regression tests for newly discovered security vulnerabilities."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pqcrypto.sign import ml_dsa_65

from src.audit.authority_monitor import AuthorityMonitor, LogIntegrityError
from src.audit.logger import AuditLogger
from src.crypto._pqcrypto_compat import sig_keygen, sig_sign
from src.crypto.handshake import EphemeralHandshakeSession, HandshakeError
from src.identity.backup import BackupIntegrityError, BackupManager
from src.identity.recovery import DeviceReEnrollment
from src.identity.revocation import RevocationCoordinator, RevocationEvent


def test_reenrollment_rejects_forged_proof_signature() -> None:
    cluster_secret = b"super-secret-cluster-key-32bytes"
    reenroll = DeviceReEnrollment(cluster_secret)
    nonce = reenroll.issue_challenge("node-1")

    new_pk, new_sk = sig_keygen(ml_dsa_65)
    challenge_resp = hashlib.sha3_256(cluster_secret + nonce + new_pk).digest()

    # Empty or forged proof_signature must fail even when challenge_response is valid
    assert not reenroll.verify_re_enrollment("node-1", challenge_resp, new_pk, b"")

    nonce2 = reenroll.issue_challenge("node-1")
    challenge_resp2 = hashlib.sha3_256(cluster_secret + nonce2 + new_pk).digest()
    assert not reenroll.verify_re_enrollment("node-1", challenge_resp2, new_pk, b"forged-sig")

    # Valid ML-DSA-65 proof-of-possession signature succeeds
    nonce3 = reenroll.issue_challenge("node-1")
    challenge_resp3 = hashlib.sha3_256(cluster_secret + nonce3 + new_pk).digest()
    signed_msg = b"track4/v1/reenroll\x00" + b"node-1" + b"\x00" + nonce3 + new_pk
    valid_sig = sig_sign(ml_dsa_65, new_sk, signed_msg)
    assert reenroll.verify_re_enrollment("node-1", challenge_resp3, new_pk, valid_sig)


def test_revocation_coordinator_rejects_unsigned_or_forged_broadcasts() -> None:
    origin = RevocationCoordinator("node-origin", require_signatures=True)
    peer = RevocationCoordinator("node-peer", require_signatures=True)

    origin_pk, origin_sk = sig_keygen(ml_dsa_65)
    peer.register_trusted_signer("node-origin", origin_pk)

    # Forged unsigned revocation must be rejected
    forged = RevocationEvent(
        revocation_id="rev-forged-1",
        key_id="key-victim",
        target_node_id="node-victim",
        revoked_by="node-origin",
        reason="forged",
        timestamp_ns=123456789,
        signature_b64="",
        revocation_epoch=1,
    )
    assert peer.receive_revocation(forged, "node-attacker") is False
    assert peer.is_revoked("key-victim") is False

    # Validly signed revocation from trusted origin succeeds
    valid_event = origin.create_revocation("key-victim", "node-victim", "compromised", signer=origin_sk)
    assert peer.receive_revocation(valid_event, "node-origin") is True
    assert peer.is_revoked("key-victim") is True

    # Stale epoch rollback must be rejected
    stale = RevocationEvent(
        revocation_id="rev-stale-0",
        key_id="key-other",
        target_node_id="node-other",
        revoked_by="node-origin",
        reason="rollback",
        timestamp_ns=123456790,
        signature_b64=valid_event.signature_b64,
        revocation_epoch=0,
    )
    # Even if epoch=0 is skipped, epoch < current (e.g. 0 vs 1) or bad signature fails
    assert peer.receive_revocation(stale, "node-attacker") is False


def test_handshake_complete_responder_rejects_identity_and_session_misbinding() -> None:
    bob_pk, bob_sk = sig_keygen(ml_dsa_65)
    alice_pk, alice_sk = sig_keygen(ml_dsa_65)
    eve_pk, eve_sk = sig_keygen(ml_dsa_65)

    bob = EphemeralHandshakeSession("bob", "dev-bob", bob_sk)
    eve = EphemeralHandshakeSession("eve", "dev-eve", eve_sk)
    alice = EphemeralHandshakeSession("alice", "dev-alice", alice_sk)

    _bob_hello = bob.create_responder_hello()
    eve_hello = eve.create_responder_hello()

    # Alice initiates with Eve's hello, then an attacker feeds Alice's init_msg to Bob
    init_msg_for_eve, _ = alice.initiate(eve_hello, eve_pk)
    with pytest.raises(HandshakeError, match="does not match responder identity"):
        bob.complete_responder(init_msg_for_eve, alice_pk)
    # Ephemerals must be wiped on failure
    assert not bob.has_ephemeral_secrets()


def test_authority_monitor_rejects_whole_log_replacement(tmp_path: Path) -> None:
    monitor = AuthorityMonitor(node_id="console-1", state_dir=tmp_path)
    monitor.grant_authority(user_id="alice", role="admin", granted_by="root")
    monitor.verify_log_integrity()

    # Attacker replaces authority_audit.log from genesis with a valid fresh SHA-256 chain
    log_path = Path(monitor.audit_logger.log_file_path)
    log_path.unlink()
    forged_logger = AuditLogger("console-1", str(log_path))
    forged_logger.log_event(
        service="console-1",
        action="BENIGN_EVENT",
        subject="alice",
        resource="console/config",
        status="SUCCESS",
    )

    with pytest.raises(LogIntegrityError, match="Audit log integrity check failed"):
        monitor.verify_log_integrity()


def test_backup_manager_rejects_malformed_mac_and_algorithm(tmp_path: Path) -> None:
    mgr = BackupManager(b"k" * 32)
    bak_path = tmp_path / "state.bak"
    mgr.create_backup({"k": "v"}, str(bak_path))

    data = json.loads(bak_path.read_text(encoding="utf-8"))
    data["manifest"]["mac"] = "not-hex!"
    bak_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BackupIntegrityError, match="Malformed backup MAC"):
        mgr.verify_and_restore(str(bak_path))

    data["manifest"]["algorithm"] = "NONE"
    bak_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(BackupIntegrityError, match="Unsupported or missing backup MAC algorithm"):
        mgr.verify_and_restore(str(bak_path))


def test_envelope_aead_failure_does_not_poison_replay_cache(tmp_path: Path) -> None:
    from src.crypto.envelope import AEADFailedError, open_envelope, seal_envelope
    from src.crypto.replay_cache import PersistentReplayCache

    alice_pk, alice_sk = sig_keygen(ml_dsa_65)
    key = b"k" * 32
    wrong_key = b"w" * 32
    rcache = PersistentReplayCache(tmp_path / "replay.db")

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-atom",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"atomic-replay",
        counter=1,
        epoch=1,
    )

    with pytest.raises(AEADFailedError):
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b",
            session_key=wrong_key,
            sender_public_key=alice_pk,
            replay_cache=rcache,
        )

    # Genuine decryption with the right key must still succeed
    assert (
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b",
            session_key=key,
            sender_public_key=alice_pk,
            replay_cache=rcache,
        )
        == b"atomic-replay"
    )


def test_token_verify_rejects_future_iat_beyond_clock_skew() -> None:
    from datetime import datetime, timedelta, timezone

    from src.identity_keys.clock import FakeClock
    from src.identity_keys.errors import NotAuthorized
    from src.identity_keys.tokens import TokenAuthority

    t0 = datetime(2026, 11, 27, 0, 0, 0, tzinfo=timezone.utc)
    issuer_clock = FakeClock(t0 + timedelta(seconds=120))
    verifier_clock = FakeClock(t0)

    ts_issue = TokenAuthority(issuer_clock, ttl_seconds=600)
    token = ts_issue.issue("u1", "d1")
    ts_verify = TokenAuthority(verifier_clock, ttl_seconds=600)
    ts_verify._pub, ts_verify._priv = ts_issue._pub, ts_issue._priv

    with pytest.raises(NotAuthorized, match="future"):
        ts_verify.verify(token, max_clock_skew_seconds=30)


def test_demo_node_preserves_active_key_across_restart(tmp_path: Path) -> None:
    from demo.node.adapters import NodeAdapters

    data_dir = str(tmp_path / "demo_data")
    node1 = NodeAdapters(node_id="node-restart", data_dir=data_dir)
    key1 = node1.identity.key_manager.get_active_key()
    assert key1 is not None

    node2 = NodeAdapters(node_id="node-restart", data_dir=data_dir)
    key2 = node2.identity.key_manager.get_active_key()
    assert key2 is not None
    assert key2.key_id == key1.key_id
