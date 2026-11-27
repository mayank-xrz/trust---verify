"""Acceptance & adversarial tests for Track 4 vulnerability fixes & Phase 2 defense-in-depth."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from pqcrypto.kem import ml_kem_768

import track4_service
from demo.node.crypto_provider import MLDSASignature, MLKEMKeyExchange
from src.crypto import (
    SUITE_V2_PARANOID,
    DualIdentityKeypair,
    ParanoidHandshakeSession,
    SecureCryptoSystem,
)
from src.crypto._pqcrypto_compat import kem_decaps, kem_keygen
from src.crypto.agility import slh_dsa_sha2_128f
from src.crypto.delivery import ChunkReceiver, chunk_and_seal
from src.crypto.envelope import AEADFailedError, EnvelopeError, open_envelope, seal_envelope
from src.crypto.handshake import HandshakeError
from tests.conftest import read_audit_events

ROOT = Path(__file__).resolve().parents[1]


def test_protected_read_and_audit_interoperability(tmp_path: Path) -> None:
    env = {**os.environ, "TRACK4_STATE_DIR": str(tmp_path)}

    def call(req):
        res = subprocess.run(
            [sys.executable, str(ROOT / "track4_service.py")],
            input=json.dumps(req),
            text=True,
            capture_output=True,
            env=env,
        )
        assert res.returncode == 0, res.stderr
        return json.loads(res.stdout)

    assert call({
        "op": "setup",
        "owners": {"doc": "alice"},
        "contents": {"doc": "classified-body"},
        "disabled": [],
        "key_material": "k-mat",
    }) == {"ready": True}

    pk, sk = kem_keygen(ml_kem_768)
    resp = call({
        "op": "protected_read",
        "actor": "alice",
        "asset": "doc",
        "request_id": "pr-01",
        "challenge": "chal-xyz",
        "public_key": base64.b64encode(pk).decode("ascii"),
    })
    assert "ciphertext" in resp and "proof" in resp
    ss = kem_decaps(ml_kem_768, sk, base64.b64decode(resp["ciphertext"]))
    expected_proof = hmac.new(ss, b"chal-xyzclassified-body", hashlib.sha256).hexdigest()
    assert resp["proof"] == expected_proof

    # audit must also reflect protected_read decisions
    audit = call({"op": "audit", "request_id": "pr-01"})
    assert audit == {"request_id": "pr-01", "decision": "allow"}


def test_protected_read_state_dir_uses_durable_default_and_supports_legacy(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("TRACK4_STATE_DIR", raising=False)
    monkeypatch.setattr(track4_service.tempfile, "gettempdir", lambda: str(tmp_path))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))

    # Symlink trap must fail closed
    trap = tmp_path / f"track4-local-{os.getuid()}"
    target = tmp_path / "evil-target"
    target.mkdir()
    trap.symlink_to(target)
    with pytest.raises(Exception):
        track4_service.state_dir()
    trap.unlink()

    trap.mkdir(mode=0o700)
    assert track4_service.state_dir() == trap
    trap.rmdir()

    safe = track4_service.state_dir()
    assert safe == tmp_path / "state" / "trust-but-verify" / "track4-local"
    assert (safe.stat().st_mode & 0o777) == 0o700


def test_demo_node_fails_closed_without_classical_downgrade() -> None:
    with pytest.raises(RuntimeError):
        MLKEMKeyExchange(use_fallback=True)
    with pytest.raises(RuntimeError):
        MLDSASignature(use_fallback=True)


def test_track4_service_works_without_node_in_path(tmp_path: Path, monkeypatch) -> None:
    env = {**os.environ, "PATH": str(Path(sys.executable).parent), "TRACK4_STATE_DIR": str(tmp_path)}
    res = subprocess.run(
        [sys.executable, str(ROOT / "track4_service.py")],
        input=json.dumps({
            "op": "setup",
            "owners": {"a": "alice"},
            "contents": {"a": "no-node-needed"},
            "disabled": [],
            "key_material": "k",
        }),
        text=True,
        capture_output=True,
        env=env,
    )
    assert res.returncode == 0, res.stderr
    assert json.loads(res.stdout) == {"ready": True}

    pk, sk = kem_keygen(ml_kem_768)
    pr = subprocess.run(
        [sys.executable, str(ROOT / "track4_service.py")],
        input=json.dumps({
            "op": "protected_read",
            "actor": "alice",
            "asset": "a",
            "request_id": "r-nonode",
            "challenge": "c1",
            "public_key": base64.b64encode(pk).decode("ascii"),
        }),
        text=True,
        capture_output=True,
        env=env,
    )
    assert pr.returncode == 0, pr.stderr
    payload = json.loads(pr.stdout)
    ss = kem_decaps(ml_kem_768, sk, base64.b64decode(payload["ciphertext"]))
    assert payload["proof"] == hmac.new(ss, b"c1no-node-needed", hashlib.sha256).hexdigest()


def test_hybrid_lattice_plus_code_kem_roundtrip_and_dual_sigs() -> None:
    if slh_dsa_sha2_128f is None:
        with pytest.raises(HandshakeError, match="requires pqcrypto with SLH-DSA"):
            DualIdentityKeypair.generate()
        return
    alice_id = DualIdentityKeypair.generate()
    bob_id = DualIdentityKeypair.generate()

    bob_hs = ParanoidHandshakeSession("bob", "dev-b", bob_id)
    alice_hs = ParanoidHandshakeSession("alice", "dev-a", alice_id)

    hello = bob_hs.create_responder_hello()
    assert hello["suite"] == SUITE_V2_PARANOID
    assert bob_hs.has_ephemeral_secrets()

    init_msg, alice_keys = alice_hs.initiate(hello, bob_id.public_bundle())
    assert not alice_hs.has_ephemeral_secrets()

    bob_keys = bob_hs.complete_responder(init_msg, alice_id.public_bundle())
    assert not bob_hs.has_ephemeral_secrets()
    assert alice_keys.tx_key == bob_keys.rx_key
    assert alice_keys.rx_key == bob_keys.tx_key

    # Downgrade or forged SLH-DSA signature fails closed even if ML-DSA-87 is untouched
    bad_hello = dict(hello)
    bad_sig = bytearray(base64.b64decode(bad_hello["sig_slhdsa"]))
    bad_sig[0] ^= 0xFF
    bad_hello["sig_slhdsa"] = base64.b64encode(bytes(bad_sig)).decode("ascii")
    with pytest.raises(HandshakeError):
        ParanoidHandshakeSession("alice", "dev-a", alice_id).initiate(bad_hello, bob_id.public_bundle())


def test_key_committing_aead_rejects_key_substitution(runtime_identities) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    key1 = b"K" * 32
    key2 = b"L" * 32
    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-kc",
        session_key=key1,
        signing_secret_key=alice_sk,
        plaintext=b"key-commit-test",
        counter=0,
    )
    assert "commit_tag" in env
    with pytest.raises(AEADFailedError):
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b",
            session_key=key2,
            sender_public_key=alice_pk,
        )
    # Tampered commit_tag rejected even with valid key1
    tampered = dict(env)
    tampered["commit_tag"] = "00" * 32
    with pytest.raises(Exception):
        open_envelope(
            tampered,
            local_identity="bob",
            local_device="dev-b",
            session_key=key1,
            sender_public_key=alice_pk,
        )


def test_bucket_padding_hides_message_length(runtime_identities) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    key = b"P" * 32
    env_short = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-pad",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"A",
        counter=0,
        pad_bucket=256,
    )
    env_long = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-pad",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"B" * 200,
        counter=1,
        pad_bucket=256,
    )
    assert len(base64.b64decode(env_short["ciphertext"])) == len(base64.b64decode(env_long["ciphertext"]))
    assert open_envelope(env_short, local_identity="bob", local_device="dev-b", session_key=key, sender_public_key=alice_pk) == b"A"
    assert open_envelope(env_long, local_identity="bob", local_device="dev-b", session_key=key, sender_public_key=alice_pk) == b"B" * 200


def test_ephemeral_rekey_provides_post_compromise_security(tmp_path: Path) -> None:
    alice = SecureCryptoSystem(identity="alice", device="dev-a", state_dir=tmp_path / "alice")
    bob = SecureCryptoSystem(identity="bob", device="dev-b", state_dir=tmp_path / "bob")

    hello = bob.create_hello()
    init_msg, ak1 = alice.initiate_session(hello, bob.signing_public_key)
    bob.accept_session(init_msg, alice.signing_public_key)
    sid = ak1.session_id
    stolen_epoch1_key = alice._sessions[sid].tx_key

    # Asymmetric ephemeral rekey -> Epoch 2
    rekey_hello = bob.create_rekey_hello(sid)
    rekey_init, new_epoch_a = alice.initiate_rekey(sid, rekey_hello, bob.signing_public_key)
    new_epoch_b = bob.accept_rekey(sid, rekey_init, alice.signing_public_key)
    assert new_epoch_a == new_epoch_b == 2
    assert alice._sessions[sid].tx_key != stolen_epoch1_key

    # Epoch-2 message decrypts cleanly on Bob, cannot be decrypted with stolen epoch-1 key
    env_e2 = alice.encrypt(sid, b"post-compromise-healed", pad_bucket=128)
    assert bob.decrypt(env_e2, alice.signing_public_key) == b"post-compromise-healed"
    with pytest.raises(AEADFailedError):
        open_envelope(env_e2, local_identity="bob", local_device="dev-b", session_key=stolen_epoch1_key, sender_public_key=alice.signing_public_key)

    # Stale epoch-1 envelope is rejected at epoch 2 (0-grace cutoff)
    env_stale = alice.encrypt(sid, b"stale-epoch", epoch=1)
    with pytest.raises(EnvelopeError):
        bob.decrypt(env_stale, alice.signing_public_key)


def test_chunk_buffer_cap_defends_against_dos(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    key = b"D" * 32
    rx = ChunkReceiver(
        local_identity="bob",
        local_device="dev-b",
        audit_logger=crypto_audit_logger,
        max_active_messages=2,
    )
    for idx in range(3):
        envs = chunk_and_seal(
            sender_identity="alice",
            sender_device="dev-a",
            recipient_identity="bob",
            recipient_device="dev-b",
            session_id="sess-dos",
            session_key=key,
            signing_secret_key=alice_sk,
            plaintext=b"Z" * 2000,
            start_counter=idx * 10,
            chunk_size=1000,
            message_id=f"dos-msg-{idx}",
        )
        rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk)

    assert len(rx._buffers) == 2
    events = read_audit_events(audit_log_path)
    assert any(
        e["action"] == "delivery_failed_incomplete" and e["metadata"]["reason"] == "buffer_capacity_evicted"
        for e in events
    )
