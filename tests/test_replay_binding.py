"""Acceptance tests for Objective 1: Replay & Recipient Binding."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from src.audit.verifier import AuditLogVerifier
from src.crypto.envelope import (
    AEADFailedError,
    RecipientMismatchError,
    SignatureInvalidError,
    open_envelope,
    seal_envelope,
)
from src.crypto.handshake import EphemeralHandshakeSession
from src.crypto.replay_cache import (
    CounterOutOfWindowError,
    PersistentReplayCache,
    ReplayRejectedError,
)
from src.crypto.resumption import PersistentResumptionStore
from tests.conftest import extract_crypto_event, read_audit_events


def test_valid_message_accepted(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    session_key = b"S" * 32
    secret_marker = b"TOP_SECRET_PLAINTEXT_MARKER_001"

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id="sess-1",
        session_key=session_key,
        signing_secret_key=alice_sk,
        plaintext=secret_marker,
        counter=0,
        epoch=1,
    )
    pt = open_envelope(
        env,
        local_identity="bob",
        local_device="dev-b1",
        session_key=session_key,
        sender_public_key=alice_pk,
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    )
    assert pt == secret_marker
    events = read_audit_events(audit_log_path)
    assert any(e["action"] == "message_accepted" and e["metadata"]["reason"] == "ok" for e in events)
    assert secret_marker.decode("ascii") not in audit_log_path.read_text(encoding="utf-8")
    assert AuditLogVerifier().verify_file(str(audit_log_path)).is_valid


def test_recipient_aad_tamper_rejected(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    session_key = b"S" * 32

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id="sess-1",
        session_key=session_key,
        signing_secret_key=alice_sk,
        plaintext=b"sensitive",
        counter=0,
    )

    # 1. Wrong recipient identity/device rejected BEFORE decryption
    with pytest.raises(RecipientMismatchError):
        open_envelope(
            env,
            local_identity="charlie",
            local_device="dev-c1",
            session_key=session_key,
            sender_public_key=alice_pk,
            replay_cache=cache,
            audit_logger=crypto_audit_logger,
        )
    events = read_audit_events(audit_log_path)
    ev = extract_crypto_event(events[-1])
    assert ev["action"] == "message_rejected"
    assert ev["reason"] == "recipient_mismatch"
    print("EVENT_OBJ1:", json.dumps(ev))

    # 2. Tamper each of the 10 AAD fields -> all rejected
    tamper_values = {
        "sender_identity": "eve",
        "sender_device": "dev-evil",
        "recipient_identity": "eve",
        "recipient_device": "dev-evil",
        "session_id": "sess-tampered",
        "message_id": "msg-tampered",
        "counter": 999,
        "epoch": 999,
        "chunk_index": 99,
        "chunk_count": 99,
    }
    for field, bad_val in tamper_values.items():
        tampered = dict(env)
        aad_obj = json.loads(base64.b64decode(tampered["aad"]))
        aad_obj[field] = bad_val
        tampered["aad"] = base64.b64encode(json.dumps(aad_obj, sort_keys=True, separators=(",", ":")).encode()).decode()
        with pytest.raises((RecipientMismatchError, SignatureInvalidError, AEADFailedError)):
            open_envelope(
                tampered,
                local_identity="bob",
                local_device="dev-b1",
                session_key=session_key,
                sender_public_key=alice_pk,
                replay_cache=cache,
                audit_logger=crypto_audit_logger,
            )


def test_duplicate_message_rejected(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    session_key = b"S" * 32

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id="sess-dup",
        session_key=session_key,
        signing_secret_key=alice_sk,
        plaintext=b"once",
        counter=5,
    )
    assert open_envelope(
        env,
        local_identity="bob",
        local_device="dev-b1",
        session_key=session_key,
        sender_public_key=alice_pk,
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    ) == b"once"

    with pytest.raises(ReplayRejectedError):
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b1",
            session_key=session_key,
            sender_public_key=alice_pk,
            replay_cache=cache,
            audit_logger=crypto_audit_logger,
        )
    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "replay_rejected"
    assert events[-1]["metadata"]["reason"] == "replay_rejected"


def test_replay_cache_survives_restart(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    db_path = tmp_path / "persistent_replay.db"
    session_key = b"S" * 32

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id="sess-restart",
        session_key=session_key,
        signing_secret_key=alice_sk,
        plaintext=b"persist-me",
        counter=10,
    )

    cache1 = PersistentReplayCache(db_path)
    open_envelope(
        env,
        local_identity="bob",
        local_device="dev-b1",
        session_key=session_key,
        sender_public_key=alice_pk,
        replay_cache=cache1,
        audit_logger=crypto_audit_logger,
    )
    del cache1

    # Simulated restart with a brand new PersistentReplayCache instance
    cache2 = PersistentReplayCache(db_path)
    with pytest.raises(ReplayRejectedError):
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b1",
            session_key=session_key,
            sender_public_key=alice_pk,
            replay_cache=cache2,
            audit_logger=crypto_audit_logger,
        )
    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "replay_rejected"
    assert events[-1]["metadata"]["reason"] == "replay_rejected"


def test_counter_out_of_window_rejected(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db", window_size=4)
    session_key = b"S" * 32

    # Advance window to counter=10 (valid window becomes [7, 10])
    env_high = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id="sess-win",
        session_key=session_key,
        signing_secret_key=alice_sk,
        plaintext=b"high",
        counter=10,
    )
    open_envelope(
        env_high,
        local_identity="bob",
        local_device="dev-b1",
        session_key=session_key,
        sender_public_key=alice_pk,
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    )

    # Counter=2 is outside sliding window [7, 10]
    env_old = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id="sess-win",
        session_key=session_key,
        signing_secret_key=alice_sk,
        plaintext=b"stale",
        counter=2,
    )
    with pytest.raises(CounterOutOfWindowError):
        open_envelope(
            env_old,
            local_identity="bob",
            local_device="dev-b1",
            session_key=session_key,
            sender_public_key=alice_pk,
            replay_cache=cache,
            audit_logger=crypto_audit_logger,
        )
    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "counter_out_of_window"
    assert events[-1]["metadata"]["reason"] == "counter_out_of_window"


def test_no_secret_or_plaintext_leak_in_log_and_db(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    bob_pk, bob_sk = runtime_identities["bob"]
    replay_db = tmp_path / "replay_leak.db"
    resump_db = tmp_path / "resump_leak.db"

    bob_hs = EphemeralHandshakeSession("bob", "dev-b1", bob_sk)
    alice_hs = EphemeralHandshakeSession("alice", "dev-a1", alice_sk)
    hello = bob_hs.create_responder_hello()
    init_msg, alice_keys = alice_hs.initiate(hello, bob_pk)
    bob_keys = bob_hs.complete_responder(init_msg, alice_pk)

    plaintext_marker = b"PLAINTEXT_SECRET_MARKER_XYZ_987"
    session_key_hex_prefix = alice_keys.tx_key[:8].hex()
    eph_key_hex_prefix = alice_sk[:8].hex()

    cache = PersistentReplayCache(replay_db)
    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a1",
        recipient_identity="bob",
        recipient_device="dev-b1",
        session_id=alice_keys.session_id,
        session_key=alice_keys.tx_key,
        signing_secret_key=alice_sk,
        plaintext=plaintext_marker,
        counter=0,
    )
    assert open_envelope(
        env,
        local_identity="bob",
        local_device="dev-b1",
        session_key=bob_keys.rx_key,
        sender_public_key=alice_pk,
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    ) == plaintext_marker

    store = PersistentResumptionStore(resump_db, audit_logger=crypto_audit_logger)
    ticket = store.issue_ticket(
        session_id=alice_keys.session_id,
        peer_identity="alice",
        peer_device="dev-a1",
        original_transcript_hash=alice_keys.transcript_hash,
        resumption_secret=alice_keys.resumption_secret,
    )
    nonce = b"N" * 16
    pop = store.create_proof_of_possession(alice_keys.resumption_secret, nonce, "th-new")
    store.resume(
        ticket,
        presented_identity="alice",
        presented_device="dev-a1",
        fresh_nonce=nonce,
        proof_of_possession=pop,
        new_transcript_hash="th-new",
    )

    log_text = audit_log_path.read_text(encoding="utf-8")
    replay_bytes = replay_db.read_bytes()
    assert plaintext_marker.decode("ascii") not in log_text
    assert session_key_hex_prefix not in log_text
    assert eph_key_hex_prefix not in log_text
    assert plaintext_marker not in replay_bytes
    assert bytes.fromhex(session_key_hex_prefix) not in replay_bytes
