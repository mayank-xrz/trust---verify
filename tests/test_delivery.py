"""Acceptance tests for Objective 3: Delivery Under Loss / Reordering."""

from __future__ import annotations
import base64
from pathlib import Path

import pytest

from src.crypto.delivery import (
    ChunkReceiver,
    DeliveryInvalidError,
    chunk_and_seal,
    derive_chunk_nonce,
)
from src.crypto.replay_cache import PersistentReplayCache
from tests.conftest import extract_crypto_event, read_audit_events


def test_reordered_chunks_deliver(tmp_path: Path, runtime_identities, crypto_audit_logger) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    key = b"D" * 32
    payload = b"0123456789" * 300  # 3000 bytes -> 3 chunks of 1000

    envs = chunk_and_seal(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-deliv",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=payload,
        chunk_size=1000,
    )
    assert len(envs) == 3

    rx = ChunkReceiver(
        local_identity="bob",
        local_device="dev-b",
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    )
    # Deliver out of order: 2, 0, 1
    assert rx.ingest_chunk(envs[2], session_key=key, sender_public_key=alice_pk) is None
    assert rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk) is None
    reassembled = rx.ingest_chunk(envs[1], session_key=key, sender_public_key=alice_pk)
    assert reassembled == payload


def test_missing_chunk_reports_incomplete(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    key = b"D" * 32
    now = [1000.0]

    rx = ChunkReceiver(
        local_identity="bob",
        local_device="dev-b",
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
        timeout_seconds=10.0,
        clock=lambda: now[0],
    )
    envs = chunk_and_seal(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-loss",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"X" * 2500,
        chunk_size=1000,
    )
    assert rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk) is None
    assert rx.ingest_chunk(envs[2], session_key=key, sender_public_key=alice_pk) is None

    now[0] += 11.0
    reports = rx.check_timeouts()
    assert len(reports) == 1
    assert reports[0]["action"] == "delivery_failed_incomplete"
    assert reports[0]["missing_chunks"] == [1]

    events = read_audit_events(audit_log_path)
    ev = extract_crypto_event(events[-1])
    assert ev["action"] == "delivery_failed_incomplete"
    assert events[-1]["metadata"]["missing_chunks"] == "1"
    print("EVENT_OBJ3:", __import__("json").dumps(ev))


def test_corrupt_chunk_discarded(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    key = b"D" * 32

    rx = ChunkReceiver(
        local_identity="bob",
        local_device="dev-b",
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    )
    envs = chunk_and_seal(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-corrupt",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"Y" * 2500,
        chunk_size=1000,
    )

    # Corrupt ciphertext of chunk 1
    bad_ct = bytearray(base64.b64decode(envs[1]["ciphertext"]))
    bad_ct[0] ^= 0xFF
    envs[1]["ciphertext"] = base64.b64encode(bytes(bad_ct)).decode("ascii")

    assert rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk) is None
    assert rx.ingest_chunk(envs[1], session_key=key, sender_public_key=alice_pk) is None
    with pytest.raises(DeliveryInvalidError):
        rx.ingest_chunk(envs[2], session_key=key, sender_public_key=alice_pk)

    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "delivery_failed_invalid"
    assert events[-1]["metadata"]["chunk_index"] == 1


def test_duplicate_chunk_handled(tmp_path: Path, runtime_identities, crypto_audit_logger, audit_log_path: Path) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    cache = PersistentReplayCache(tmp_path / "replay.db")
    key = b"D" * 32

    rx = ChunkReceiver(
        local_identity="bob",
        local_device="dev-b",
        replay_cache=cache,
        audit_logger=crypto_audit_logger,
    )
    envs = chunk_and_seal(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-dup-chunk",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"Z" * 1500,
        chunk_size=1000,
    )
    assert rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk) is None
    # Duplicate chunk 0 ignored consistently and logged once
    assert rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk) is None
    assert rx.ingest_chunk(envs[0], session_key=key, sender_public_key=alice_pk) is None
    assert rx.ingest_chunk(envs[1], session_key=key, sender_public_key=alice_pk) == b"Z" * 1500

    dup_events = [
        e for e in read_audit_events(audit_log_path)
        if e["action"] == "message_rejected" and e["metadata"].get("reason") == "duplicate_chunk"
    ]
    assert len(dup_events) == 1


def test_nonce_uniqueness() -> None:
    key1 = b"A" * 32
    key2 = b"B" * 32
    seen = set()
    for mid in ("msg-1", "msg-2"):
        for idx in range(50):
            n1 = derive_chunk_nonce(key1, mid, idx)
            n2 = derive_chunk_nonce(key2, mid, idx)
            assert len(n1) == 12
            assert n1 not in seen
            assert n2 not in seen
            seen.add(n1)
            seen.add(n2)
