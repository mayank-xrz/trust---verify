"""Delivery chunk-metadata binding and plaintext zeroization.

Objective 11 already reassembled/tamper-checked correctly, but a receiver would
happily mix chunks that disagreed on sender/session/chunk_count/whole hash
under one message_id, accepted absurd chunk counts, and left decrypted partial
plaintext copies in memory after a failed reassembly.
"""

from __future__ import annotations

import base64

import pytest
from pqcrypto.sign import ml_dsa_65

import src.crypto.delivery as delivery
from src.crypto._pqcrypto_compat import sig_keygen
from src.crypto.delivery import ChunkReceiver, DeliveryInvalidError, chunk_and_seal
from src.crypto.policy import MAX_FILE_SIZE_BYTES

SESSION_KEY = b"K" * 32
PAYLOAD = b"0123456789ab"  # 12 bytes -> 3 chunks of 4


def _seal(chunk_size: int = 4):
    public_key, secret_key = sig_keygen(ml_dsa_65)
    envelopes = chunk_and_seal(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-fix11",
        session_key=SESSION_KEY,
        signing_secret_key=secret_key,
        plaintext=PAYLOAD,
        chunk_size=chunk_size,
        message_id="msg-fix11",
    )
    return public_key, envelopes


def _receiver() -> ChunkReceiver:
    return ChunkReceiver(local_identity="bob", local_device="dev-b", clock=lambda: 1000.0)


def test_chunk_count_mismatch_fails_closed() -> None:
    public_key, envelopes = _seal()
    rx = _receiver()
    assert rx.ingest_chunk(envelopes[0], session_key=SESSION_KEY, sender_public_key=public_key) is None

    tampered = dict(envelopes[1])
    tampered["chunk_count"] = 99
    with pytest.raises(DeliveryInvalidError):
        rx.ingest_chunk(tampered, session_key=SESSION_KEY, sender_public_key=public_key)

    assert rx.failure_reports[-1]["reason"] == "chunk_metadata_mismatch"
    assert rx.pending_count() == 0


def test_sender_mismatch_fails_closed() -> None:
    public_key, envelopes = _seal()
    rx = _receiver()
    assert rx.ingest_chunk(envelopes[0], session_key=SESSION_KEY, sender_public_key=public_key) is None

    tampered = dict(envelopes[1])
    tampered["sender_identity"] = "mallory"
    with pytest.raises(DeliveryInvalidError):
        rx.ingest_chunk(tampered, session_key=SESSION_KEY, sender_public_key=public_key)
    assert rx.failure_reports[-1]["reason"] == "chunk_metadata_mismatch"


def test_absurd_chunk_count_rejected_before_buffering() -> None:
    public_key, envelopes = _seal()
    rx = _receiver()
    absurd = dict(envelopes[0])
    absurd["chunk_count"] = MAX_FILE_SIZE_BYTES + 1

    with pytest.raises(DeliveryInvalidError):
        rx.ingest_chunk(absurd, session_key=SESSION_KEY, sender_public_key=public_key)
    assert rx.failure_reports[-1]["reason"] == "chunk_count_exceeds_limit"
    assert rx.pending_count() == 0


def test_partial_plaintext_is_zeroized_on_failure(monkeypatch) -> None:
    public_key, envelopes = _seal()
    wiped: list[bytes] = []
    original = delivery._zeroize_bytes

    def spy(buf):
        if isinstance(buf, bytes) and buf:
            wiped.append(buf)
        original(buf)

    monkeypatch.setattr(delivery, "_zeroize_bytes", spy)

    rx = _receiver()
    assert rx.ingest_chunk(envelopes[0], session_key=SESSION_KEY, sender_public_key=public_key) is None
    assert rx.ingest_chunk(envelopes[1], session_key=SESSION_KEY, sender_public_key=public_key) is None

    # Corrupt the final chunk's ciphertext so reassembly fails after two chunks
    # have already been decrypted.
    broken = dict(envelopes[2])
    raw = bytearray(base64.b64decode(broken["ciphertext"]))
    raw[0] ^= 0xFF
    broken["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")

    with pytest.raises(DeliveryInvalidError):
        rx.ingest_chunk(broken, session_key=SESSION_KEY, sender_public_key=public_key)

    # The two decrypted 4-byte parts must have been overwritten with zeros.
    assert len(wiped) >= 2
    assert all(len(part) == 4 for part in wiped)
    assert all(part == b"\x00" * len(part) for part in wiped)
    assert rx.pending_count() == 0


def test_normal_inorder_and_reverse_still_reassemble() -> None:
    public_key, envelopes = _seal()
    for order in (envelopes, list(reversed(envelopes))):
        rx = _receiver()
        result = None
        for envelope in order:
            result = rx.ingest_chunk(
                envelope, session_key=SESSION_KEY, sender_public_key=public_key
            ) or result
        assert result == PAYLOAD
