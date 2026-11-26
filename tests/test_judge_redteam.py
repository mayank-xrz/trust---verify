"""Adversarial vulnerability tests simulating hackathon judges and automated red-team bots."""

from __future__ import annotations

import copy
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest
from pqcrypto.sign import ml_dsa_65

from src.audit.authority_monitor import (
    AuthorityMonitor,
    LogIntegrityError,
    SuspiciousAuthorityError,
)
from src.crypto._pqcrypto_compat import sig_keygen
from src.crypto.delivery import ChunkReceiver, DeliveryInvalidError, chunk_and_seal
from src.crypto.envelope import (
    EnvelopeError,
    RecipientMismatchError,
    SignatureInvalidError,
    open_envelope,
    seal_envelope,
)
from src.crypto.policy import (
    MAX_FILE_SIZE_BYTES,
    DeviceLimitExceededError,
    DevicePolicyError,
    FileSizeLimitError,
    MediaFormatError,
    SingleDeviceRegistry,
    TimezoneMismatchError,
    validate_shared_file,
)
from src.crypto.replay_cache import PersistentReplayCache
from src.crypto.resumption import (
    PersistentResumptionStore,
    ResumptionError,
    ResumptionPeerMismatchError,
    ResumptionReplayedError,
)


def test_bot_envelope_tamper_matrix(tmp_path: Path) -> None:
    """Bot mutates every critical envelope field; all must fail closed without poisoning replay."""
    alice_pk, alice_sk = sig_keygen(ml_dsa_65)
    key = b"K" * 32
    rcache = PersistentReplayCache(tmp_path / "replay.db")

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-bot-1",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"sensitive-payload",
        counter=1,
        epoch=1,
    )

    # 1. Cross-recipient & cross-device confusion
    for bad_id, bad_dev in [("eve", "dev-b"), ("bob", "dev-other")]:
        with pytest.raises(RecipientMismatchError):
            open_envelope(
                env,
                local_identity=bad_id,
                local_device=bad_dev,
                session_key=key,
                sender_public_key=alice_pk,
                replay_cache=rcache,
            )

    # 2. Tampered signature / header fields
    for field, bad_val in [
        ("signature", "00" * 64),
        ("session_id", "sess-tampered"),
        ("counter", 2),
        ("epoch", 99),
    ]:
        tampered = copy.deepcopy(env)
        tampered[field] = bad_val
        with pytest.raises((SignatureInvalidError, EnvelopeError)):
            open_envelope(
                tampered,
                local_identity="bob",
                local_device="dev-b",
                session_key=key,
                sender_public_key=alice_pk,
                replay_cache=rcache,
            )

    # 3. Genuine envelope must still succeed (none of the attacks burned counter=1)
    assert (
        open_envelope(
            env,
            local_identity="bob",
            local_device="dev-b",
            session_key=key,
            sender_public_key=alice_pk,
            replay_cache=rcache,
        )
        == b"sensitive-payload"
    )


def test_bot_chunk_delivery_malformed_and_partial_discard() -> None:
    """Bot injects out-of-bounds chunk_index or corrupt chunk; buffer must discard completely."""
    alice_pk, alice_sk = sig_keygen(ml_dsa_65)
    key = b"C" * 32
    chunks = chunk_and_seal(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id="sess-chunk-bot",
        session_key=key,
        signing_secret_key=alice_sk,
        plaintext=b"X" * 2500,
        start_counter=0,
        chunk_size=1000,
    )

    receiver = ChunkReceiver(local_identity="bob", local_device="dev-b")
    assert receiver.ingest_chunk(chunks[0], session_key=key, sender_public_key=alice_pk) is None
    assert receiver.pending_count() == 1

    # Tamper chunk 1 ciphertext and complete delivery -> must raise and discard buffered chunks
    bad_chunk = copy.deepcopy(chunks[1])
    bad_chunk["ciphertext"] = "AAAA" + bad_chunk["ciphertext"][4:]
    receiver.ingest_chunk(bad_chunk, session_key=key, sender_public_key=alice_pk)
    with pytest.raises(DeliveryInvalidError):
        receiver.ingest_chunk(chunks[2], session_key=key, sender_public_key=alice_pk)
    assert receiver.pending_count() == 0
    assert len(receiver.failure_reports) >= 1


def test_bot_resumption_forgery_and_pop_tamper(tmp_path: Path) -> None:
    """Bot forges ticket fields, swaps transcript hash, or replays consumed ticket."""
    store = PersistentResumptionStore(tmp_path / "resump.db")
    secret = secrets.token_bytes(32)
    ticket = store.issue_ticket(
        session_id="sess-r1",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=secret,
    )
    nonce = secrets.token_bytes(16)
    pop = store.create_proof_of_possession(secret, nonce, "th-new")

    # Wrong transcript hash in PoP check
    with pytest.raises(ResumptionError):
        store.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-wrong",
        )

    # Tampered peer_identity_hash
    bad_ticket = copy.deepcopy(ticket)
    bad_ticket["peer_identity_hash"] = "0" * 64
    with pytest.raises(ResumptionPeerMismatchError):
        store.resume(
            bad_ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-new",
        )

    # Valid resume succeeds once, then replay is rejected
    store.resume(
        ticket,
        presented_identity="alice",
        presented_device="dev-a",
        fresh_nonce=nonce,
        proof_of_possession=pop,
        new_transcript_hash="th-new",
    )
    with pytest.raises(ResumptionReplayedError):
        store.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-new",
        )


def test_bot_file_upload_traversal_polyglot_and_size_bypass() -> None:
    """Bot tries path traversal, executable polyglot disguised as PNG, and 20MB+1 bypass."""
    with pytest.raises(MediaFormatError):
        validate_shared_file("../../etc/passwd.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 16)

    with pytest.raises(MediaFormatError):
        validate_shared_file("payload.sh", b"#!/bin/sh\nid\n")

    with pytest.raises(MediaFormatError):
        validate_shared_file("elf.png", b"\x7fELF\x02\x01\x01\x00")

    with pytest.raises(FileSizeLimitError):
        validate_shared_file("huge.png", b"\x89PNG\r\n\x1a\n" + b"A" * MAX_FILE_SIZE_BYTES)


def test_bot_single_device_and_timezone_bypass(tmp_path: Path) -> None:
    """Bot tries 2nd device registration, revoked device reuse, and timezone spoofing."""
    reg = SingleDeviceRegistry(tmp_path / "devices.db")
    reg.register_device("alice", "dev-1")
    reg.verify_access_timezone("alice", "dev-1", "Asia/Kolkata")

    with pytest.raises(DeviceLimitExceededError):
        reg.register_device("alice", "dev-2")

    with pytest.raises(TimezoneMismatchError):
        reg.verify_access_timezone("alice", "dev-1", "Mars/Olympus")

    with pytest.raises(TimezoneMismatchError):
        reg.verify_access_timezone("alice", "dev-1", "America/New_York")

    reg.revoke_device("alice", "dev-1")
    with pytest.raises(DevicePolicyError):
        reg.register_device("alice", "dev-1")


def test_bot_authority_escalation_and_log_tamper(tmp_path: Path) -> None:
    """Bot grants admin, attempts to disable audit, and tampers with audit log."""
    mon = AuthorityMonitor(node_id="console-1", state_dir=tmp_path / "mon")
    mon.grant_authority(user_id="eve", role="admin", granted_by="root")

    with pytest.raises(SuspiciousAuthorityError):
        mon.execute_console_action(
            user_id="eve",
            action="DISABLE_AUDIT",
            proposed_changes={"audit_enabled": False},
        )
    assert mon.console_state["audit_enabled"] is True

    # Tamper with audit log (line 1 is the first JSON record after the header)
    log_path = Path(mon.audit_logger.log_file_path)
    lines = log_path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace("AUTHORITY_GRANTED", "TAMPERED_ACTION")
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(LogIntegrityError):
        mon.verify_log_integrity()


def test_bot_track4_service_no_secret_leak_and_wrong_owner_denied(tmp_path: Path) -> None:
    """Bot invokes track4_service.py directly and checks secret non-leakage & cross-owner denial."""
    repo_root = Path(__file__).resolve().parent.parent
    env = {**os.environ, "TRACK4_STATE_DIR": str(tmp_path)}
    secret_marker = "SUPER-SECRET-BOT-CANARY-9999"

    def _run(payload: dict) -> dict:
        proc = subprocess.run(
            [sys.executable, str(repo_root / "track4_service.py")],
            input=json.dumps(payload),
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        assert secret_marker not in proc.stdout
        assert secret_marker not in proc.stderr
        return json.loads(proc.stdout)

    setup = _run({
        "op": "setup",
        "owners": {"secret-doc": "alice"},
        "contents": {"secret-doc": secret_marker},
        "disabled": [],
        "key_material": "bot-test-key",
    })
    assert setup["ready"] is True

    denied = _run({
        "op": "read",
        "request_id": "bot-read-mallory",
        "actor": "mallory",
        "asset": "secret-doc",
    })
    assert denied["decision"] == "deny"
    assert "body" not in denied and "content" not in denied

    # Plaintext asset downgrade in state.json must be rejected by _decrypt_asset
    from src.crypto.primitives import CryptoError
    from track4_service import _decrypt_asset
    with pytest.raises(CryptoError, match="unauthenticated"):
        _decrypt_asset(b"k" * 32, "secret-doc", "plaintext-downgrade")
