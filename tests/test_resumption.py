"""Acceptance tests for Objective 4: Peer-Bound Session Resumption."""

from __future__ import annotations
from pathlib import Path

import pytest

from src.crypto.resumption import (
    PersistentResumptionStore,
    ResumptionError,
    ResumptionExpiredError,
    ResumptionPeerMismatchError,
    ResumptionReplayedError,
)
from tests.conftest import extract_crypto_event, read_audit_events


def test_same_peer_resumes(tmp_path: Path, crypto_audit_logger, audit_log_path: Path) -> None:
    store = PersistentResumptionStore(tmp_path / "resumption.db", audit_logger=crypto_audit_logger)
    res_secret = b"R" * 32
    ticket = store.issue_ticket(
        session_id="sess-1",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig-1",
        resumption_secret=res_secret,
    )

    nonce = b"N" * 16
    pop = store.create_proof_of_possession(res_secret, nonce, "th-new-1")
    new_keys, rotated_ticket = store.resume(
        ticket,
        presented_identity="alice",
        presented_device="dev-a",
        fresh_nonce=nonce,
        proof_of_possession=pop,
        new_transcript_hash="th-new-1",
    )
    assert new_keys.session_id != "sess-1"
    assert new_keys.peer_identity == "alice"
    assert rotated_ticket["session_id"] == new_keys.session_id

    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "resumption_accepted"


def test_different_identity_same_session_id_rejected(tmp_path: Path, crypto_audit_logger, audit_log_path: Path) -> None:
    store = PersistentResumptionStore(tmp_path / "resumption.db", audit_logger=crypto_audit_logger)
    res_secret = b"R" * 32
    ticket = store.issue_ticket(
        session_id="sess-hijack",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=res_secret,
    )

    with pytest.raises(ResumptionPeerMismatchError):
        store.resume(
            ticket,
            presented_identity="mallory",
            presented_device="dev-m",
            fresh_nonce=b"N" * 16,
            proof_of_possession="anything",
            new_transcript_hash="th-new",
        )
    events = read_audit_events(audit_log_path)
    ev = extract_crypto_event(events[-1])
    assert ev["action"] == "resumption_peer_mismatch"
    assert events[-1]["metadata"]["presented_identity"] == "mallory"
    assert events[-1]["metadata"]["bound_identity"] == "alice"
    print("EVENT_OBJ4:", __import__("json").dumps(ev))


def test_expired_ticket_rejected(tmp_path: Path, crypto_audit_logger, audit_log_path: Path) -> None:
    now = [1000.0]
    store = PersistentResumptionStore(
        tmp_path / "resumption.db",
        audit_logger=crypto_audit_logger,
        clock=lambda: now[0],
    )
    res_secret = b"R" * 32
    ticket = store.issue_ticket(
        session_id="sess-exp",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=res_secret,
        ttl_seconds=60.0,
    )
    now[0] += 61.0
    nonce = b"N" * 16
    pop = store.create_proof_of_possession(res_secret, nonce, "th-new")
    with pytest.raises(ResumptionExpiredError):
        store.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-new",
        )
    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "resumption_expired"
    assert events[-1]["metadata"]["reason"] == "resumption_expired"


def test_replayed_ticket_rejected(tmp_path: Path, crypto_audit_logger, audit_log_path: Path) -> None:
    db_path = tmp_path / "resumption_restart.db"
    store1 = PersistentResumptionStore(db_path, audit_logger=crypto_audit_logger)
    res_secret = b"R" * 32
    ticket = store1.issue_ticket(
        session_id="sess-once",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=res_secret,
    )
    nonce1 = b"1" * 16
    pop1 = store1.create_proof_of_possession(res_secret, nonce1, "th-new-1")
    store1.resume(
        ticket,
        presented_identity="alice",
        presented_device="dev-a",
        fresh_nonce=nonce1,
        proof_of_possession=pop1,
        new_transcript_hash="th-new-1",
    )
    del store1

    # Simulated restart: new store instance on same SQLite DB
    store2 = PersistentResumptionStore(db_path, audit_logger=crypto_audit_logger)
    nonce2 = b"2" * 16
    pop2 = store2.create_proof_of_possession(res_secret, nonce2, "th-new-2")
    with pytest.raises(ResumptionReplayedError):
        store2.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce2,
            proof_of_possession=pop2,
            new_transcript_hash="th-new-2",
        )
    events = read_audit_events(audit_log_path)
    assert events[-1]["action"] == "resumption_replayed"
    assert events[-1]["metadata"]["reason"] == "resumption_replayed"


def test_ticket_bound_to_transcript(tmp_path: Path, crypto_audit_logger) -> None:
    store = PersistentResumptionStore(tmp_path / "resumption.db", audit_logger=crypto_audit_logger)
    res_secret = b"R" * 32
    ticket = store.issue_ticket(
        session_id="sess-th",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=res_secret,
    )
    nonce = b"N" * 16
    # PoP computed for "th-new-A", presented with "th-new-B" -> rejected
    pop = store.create_proof_of_possession(res_secret, nonce, "th-new-A")
    with pytest.raises(Exception):
        store.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-new-B",
        )


def test_resumption_missing_pop_rejected(tmp_path: Path, crypto_audit_logger) -> None:
    store = PersistentResumptionStore(tmp_path / "resumption.db", audit_logger=crypto_audit_logger)
    res_secret = b"R" * 32
    ticket = store.issue_ticket(
        session_id="sess-nopop",
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=res_secret,
    )
    with pytest.raises(ResumptionError):
        store.resume(
            ticket,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=b"N" * 16,
            proof_of_possession="",
            new_transcript_hash="th-new",
        )
