"""FIX-04 regression tests: ML-DSA-65 resumption tickets and peer identity hash."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from pqcrypto.sign import ml_dsa_65

from src.crypto._pqcrypto_compat import sig_verify
from src.crypto.resumption import (
    PersistentResumptionStore,
    ResumptionError,
    ResumptionPeerMismatchError,
)

TICKET_DOMAIN = b"track4/v1/ticket\x00"
POP_DOMAIN = b"track4/v1/resume-pop\x00"
SECRET = b"R" * 32
NONCE = b"N" * 16


def _store(tmp_path: Path, name: str = "resumption.db") -> PersistentResumptionStore:
    return PersistentResumptionStore(tmp_path / name)


def _issue(store: PersistentResumptionStore, session_id: str = "sess-fix04"):
    return store.issue_ticket(
        session_id=session_id,
        peer_identity="alice",
        peer_device="dev-a",
        original_transcript_hash="th-orig",
        resumption_secret=SECRET,
    )


def test_ticket_is_mldsa_signed_and_binds_peer_identity_hash(tmp_path: Path) -> None:
    store = _store(tmp_path)
    ticket = _issue(store)

    expected_hash = hashlib.sha256(b"alice").hexdigest()
    assert ticket["peer_identity_hash"] == expected_hash
    assert "signature" in ticket
    assert "mac" not in ticket

    body = store._canonical_ticket_body(ticket)
    assert sig_verify(
        ml_dsa_65,
        store._signing_public_key,
        TICKET_DOMAIN + body,
        bytes.fromhex(ticket["signature"]),
    )


def test_tampered_peer_identity_hash_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    ticket = _issue(store)
    tampered = dict(ticket)
    tampered["peer_identity_hash"] = hashlib.sha256(b"bob").hexdigest()
    pop = store.create_proof_of_possession(SECRET, NONCE, "th-new")

    with pytest.raises(ResumptionPeerMismatchError):
        store.resume(
            tampered,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=NONCE,
            proof_of_possession=pop,
            new_transcript_hash="th-new",
        )


def test_forged_ticket_signature_is_rejected(tmp_path: Path) -> None:
    store = _store(tmp_path)
    ticket = _issue(store)
    forged = dict(ticket)
    forged["signature"] = "00" * 64
    pop = store.create_proof_of_possession(SECRET, NONCE, "th-new")

    with pytest.raises(ResumptionError):
        store.resume(
            forged,
            presented_identity="alice",
            presented_device="dev-a",
            fresh_nonce=NONCE,
            proof_of_possession=pop,
            new_transcript_hash="th-new",
        )


def test_proof_of_possession_is_mldsa_signed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    pop = store.create_proof_of_possession(SECRET, NONCE, "th-new")
    msg = POP_DOMAIN + hashlib.sha256(SECRET).digest() + NONCE + b"th-new"
    assert sig_verify(ml_dsa_65, store._signing_public_key, msg, bytes.fromhex(pop))

    # A PoP made for a different shared secret must not verify against this one.
    other = store.create_proof_of_possession(b"X" * 32, NONCE, "th-new")
    assert not sig_verify(ml_dsa_65, store._signing_public_key, msg, bytes.fromhex(other))


def test_ticket_and_signing_key_survive_store_restart(tmp_path: Path) -> None:
    db = tmp_path / "restart.db"
    store1 = PersistentResumptionStore(db)
    ticket = _issue(store1)
    public_key = store1._signing_public_key
    del store1

    store2 = PersistentResumptionStore(db)
    assert store2._signing_public_key == public_key
    pop = store2.create_proof_of_possession(SECRET, NONCE, "th-new")
    new_keys, rotated = store2.resume(
        ticket,
        presented_identity="alice",
        presented_device="dev-a",
        fresh_nonce=NONCE,
        proof_of_possession=pop,
        new_transcript_hash="th-new",
    )
    assert new_keys.peer_identity == "alice"
    assert rotated["peer_identity_hash"] == hashlib.sha256(b"alice").hexdigest()
