"""End-to-end tests for the merged SecureCryptoSystem (handshake + encrypt + decrypt + chunked + resumption)."""

from __future__ import annotations

from pathlib import Path

import pytest

from src.audit.verifier import AuditLogVerifier
from src.crypto import SecureCryptoSystem
from src.crypto.envelope import RecipientMismatchError
from src.crypto.replay_cache import ReplayRejectedError
from src.crypto.resumption import ResumptionPeerMismatchError


def test_merged_encrypt_decrypt_and_chunked_roundtrip(tmp_path: Path) -> None:
    alice = SecureCryptoSystem(identity="alice", device="dev-a", state_dir=tmp_path / "alice")
    bob = SecureCryptoSystem(identity="bob", device="dev-b", state_dir=tmp_path / "bob")
    charlie = SecureCryptoSystem(identity="charlie", device="dev-c", state_dir=tmp_path / "charlie")

    # 1. Forward-secret hybrid handshake
    hello = bob.create_hello()
    init_msg, alice_keys = alice.initiate_session(hello, bob.signing_public_key)
    bob_keys = bob.accept_session(init_msg, alice.signing_public_key)
    assert alice_keys.session_id == bob_keys.session_id

    # 2. Single-message encrypt -> decrypt
    env = alice.encrypt(alice_keys.session_id, b"merged-system-secret-payload")
    assert bob.decrypt(env, alice.signing_public_key) == b"merged-system-secret-payload"

    # Replay rejected
    with pytest.raises(ReplayRejectedError):
        bob.decrypt(env, alice.signing_public_key)

    # Wrong recipient rejected before decryption
    with pytest.raises(RecipientMismatchError):
        charlie.decrypt(env, alice.signing_public_key)

    # 3. Chunked encrypt -> out-of-order decrypt
    big_payload = b"CHUNK-" * 500
    chunks = alice.encrypt_chunked(alice_keys.session_id, big_payload, chunk_size=1000)
    assert len(chunks) == 3
    assert bob.decrypt_chunk(chunks[2], alice.signing_public_key) is None
    assert bob.decrypt_chunk(chunks[0], alice.signing_public_key) is None
    assert bob.decrypt_chunk(chunks[1], alice.signing_public_key) == big_payload

    # 4. Peer-bound resumption
    ticket = bob.issue_resumption_ticket(bob_keys.session_id)
    with pytest.raises(ResumptionPeerMismatchError):
        bob.resume_session(
            ticket,
            presented_identity="charlie",
            presented_device="dev-c",
            fresh_nonce=b"N" * 16,
            proof_of_possession="",
            new_transcript_hash="th-bad",
        )

    nonce = b"N" * 16
    pop = bob.resumption_store.create_proof_of_possession(
        alice_keys.resumption_secret, nonce, "th-resumed"
    )
    resumed_keys, _ = bob.resume_session(
        ticket,
        presented_identity="alice",
        presented_device="dev-a",
        fresh_nonce=nonce,
        proof_of_possession=pop,
        new_transcript_hash="th-resumed",
    )
    assert resumed_keys.peer_identity == "alice"

    # 5. Hash-chained audit log integrity
    assert AuditLogVerifier().verify_file(str(tmp_path / "bob" / "crypto_audit.log")).is_valid
