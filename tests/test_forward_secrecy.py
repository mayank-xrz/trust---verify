"""Acceptance tests for Objective 2: Forward Secrecy."""

from __future__ import annotations

import pytest

from src.crypto.envelope import AEADFailedError, open_envelope, seal_envelope
from src.crypto.handshake import EphemeralHandshakeSession, HandshakeError


def test_identity_key_exposure_does_not_decrypt_past_session(runtime_identities) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    bob_pk, bob_sk = runtime_identities["bob"]

    bob_hs = EphemeralHandshakeSession("bob", "dev-b", bob_sk)
    alice_hs = EphemeralHandshakeSession("alice", "dev-a", alice_sk)

    hello = bob_hs.create_responder_hello()
    init_msg, alice_keys = alice_hs.initiate(hello, bob_pk)
    bob_keys = bob_hs.complete_responder(init_msg, alice_pk)

    assert alice_keys.tx_key == bob_keys.rx_key
    assert alice_keys.rx_key == bob_keys.tx_key

    env = seal_envelope(
        sender_identity="alice",
        sender_device="dev-a",
        recipient_identity="bob",
        recipient_device="dev-b",
        session_id=alice_keys.session_id,
        session_key=alice_keys.tx_key,
        signing_secret_key=alice_sk,
        plaintext=b"historical-confidential-payload",
        counter=0,
    )

    # Compromise of both long-term ML-DSA-65 identity keys cannot decrypt past session traffic
    for compromised_key in (alice_sk[:32], bob_sk[:32], alice_pk[:32], bob_pk[:32]):
        with pytest.raises(AEADFailedError):
            open_envelope(
                env,
                local_identity="bob",
                local_device="dev-b",
                session_key=compromised_key,
                sender_public_key=alice_pk,
            )


def test_ephemeral_keys_absent_after_session(runtime_identities) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    bob_pk, bob_sk = runtime_identities["bob"]

    bob_hs = EphemeralHandshakeSession("bob", "dev-b", bob_sk)
    alice_hs = EphemeralHandshakeSession("alice", "dev-a", alice_sk)

    hello = bob_hs.create_responder_hello()
    assert bob_hs.has_ephemeral_secrets()

    init_msg, _ = alice_hs.initiate(hello, bob_pk)
    assert not alice_hs.has_ephemeral_secrets()

    bob_hs.complete_responder(init_msg, alice_pk)
    assert not bob_hs.has_ephemeral_secrets()

    # Attempting to reuse wiped responder ephemerals fails
    with pytest.raises(HandshakeError):
        bob_hs.complete_responder(init_msg, alice_pk)


def test_each_session_uses_fresh_ephemerals(runtime_identities) -> None:
    alice_pk, alice_sk = runtime_identities["alice"]
    bob_pk, bob_sk = runtime_identities["bob"]

    bob1 = EphemeralHandshakeSession("bob", "dev-b", bob_sk)
    alice1 = EphemeralHandshakeSession("alice", "dev-a", alice_sk)
    h1 = bob1.create_responder_hello()
    m1, ak1 = alice1.initiate(h1, bob_pk)
    bk1 = bob1.complete_responder(m1, alice_pk)

    bob2 = EphemeralHandshakeSession("bob", "dev-b", bob_sk)
    alice2 = EphemeralHandshakeSession("alice", "dev-a", alice_sk)
    h2 = bob2.create_responder_hello()
    m2, ak2 = alice2.initiate(h2, bob_pk)
    bk2 = bob2.complete_responder(m2, alice_pk)

    assert h1["x25519_pub"] != h2["x25519_pub"]
    assert h1["mlkem_pub"] != h2["mlkem_pub"]
    assert m1["init_x25519_pub"] != m2["init_x25519_pub"]
    assert m1["mlkem_ct"] != m2["mlkem_ct"]
    assert ak1.tx_key != ak2.tx_key
    assert bk1.rx_key != bk2.rx_key
