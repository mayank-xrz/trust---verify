"""Crypto Security Test Suite:
- Replay attack rejection
- Recipient binding & swap protection
- Forward secrecy via ephemeral key destruction
- Resumption hijacking rejection
"""

import unittest
from src.crypto.pqc_kem import MLKEMKeyExchange
from src.crypto.pqc_sig import MLDSASignature
from src.crypto.messaging import (
    SecureMessaging,
    RecipientMismatchError,
    ReplayAttackError,
    MessageTamperedError,
)
from src.crypto.session import SessionManager, ResumptionHijackError


class TestCryptoSecurity(unittest.TestCase):

    def test_pqc_kem_key_exchange(self):
        """Verify ephemeral key exchange establishes identical shared secret."""
        server_kem = MLKEMKeyExchange()
        client_kem = MLKEMKeyExchange()

        server_pub, server_priv = server_kem.generate_keypair()
        ciphertext, client_secret = client_kem.encapsulate(server_pub)
        recovered_secret = server_kem.decapsulate(ciphertext, server_priv)

        self.assertEqual(len(client_secret), 32)
        self.assertEqual(client_secret, recovered_secret)

    def test_pqc_sig_sign_and_verify(self):
        """Verify ML-DSA quantum-resistant signature generation and verification."""
        signer = MLDSASignature()
        pub, priv = signer.generate_keypair()
        msg = b"CRITICAL_SET_STATE_AUTHORIZED"

        signature = signer.sign(msg, priv)
        self.assertTrue(signer.verify(msg, signature, pub))
        self.assertFalse(signer.verify(b"CRITICAL_SET_STATE_FORGED", signature, pub))

    def test_messaging_recipient_swap_protection(self):
        """Verify that an envelope addressed to Node-B fails when sent to Node-C (Recipient Binding)."""
        alice = SecureMessaging("node-alice")
        bob = SecureMessaging("node-bob")
        charlie = SecureMessaging("node-charlie")

        signer = MLDSASignature()
        signer_pub, signer_priv = signer.generate_keypair()

        shared_key = b"SHARED-SYMMETRIC-SECRET-32BYTES!"
        payload = b'{"command": "TRANSFER_ASSET", "amount": 1000}'

        # Alice creates message explicitly addressed to Bob
        envelope = alice.pack_envelope(
            sender_id="node-alice",
            recipient_id="node-bob",
            plaintext=payload,
            shared_key=shared_key,
            signer=signer,
        )

        # Bob successfully unpacks it
        bob_received = bob.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertEqual(bob_received, payload)

        # Charlie intercepts and attempts to unpack the envelope
        with self.assertRaises(RecipientMismatchError) as ctx:
            charlie.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertIn("Recipient binding violation", str(ctx.exception))

    def test_messaging_anti_replay(self):
        """Verify replayed message IDs or duplicate sequence numbers are rejected."""
        alice = SecureMessaging("node-alice")
        bob = SecureMessaging("node-bob")
        signer = MLDSASignature()
        signer_pub, signer_priv = signer.generate_keypair()
        shared_key = b"SHARED-SYMMETRIC-SECRET-32BYTES!"

        envelope = alice.pack_envelope(
            sender_id="node-alice",
            recipient_id="node-bob",
            plaintext=b"EXECUTE_TRANSACTION_#42",
            shared_key=shared_key,
            signer=signer,
        )

        # First delivery succeeds
        bob.unpack_envelope(envelope, shared_key, signer, signer_pub)

        # Replay of the exact same envelope is detected and rejected
        with self.assertRaises(ReplayAttackError) as ctx:
            bob.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertTrue("Duplicate message_id" in str(ctx.exception) or "Replay detected" in str(ctx.exception))

    def test_forward_secrecy(self):
        """Verify that after wiping ephemeral keys, past ciphertexts cannot be decapsulated."""
        kem = MLKEMKeyExchange()
        pub, priv = kem.generate_keypair()
        ciphertext, secret = kem.encapsulate(pub)

        self.assertEqual(kem.decapsulate(ciphertext, priv), secret)

        # Enforce forward secrecy by key wiping
        kem.wipe_keys()
        with self.assertRaises(ValueError) as ctx:
            kem.decapsulate(ciphertext)
        self.assertIn("No private key available", str(ctx.exception))

    def test_resumption_hijack_protection(self):
        """Verify that a session resumption token issued to Client-A cannot be hijacked by Mallory."""
        server_sm = SessionManager("server-node")
        master_secret = b"INITIAL-HANDSHAKE-MASTER-SECRET!"

        sess_id, channel_key = server_sm.create_session("client-alice", master_secret)
        ticket = server_sm.issue_resumption_ticket(sess_id)

        # Alice can resume
        new_sess_id, new_key = server_sm.resume_session(ticket, requesting_peer_id="client-alice")
        self.assertNotEqual(new_sess_id, sess_id)
        self.assertNotEqual(new_key, channel_key)

        # Mallory attempts to resume using Alice's ticket
        with self.assertRaises(ResumptionHijackError) as ctx:
            server_sm.resume_session(ticket, requesting_peer_id="mallory-attacker")
        self.assertIn("Resumption hijack attempt detected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
