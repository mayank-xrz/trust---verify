import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from crypto import classical
from crypto.chunks import Reassembler, make_transfer
from crypto.primitives import (
    CryptoError,
    b64,
    canonical,
    decapsulate,
    encapsulate,
    kem_keypair,
    sign,
    signing_keypair,
    verify,
)
from crypto.protected_read import protected_read
from crypto.replay import ReplayLedger
from crypto.session import PrekeyStore, TrustRegistry, accept, finish, initiate

ROOT = Path(__file__).resolve().parents[1]


class CryptoTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registry = TrustRegistry()
        self.alice_pk, self.alice_sk = signing_keypair()
        self.bob_pk, self.bob_sk = signing_keypair()
        self.registry.enroll("alice", "phone", self.alice_pk)
        self.registry.enroll("bob", "laptop", self.bob_pk)

    def sessions(self):
        prekeys = PrekeyStore()
        offer = prekeys.offer("bob", "laptop", self.bob_sk)
        initiation, alice = initiate(offer, "alice", "phone", self.alice_sk, self.registry)
        ack, bob = accept(offer, initiation, self.bob_sk, self.registry, prekeys)
        finish(ack, initiation, self.registry, alice)
        self.assertEqual(alice.root, bob.root)
        return alice, bob, prekeys, offer, initiation

    def test_kem_and_bad_input(self):
        public, private = kem_keypair()
        ciphertext, shared = encapsulate(public)
        self.assertEqual(shared, decapsulate(private, ciphertext))
        for bad in (b"", public[:-1]):
            with self.assertRaises(CryptoError):
                encapsulate(bad)
        with self.assertRaises(CryptoError):
            decapsulate(private, ciphertext[:-1])

    def test_x25519_ephemeral_agreement_and_bad_key(self):
        alice_public, alice_private = classical.keypair()
        bob_public, bob_private = classical.keypair()
        self.assertEqual(classical.shared(alice_private, bob_public),
                         classical.shared(bob_private, alice_public))
        with self.assertRaises(CryptoError):
            classical.shared(alice_private, bob_public[:-1])

    def test_signature_and_tamper(self):
        transcript = {"version": 1, "identity": "alice"}
        signature = sign(self.alice_sk, "track4/v1/test", transcript)
        verify(self.alice_pk, "track4/v1/test", transcript, signature)
        with self.assertRaises(CryptoError):
            verify(self.alice_pk, "track4/v1/test", {**transcript, "identity": "bob"}, signature)
        with self.assertRaises(CryptoError):
            verify(self.alice_pk, "track4/v1/other", transcript, signature)

    def test_handshake_identity_binding_and_prekey_once(self):
        alice, bob, prekeys, offer, initiation = self.sessions()
        with self.assertRaises(CryptoError):
            accept(offer, initiation, self.bob_sk, self.registry, prekeys)
        malicious = copy.deepcopy(initiation)
        malicious["initiator"] = "mallory"
        with self.assertRaises(CryptoError):
            accept(offer, malicious, self.bob_sk, self.registry, PrekeyStore())
        self.assertEqual(alice.peer, "bob")
        self.assertEqual(bob.peer, "alice")

    def test_offer_tamper_and_suite_substitution(self):
        prekeys = PrekeyStore()
        offer = prekeys.offer("bob", "laptop", self.bob_sk)
        changed = copy.deepcopy(offer)
        changed["responder"] = "mallory"
        with self.assertRaises(CryptoError):
            initiate(changed, "alice", "phone", self.alice_sk, self.registry)
        changed = copy.deepcopy(offer)
        changed["suite"] = "classical-only"
        with self.assertRaises(CryptoError):
            initiate(changed, "alice", "phone", self.alice_sk, self.registry)
        different_pk, _ = signing_keypair()
        with self.assertRaises(CryptoError):
            self.registry.enroll("bob", "laptop", different_pk)

    def test_aead_replay_restart_and_binding(self):
        alice, bob, *_ = self.sessions()
        ledger_path = Path(self.temp.name) / "replay.db"
        packet = alice.encrypt(b"secret")
        self.assertEqual(bob.decrypt(packet, ReplayLedger(ledger_path)), b"secret")
        with self.assertRaises(CryptoError):
            bob.decrypt(packet, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["header"]["recipient"] = "mallory"
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["header"]["recipient_device"] = "other-device"
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["header"]["session_id"] = "wrong-session"
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["header"]["epoch"] = 1
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["tag"] = b64(b"0" * 16)
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["ciphertext"] = b64(b"bad-data")
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))
        bad = copy.deepcopy(alice.encrypt(b"secret"))
        bad["header"]["version"] = 2
        with self.assertRaises(CryptoError):
            bob.decrypt(bad, ReplayLedger(ledger_path))

    def test_identity_key_compromise_does_not_recover_session_key(self):
        alice, bob, *_ = self.sessions()
        compromised_identity_secret = self.bob_sk
        self.assertNotEqual(compromised_identity_secret, alice.root)
        packet = alice.encrypt(b"historical")
        self.assertEqual(bob.decrypt(packet, ReplayLedger(Path(self.temp.name) / "replay.db")), b"historical")
        # This models disclosure of signing credentials only. It is not a memory-erasure proof.

    def test_replay_ledger_capacity_fails_closed(self):
        alice, bob, *_ = self.sessions()
        ledger = ReplayLedger(Path(self.temp.name) / "bounded.db", max_rows=1)
        self.assertEqual(bob.decrypt(alice.encrypt(b"first"), ledger), b"first")
        with self.assertRaises(CryptoError):
            bob.decrypt(alice.encrypt(b"second"), ledger)

    def test_chunks_reorder_duplicate_missing_and_cross_session(self):
        alice, bob, *_ = self.sessions()
        data = os.urandom(100000)
        packets = make_transfer(alice, data, chunk_size=20000)
        receiver = Reassembler(bob, ReplayLedger(Path(self.temp.name) / "replay.db"))
        result = receiver.ingest(packets[2])
        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(receiver.ingest(packets[2])["status"], "duplicate")
        receiver.ingest(packets[0])
        self.assertEqual(len(receiver.missing(result["transfer_id"])), 4)
        for packet in reversed(packets[1:]):
            result = receiver.ingest(packet)
        self.assertEqual(result["status"], "delivered")
        self.assertEqual(result["data"], data)
        replay_receiver = Reassembler(bob, ReplayLedger(Path(self.temp.name) / "replay.db"))
        replay_manifest = {"kind": "manifest", "transfer_id": result["transfer_id"],
                           "size": len(data), "count": 5, "chunk_size": 20000,
                           "sha256": hashlib.sha256(data).hexdigest()}
        with self.assertRaises(CryptoError):
            replay_receiver.ingest(alice.encrypt(canonical(replay_manifest)))
        another_alice, another_bob, *_ = self.sessions()
        mixed = make_transfer(another_alice, b"cross-session")
        with self.assertRaises(CryptoError):
            receiver.ingest(mixed[0])
        self.assertNotEqual(another_bob.transcript["session_id"], bob.transcript["session_id"])

    def test_chunk_tamper_and_expiration(self):
        alice, bob, *_ = self.sessions()
        packets = make_transfer(alice, b"a" * 90000, chunk_size=30000)
        receiver = Reassembler(bob, ReplayLedger(Path(self.temp.name) / "replay.db"), timeout=0)
        tampered = copy.deepcopy(packets[1])
        tampered["tag"] = b64(b"0" * 16)
        with self.assertRaises(CryptoError):
            receiver.ingest(tampered)
        first = receiver.ingest(packets[0])
        self.assertEqual(first["status"], "incomplete")
        self.assertTrue(receiver.cleanup())

    def test_protected_read_exact_interop(self):
        public, private = kem_keypair()
        result = protected_read("fresh-challenge", "stored body", b64(public))
        secret = decapsulate(private, __import__("base64").b64decode(result["ciphertext"], validate=True))
        import hashlib
        import hmac
        expected = hmac.new(secret, b"fresh-challengestored body", hashlib.sha256).hexdigest()
        self.assertEqual(result["proof"], expected)
        with self.assertRaises(CryptoError):
            protected_read("challenge", "body", "bad!")

    def test_adapter_authorization_and_persistence(self):
        state = Path(self.temp.name)
        def call(request):
            result = subprocess.run([sys.executable, str(ROOT / "track4_service.py")],
                                    input=json.dumps(request), text=True, capture_output=True,
                                    env={**os.environ, "TRACK4_STATE_DIR": str(state)})
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)
        self.assertEqual(call({"op": "setup", "owners": {"brief": "maya"}, "contents": {"brief": "note"},
                               "disabled": [], "key_material": "never-print"}), {"ready": True})
        public, private = kem_keypair()
        allowed = call({"op": "protected_read", "actor": "maya", "asset": "brief", "challenge": "fresh", "public_key": b64(public)})
        secret = decapsulate(private, __import__("base64").b64decode(allowed["ciphertext"]))
        import hashlib
        import hmac
        self.assertEqual(allowed["proof"], hmac.new(secret, b"freshnote", hashlib.sha256).hexdigest())
        self.assertEqual(call({"op": "protected_read", "actor": "other", "asset": "brief", "challenge": "fresh", "public_key": b64(public)}), {"decision": "deny"})
        call({"op": "revoke", "actor": "maya"})
        self.assertEqual(call({"op": "protected_read", "actor": "maya", "asset": "brief", "challenge": "fresh", "public_key": b64(public)}), {"decision": "deny"})


if __name__ == "__main__":
    unittest.main()
