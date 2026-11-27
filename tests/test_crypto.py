import copy
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from src.crypto import classical
from src.crypto.chunks import Reassembler, make_transfer
from src.crypto.primitives import (
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
from src.crypto.protected_read import protected_read
from src.crypto.replay import ReplayLedger
from src.crypto.session import PrekeyStore, Session, TrustRegistry, accept, finish, initiate

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

    def test_epoch_rekey_rejects_old_epoch_and_ratchets_chain(self):
        alice, bob, _, _, _ = self.sessions()
        ledger = ReplayLedger(Path(self.temp.name) / "replay.db")
        initial_chain = alice._send_chain_key
        pkt0 = alice.encrypt(b"msg-0")
        self.assertNotEqual(alice._send_chain_key, initial_chain)
        self.assertEqual(bob.decrypt(pkt0, ledger), b"msg-0")

        alice.rekey()
        bob.rekey()
        self.assertEqual(alice.epoch, 1)
        self.assertEqual(bob.epoch, 1)
        with self.assertRaises(CryptoError):
            bob.decrypt(pkt0, ledger)
        pkt1 = alice.encrypt(b"msg-1-epoch1")
        self.assertEqual(pkt1["header"]["epoch"], 1)
        self.assertEqual(bob.decrypt(pkt1, ledger), b"msg-1-epoch1")

    def test_key_confirmation_required_before_ready(self):
        prekeys = PrekeyStore()
        offer = prekeys.offer("bob", "laptop", self.bob_sk)
        initiation, alice = initiate(offer, "alice", "phone", self.alice_sk, self.registry)
        ack, _ = accept(offer, initiation, self.bob_sk, self.registry, prekeys)
        bad_ack = dict(ack)
        bad_ack["key_confirm"] = "0" * 64
        with self.assertRaises(CryptoError):
            finish(bad_ack, initiation, self.registry, alice)
        self.assertFalse(alice.ready)
        alice.root = b"\x00" * 32
        with self.assertRaisesRegex(CryptoError, "key confirmation"):
            finish(ack, initiation, self.registry, alice)

    def test_session_persistence_restart_and_refuse_unwritable(self):
        alice_state = Path(self.temp.name) / "alice_session.json"
        bob_state = Path(self.temp.name) / "bob_session.json"
        prekeys = PrekeyStore()
        offer = prekeys.offer("bob", "laptop", self.bob_sk)
        initiation, alice = initiate(offer, "alice", "phone", self.alice_sk, self.registry, state_path=alice_state)
        ack, bob = accept(offer, initiation, self.bob_sk, self.registry, prekeys, state_path=bob_state)
        finish(ack, initiation, self.registry, alice)

        pkt0 = alice.encrypt(b"before-restart")
        alice_restarted = Session.load(alice_state)
        self.assertEqual(alice_restarted.send_counter, 1)
        pkt1 = alice_restarted.encrypt(b"after-restart")
        self.assertEqual(pkt1["header"]["counter"], 1)

        ledger = ReplayLedger(Path(self.temp.name) / "replay.db")
        self.assertEqual(bob.decrypt(pkt0, ledger), b"before-restart")
        self.assertEqual(bob.decrypt(pkt1, ledger), b"after-restart")

        # Refuse to encrypt if state cannot be persisted
        alice_restarted.state_path = Path(self.temp.name)  # directory path causes OSError on replace
        with self.assertRaises(CryptoError):
            alice_restarted.encrypt(b"should-fail")
        self.assertEqual(alice_restarted.send_counter, 2)

    def test_trust_registry_and_prekey_persistence_and_revocation(self):
        reg_path = Path(self.temp.name) / "trust.json"
        pk_path = Path(self.temp.name) / "prekeys.json"
        reg1 = TrustRegistry(reg_path)
        reg1.enroll("alice", "phone", self.alice_pk)
        reg1.enroll("bob", "laptop", self.bob_pk)
        self.assertEqual(oct(reg_path.stat().st_mode & 0o777), "0o600")

        pks1 = PrekeyStore(pk_path)
        expired_offer = pks1.offer("bob", "laptop", self.bob_sk, lifetime=1)
        pks1._private[expired_offer["prekey_id"]]["expires_at"] = 0
        pks1._save()
        valid_offer = pks1.offer("bob", "laptop", self.bob_sk, lifetime=300)

        pks2 = PrekeyStore(pk_path)
        with self.assertRaises(CryptoError):
            pks2.take(expired_offer["prekey_id"])
        self.assertNotIn(expired_offer["prekey_id"], pks2._private)
        pks2.revoke(valid_offer["prekey_id"])
        with self.assertRaises(CryptoError):
            PrekeyStore(pk_path).take(valid_offer["prekey_id"])
        with self.assertRaises(CryptoError):
            PrekeyStore(pk_path).bundle(valid_offer["prekey_id"])

        reg2 = TrustRegistry(reg_path)
        linked = PrekeyStore(pk_path, registry=reg2)
        another_offer = linked.offer("bob", "laptop", self.bob_sk)
        reg2.revoke("bob", "laptop")
        with self.assertRaises(CryptoError):
            PrekeyStore(pk_path, registry=TrustRegistry(reg_path)).bundle(another_offer["prekey_id"])
        reg2.revoke("alice", "phone")
        reg3 = TrustRegistry(reg_path)
        with self.assertRaises(CryptoError):
            reg3.key("alice", "phone")
        with self.assertRaises(CryptoError):
            initiate(valid_offer, "alice", "phone", self.alice_sk, reg3)

    def test_handshake_node_process_count_and_distinct_errors(self):
        import subprocess as sp
        from unittest.mock import patch

        from src.crypto import aead, node_bridge

        prekeys = PrekeyStore()
        offer = prekeys.offer("bob", "laptop", self.bob_sk)

        real_run = sp.run
        counts = []

        def counting_run(*args, **kwargs):
            counts.append(args[0])
            return real_run(*args, **kwargs)

        with patch("src.crypto.node_bridge.subprocess.run", side_effect=counting_run):
            counts.clear()
            initiation, alice = initiate(offer, "alice", "phone", self.alice_sk, self.registry)
            self.assertLessEqual(len(counts), 2)

            counts.clear()
            ack, bob = accept(offer, initiation, self.bob_sk, self.registry, prekeys)
            self.assertLessEqual(len(counts), 2)

            counts.clear()
            finish(ack, initiation, self.registry, alice)
            self.assertLessEqual(len(counts), 1)

        # Distinct error: AEAD tag mismatch vs timeout vs missing node
        key = b"\x01" * 32
        nonce = b"\x02" * 12
        ct, tag = aead.encrypt(key, nonce, b"aad", b"hello")
        bad_tag = bytes([tag[0] ^ 0xFF]) + tag[1:]
        with self.assertRaises(CryptoError) as ctx_auth:
            aead.decrypt(key, nonce, b"aad", ct, bad_tag)
        self.assertIn("AEAD authentication failed", str(ctx_auth.exception))

        node_bridge._stop_worker()
        with patch("src.crypto.node_bridge.select.select", return_value=([], [], [])):
            with self.assertRaises(CryptoError) as ctx_to:
                node_bridge.call_node({"op": "hkdf", "ikm": "YQ==", "salt": "Yg==", "info": "Yw==", "length": 32}, CryptoError, timeout=0.01)
            self.assertIn("timed out", str(ctx_to.exception))

        orig_bin = node_bridge._NODE_BIN
        try:
            node_bridge._stop_worker()
            node_bridge._NODE_BIN = None
            with patch("src.crypto.node_bridge.shutil.which", return_value=None):
                self.assertEqual(aead.decrypt(key, nonce, b"aad", ct, tag), b"hello")
                with patch.object(aead, "AESGCM", None):
                    with self.assertRaises(CryptoError) as ctx_missing:
                        aead.decrypt(key, nonce, b"aad", ct, tag)
                self.assertIn("not found", str(ctx_missing.exception))
        finally:
            node_bridge._NODE_BIN = orig_bin

    def test_per_session_replay_cap_and_auto_rekey(self):
        ledger = ReplayLedger(Path(self.temp.name) / "scoped.db", max_rows=2)
        ledger.mark("sess-a", "a", "b", 0)
        ledger.mark("sess-a", "a", "b", 1)
        with self.assertRaises(CryptoError):
            ledger.mark("sess-a", "a", "b", 2)
        # Session B has its own quota
        ledger.mark("sess-b", "a", "b", 0)

        alice, bob, _, _, _ = self.sessions()
        session_ledger = ReplayLedger(Path(self.temp.name) / "auto_rekey.db")
        alice.auto_rekey_at = 2
        p0 = alice.encrypt(b"m0")
        p1 = alice.encrypt(b"m1")
        p2 = alice.encrypt(b"m2")  # triggers auto-rekey to epoch 1
        self.assertEqual(p2["header"]["epoch"], 1)
        self.assertEqual(p2["header"]["counter"], 0)
        self.assertEqual(bob.decrypt(p0, session_ledger), b"m0")
        self.assertEqual(bob.decrypt(p1, session_ledger), b"m1")
        self.assertEqual(bob.decrypt(p2, session_ledger), b"m2")
        self.assertEqual(bob.epoch, 1)

    def test_concurrent_session_loads_reserve_distinct_counters(self):
        state = Path(self.temp.name) / "session.json"
        alice, bob, _, _, _ = self.sessions()
        alice.state_path = state
        alice._persist()
        first = Session.load(state)
        second = Session.load(state)
        p0 = first.encrypt(b"first")
        p1 = second.encrypt(b"second")
        self.assertEqual((p0["header"]["counter"], p1["header"]["counter"]), (0, 1))
        ledger = ReplayLedger(Path(self.temp.name) / "concurrent.db")
        self.assertEqual(bob.decrypt(p0, ledger), b"first")
        self.assertEqual(bob.decrypt(p1, ledger), b"second")

    def test_session_defaults_to_persistent_state(self):
        alice, _, _, _, _ = self.sessions()
        self.assertTrue(alice.state_path.is_file())
        self.assertEqual(Session.load(alice.state_path).send_counter, 0)

    def test_session_counter_rollback_rejected_on_load(self):
        state = Path(self.temp.name) / "rollback.json"
        alice, _, _, _, _ = self.sessions()
        alice.state_path = state
        alice._persist()
        old_state = state.read_bytes()
        alice.encrypt(b"advance")
        state.write_bytes(old_state)
        with self.assertRaisesRegex(CryptoError, "rollback"):
            Session.load(state)

    def test_counter_cap_rekeys_persistently(self):
        state = Path(self.temp.name) / "capped.json"
        alice, bob, _, _, _ = self.sessions()
        alice.max_messages_per_epoch = 2
        alice.auto_rekey_at = 2
        alice.state_path = state
        alice._persist()
        p0 = alice.encrypt(b"zero")
        p1 = alice.encrypt(b"one")
        p2 = Session.load(state).encrypt(b"two")
        self.assertEqual((p0["header"]["epoch"], p0["header"]["counter"]), (0, 0))
        self.assertEqual((p2["header"]["epoch"], p2["header"]["counter"]), (1, 0))
        ledger = ReplayLedger(Path(self.temp.name) / "cap.db")
        for packet, plain in ((p0, b"zero"), (p1, b"one"), (p2, b"two")):
            self.assertEqual(bob.decrypt(packet, ledger), plain)
        with self.assertRaises(CryptoError):
            bob.decrypt(p0, ledger)

    def test_worker_reused_for_multiple_calls(self):
        from src.crypto import node_bridge
        node_bridge._stop_worker()
        request = {"op": "hkdf", "ikm": "YQ==", "salt": "Yg==", "info": "Yw==", "length": 32}
        node_bridge.call_node(request, CryptoError)
        pid = node_bridge._worker.pid
        node_bridge.call_node(request, CryptoError)
        self.assertEqual(node_bridge._worker.pid, pid)

    def test_adapter_at_rest_encryption_audit_chain_and_challenge_bounds(self):
        import track4_service

        state_root = Path(self.temp.name)
        def call(request, expect_ok=True):
            result = subprocess.run(
                [sys.executable, str(ROOT / "track4_service.py")],
                input=json.dumps(request),
                text=True,
                capture_output=True,
                env={**os.environ, "TRACK4_STATE_DIR": str(state_root)},
            )
            if expect_ok:
                self.assertEqual(result.returncode, 0, result.stderr)
                return json.loads(result.stdout)
            self.assertNotEqual(result.returncode, 0)
            return result

        secret_body = "top-secret-body-value"
        key_mat = "super-secret-key-material"
        self.assertEqual(
            call({"op": "setup", "owners": {"doc1": "alice"}, "contents": {"doc1": secret_body},
                  "disabled": [], "key_material": key_mat}),
            {"ready": True},
        )
        raw_state = (state_root / "track4-local" / "state.json").read_text(encoding="utf-8")
        raw_key = (state_root / "track4-local" / ".storage_key").read_text(encoding="utf-8")
        self.assertNotIn(secret_body, raw_state)
        self.assertNotIn(key_mat, raw_state)
        self.assertNotIn(key_mat, raw_key)

        self.assertEqual(
            call({"op": "read", "actor": "alice", "asset": "doc1", "request_id": "r1"}),
            {"decision": "allow", "body": secret_body},
        )
        self.assertEqual(
            call({"op": "audit", "request_id": "unknown-id"}),
            {"request_id": "unknown-id", "decision": "deny"},
        )

        # Challenge validation & reuse rejection
        public, _ = kem_keypair()
        pk_b64 = b64(public)
        self.assertEqual(call({"op": "protected_read", "actor": "alice", "asset": "doc1", "challenge": "", "public_key": pk_b64}), {"decision": "deny"})
        self.assertEqual(call({"op": "protected_read", "actor": "alice", "asset": "doc1", "challenge": "x" * 513, "public_key": pk_b64}), {"decision": "deny"})
        call({"op": "protected_read", "actor": "alice", "asset": "doc1", "challenge": "once", "public_key": pk_b64}, expect_ok=True)
        self.assertEqual(call({"op": "protected_read", "actor": "alice", "asset": "doc1", "challenge": "once", "public_key": pk_b64}), {"decision": "deny"})

        # Audit hash chain verification & 1-byte tamper detection
        state_obj = json.loads((state_root / "track4-local" / "state.json").read_text(encoding="utf-8"))
        audit_log = state_obj["audit_log"]
        self.assertGreaterEqual(len(audit_log), 3)
        self.assertTrue(track4_service.verify_chain(audit_log))
        protected = [entry for entry in audit_log if entry["op"] == "protected_read"]
        self.assertTrue(any(entry["decision"] == "allow" for entry in protected))
        self.assertTrue(any(entry["decision"] == "deny" for entry in protected))
        tampered_log = copy.deepcopy(audit_log)
        tampered_log[0]["decision"] = "deny"
        self.assertFalse(track4_service.verify_chain(tampered_log))


if __name__ == "__main__":
    unittest.main()
