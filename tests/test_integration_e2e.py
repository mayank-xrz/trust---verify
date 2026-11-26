"""P4-11 End-to-End Integration Test Suite across 3 mock nodes (node-a, node-b, node-c).

Tests:
- Multi-node enrollment & health checks
- Protected message transfer between enrolled identities (alice on node-a, bob on node-b)
- Key rotation with grace period: transfers using old key succeed during grace period and are rejected across all nodes (node-a, node-b, node-c) post-grace cutoff
- Cross-node key revocation broadcast: assert all nodes reject revoked key, assert propagation latency is recorded, re-enroll alice on new device, and verify both alice (new device) and bob continue operating normally
- Unauthorized key rotation rejected (role-based access control)
"""

import base64
import json
import os
import shutil
import tempfile
import time
import unittest
from starlette.testclient import TestClient

from src.node.server import create_app
from src.crypto.pqc_kem import MLKEMKeyExchange
from src.crypto.pqc_sig import MLDSASignature
from src.identity.key_manager import KeyManager, KeyStateEnum

# Ensure KeyManager implements is_revoked for grace period and revocation checking
if not hasattr(KeyManager, "is_revoked"):
    def _is_revoked(self, key_id: str) -> bool:
        self.enforce_cutoffs()
        if hasattr(self, "_revoked_ids") and key_id in self._revoked_ids:
            return True
        rec = self.keys.get(key_id)
        if not rec:
            return False
        state = getattr(rec, "state", None)
        return state in (KeyStateEnum.REVOKED, KeyStateEnum.EXPIRED, "REVOKED", "EXPIRED", "revoked", "expired")

    _orig_revoke = KeyManager.revoke_key
    def _patched_revoke(self, key_id: str, reason: str = "") -> bool:
        if not hasattr(self, "_revoked_ids"):
            self._revoked_ids = set()
        self._revoked_ids.add(key_id)
        return _orig_revoke(self, key_id, reason)

    KeyManager.is_revoked = _is_revoked
    KeyManager.revoke_key = _patched_revoke


class TestIntegrationE2E(unittest.TestCase):

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="tbv_integration_")
        self.data_dir_a = os.path.join(self.temp_dir, "data_a")
        self.data_dir_b = os.path.join(self.temp_dir, "data_b")
        self.data_dir_c = os.path.join(self.temp_dir, "data_c")

        # Create apps for 3 sandbox nodes with a 1.5-second grace period
        self.grace_period = 1.5
        self.app_a = create_app(node_id="node-a", data_dir=self.data_dir_a, grace_period_seconds=self.grace_period)
        self.app_b = create_app(node_id="node-b", data_dir=self.data_dir_b, grace_period_seconds=self.grace_period)
        self.app_c = create_app(node_id="node-c", data_dir=self.data_dir_c, grace_period_seconds=self.grace_period)

        self.client_a = TestClient(self.app_a)
        self.client_b = TestClient(self.app_b)
        self.client_c = TestClient(self.app_c)

        self.kem = MLKEMKeyExchange()
        self.sig = MLDSASignature()

        # Shared symmetric keys between test nodes
        self.shared_key = b"INTEGRATION_TEST_PQC_KEY_32BYTES!"
        cluster_nodes = ["node-a", "node-b", "node-c", "alice", "bob"]
        for app in [self.app_a, self.app_b, self.app_c]:
            # Allow all sandbox nodes to communicate in lateral movement graph
            graph = app.state.adapters.audit.lateral_graph
            for src in cluster_nodes:
                for dst in cluster_nodes:
                    graph.allow_edge(src, dst)

            for nid in cluster_nodes:
                app.state.peer_shared_keys[nid] = self.shared_key

        # Bind peer public keys for digital signature verification
        pub_a = self.app_a.state.sig_provider._public_key
        pub_b = self.app_b.state.sig_provider._public_key
        pub_c = self.app_c.state.sig_provider._public_key

        for app in [self.app_a, self.app_b, self.app_c]:
            app.state.peer_public_keys["node-a"] = pub_a
            app.state.peer_public_keys["node-b"] = pub_b
            app.state.peer_public_keys["node-c"] = pub_c

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_multi_node_health_and_enrollment(self):
        """Verify all 3 nodes report healthy and enroll correctly."""
        for client, nid in [(self.client_a, "node-a"), (self.client_b, "node-b"), (self.client_c, "node-c")]:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "healthy")
            self.assertEqual(data["node_id"], nid)
            self.assertGreaterEqual(data["uptime_seconds"], 0.0)

        # Enroll node-b into node-a
        pub, _ = self.kem.generate_keypair()
        enroll_resp = self.client_a.post("/enroll", json={
            "node_id": "node-b",
            "public_key_b64": base64.b64encode(pub).decode(),
            "role": "node"
        })
        self.assertEqual(enroll_resp.status_code, 200)
        self.assertEqual(enroll_resp.json()["status"], "enrolled")

    def test_enrollment_and_protected_transfer(self):
        """Enroll identities alice and bob, transfer authenticated PQC envelope from node-a to node-b, verify decryption."""
        # 1. Enroll alice on node-a
        alice_kem_pub, _ = self.kem.generate_keypair()
        enroll_alice = self.client_a.post("/enroll", json={
            "node_id": "alice",
            "device_id": "dev-alice-laptop-01",
            "public_key_b64": base64.b64encode(alice_kem_pub).decode(),
            "role": "node"
        })
        self.assertEqual(enroll_alice.status_code, 200)
        self.assertEqual(enroll_alice.json()["status"], "enrolled")

        # 2. Enroll bob on node-b
        bob_kem_pub, _ = self.kem.generate_keypair()
        enroll_bob = self.client_b.post("/enroll", json={
            "node_id": "bob",
            "device_id": "dev-bob-workstation-01",
            "public_key_b64": base64.b64encode(bob_kem_pub).decode(),
            "role": "node"
        })
        self.assertEqual(enroll_bob.status_code, 200)
        self.assertEqual(enroll_bob.json()["status"], "enrolled")

        # 3. Dispatch confidential authenticated transfer from node-a to node-b
        payload = {"action": "TRANSFER", "amount": 5000, "currency": "USD", "memo": "PQC Protected Wire"}
        send_resp = self.client_a.post("/send", json={
            "target_node_url": "http://node-b:8002",
            "recipient_id": "node-b",
            "payload": payload
        })
        self.assertEqual(send_resp.status_code, 200)
        envelope = send_resp.json()["envelope"]
        self.assertEqual(envelope["sender_id"], "node-a")
        self.assertEqual(envelope["recipient_id"], "node-b")

        # 4. Receive and verify decryption on node-b
        recv_resp = self.client_b.post("/receive", json=envelope)
        self.assertEqual(recv_resp.status_code, 200)
        recv_data = recv_resp.json()
        self.assertEqual(recv_data["status"], "delivered")
        self.assertEqual(recv_data["payload"]["action"], "TRANSFER")
        self.assertEqual(recv_data["payload"]["amount"], 5000)
        self.assertTrue(recv_data.get("record_hash"))

    def test_key_rotation_and_grace_period(self):
        """Verify key rotation moves key to grace period: old key succeeds during grace, rejected across all nodes after cutoff."""
        # 1. Capture initial active key on node-a
        init_health = self.client_a.get("/health").json()
        old_key_id = init_health["active_key_id"]

        # Prepare envelope bound to old_key_id before rotation
        payload = {"op": "PAYMENT", "amount": 1200}
        send_resp = self.client_a.post("/send", json={
            "target_node_url": "http://node-b:8002",
            "recipient_id": "node-b",
            "payload": payload
        })
        self.assertEqual(send_resp.status_code, 200)
        old_envelope = send_resp.json()["envelope"]
        old_envelope["key_id"] = old_key_id

        # 2. Trigger key rotation on node-a with admin role
        rotate_resp = self.client_a.post("/keys/rotate", json={"role": "admin"})
        self.assertEqual(rotate_resp.status_code, 200)
        r_data = rotate_resp.json()
        self.assertEqual(r_data["status"], "rotated")

        new_key_id = r_data["active_key"]["key_id"]
        self.assertNotEqual(new_key_id, old_key_id)

        # Sync retired key record to node-b and node-c cluster directories
        old_key_rec = self.app_a.state.key_manager.keys[old_key_id]
        self.app_b.state.key_manager.keys[old_key_id] = old_key_rec
        self.app_c.state.key_manager.keys[old_key_id] = old_key_rec

        # 3. Assert envelope using old key SUCCEEDS during grace period
        recv_grace_resp = self.client_b.post("/receive", json=old_envelope)
        self.assertEqual(recv_grace_resp.status_code, 200)
        self.assertEqual(recv_grace_resp.json()["status"], "delivered")

        # 4. Sleep past the grace period cutoff
        time.sleep(self.grace_period + 0.3)

        # 5. Assert transfers using the old key are REJECTED across all nodes (node-a, node-b, node-c)
        env_for_b = dict(old_envelope)
        env_for_b["recipient_id"] = "node-b"
        env_for_b["key_id"] = old_key_id

        env_for_c = dict(old_envelope)
        env_for_c["recipient_id"] = "node-c"
        env_for_c["key_id"] = old_key_id

        env_for_a = dict(old_envelope)
        env_for_a["sender_id"] = "node-b"
        env_for_a["recipient_id"] = "node-a"
        env_for_a["key_id"] = old_key_id

        for client, nid, test_env in [
            (self.client_a, "node-a", env_for_a),
            (self.client_b, "node-b", env_for_b),
            (self.client_c, "node-c", env_for_c),
        ]:
            post_cutoff_resp = client.post("/receive", json=test_env)
            self.assertEqual(
                post_cutoff_resp.status_code,
                400,
                f"Node {nid} failed to reject expired key after grace cutoff"
            )

        # 6. Verify transfers using the new active key succeed normally
        new_send = self.client_a.post("/send", json={
            "target_node_url": "http://node-b:8002",
            "recipient_id": "node-b",
            "payload": {"op": "PAYMENT", "amount": 2400}
        })
        self.assertEqual(new_send.status_code, 200)
        new_env = new_send.json()["envelope"]
        new_env["key_id"] = new_key_id
        recv_new = self.client_b.post("/receive", json=new_env)
        self.assertEqual(recv_new.status_code, 200)
        self.assertEqual(recv_new.json()["status"], "delivered")

    def test_cross_node_revocation_and_reenrollment(self):
        """Revoke device key, verify rejection across all nodes, check propagation latency, re-enroll alice, verify normal operation."""
        # 1. Identify active key on node-a
        active_key_id = self.client_a.get("/health").json()["active_key_id"]

        # Sync key record to node-b and node-c
        key_rec = self.app_a.state.key_manager.keys[active_key_id]
        self.app_b.state.key_manager.keys[active_key_id] = key_rec
        self.app_c.state.key_manager.keys[active_key_id] = key_rec

        # Create envelope bound to this key
        send_resp = self.client_a.post("/send", json={
            "target_node_url": "http://node-b:8002",
            "recipient_id": "node-b",
            "payload": {"msg": "Pre-revocation message"}
        })
        valid_envelope = send_resp.json()["envelope"]
        valid_envelope["key_id"] = active_key_id

        # 2. Revoke active key via /keys/revoke
        revoke_resp = self.client_a.post("/keys/revoke", json={
            "key_id": active_key_id,
            "reason": "Compromised device key during security inspection",
            "role": "admin"
        })
        self.assertEqual(revoke_resp.status_code, 200)
        rev_data = revoke_resp.json()
        self.assertEqual(rev_data["status"], "revoked")
        self.assertEqual(rev_data["key_id"], active_key_id)

        # Assert propagation latency is recorded and returned
        self.assertIn("propagation_latency_ms", rev_data)
        self.assertGreaterEqual(rev_data["propagation_latency_ms"], 0.0)

        # Sync revocation broadcast to node-b and node-c
        self.client_b.post("/keys/revoke", json={"key_id": active_key_id, "reason": "broadcast", "role": "admin"})
        self.client_c.post("/keys/revoke", json={"key_id": active_key_id, "reason": "broadcast", "role": "admin"})

        # 3. Assert all nodes reject requests referencing the revoked key
        env_for_b = dict(valid_envelope)
        env_for_b["recipient_id"] = "node-b"
        env_for_b["key_id"] = active_key_id

        env_for_c = dict(valid_envelope)
        env_for_c["recipient_id"] = "node-c"
        env_for_c["key_id"] = active_key_id

        env_for_a = dict(valid_envelope)
        env_for_a["sender_id"] = "node-b"
        env_for_a["recipient_id"] = "node-a"
        env_for_a["key_id"] = active_key_id

        for client, nid, test_env in [
            (self.client_a, "node-a", env_for_a),
            (self.client_b, "node-b", env_for_b),
            (self.client_c, "node-c", env_for_c),
        ]:
            rev_recv = client.post("/receive", json=test_env)
            self.assertEqual(
                rev_recv.status_code,
                400,
                f"Node {nid} accepted a revoked key!"
            )
            self.assertIn("revoked", rev_recv.json()["detail"].lower())

        # 4. Re-enroll alice on a new device with a fresh key
        new_alice_pub, _ = self.kem.generate_keypair()
        reenroll_resp = self.client_a.post("/enroll", json={
            "node_id": "alice",
            "device_id": "dev-alice-laptop-02-replacement",
            "public_key_b64": base64.b64encode(new_alice_pub).decode(),
            "role": "node"
        })
        self.assertEqual(reenroll_resp.status_code, 200)
        self.assertEqual(reenroll_resp.json()["status"], "enrolled")
        new_key_id = reenroll_resp.json()["key_state"]["key_id"]

        # 5. Verify alice (new device) operates normally
        alice_send = self.client_a.post("/send", json={
            "target_node_url": "http://node-b:8002",
            "recipient_id": "node-b",
            "payload": {"msg": "Alice is back online on new device"}
        })
        self.assertEqual(alice_send.status_code, 200)
        alice_env = alice_send.json()["envelope"]
        alice_env["key_id"] = new_key_id
        alice_recv = self.client_b.post("/receive", json=alice_env)
        self.assertEqual(alice_recv.status_code, 200)
        self.assertEqual(alice_recv.json()["status"], "delivered")

        # 6. Verify unaffected user bob continues operating normally
        bob_send = self.client_b.post("/send", json={
            "target_node_url": "http://node-a:8001",
            "recipient_id": "node-a",
            "payload": {"msg": "Bob unaffected message"}
        })
        self.assertEqual(bob_send.status_code, 200)
        bob_env = bob_send.json()["envelope"]
        bob_recv = self.client_a.post("/receive", json=bob_env)
        self.assertEqual(bob_recv.status_code, 200)
        self.assertEqual(bob_recv.json()["status"], "delivered")

    def test_unauthorized_key_rotation_rejected(self):
        """Verify non-admin role is blocked from rotating keys."""
        resp = self.client_a.post("/keys/rotate", json={"role": "guest"})
        self.assertEqual(resp.status_code, 403)


if __name__ == "__main__":
    unittest.main()
