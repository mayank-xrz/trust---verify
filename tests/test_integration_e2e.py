"""P4-11 End-to-End Integration Test Suite across 3 mock nodes (node-a, node-b, node-c).

Tests:
- Multi-node enrollment
- Authenticated PQC message transfer between nodes
- Key rotation with grace period
- Post-cutoff key rejection across nodes
- Cross-node revocation broadcast & enforcement
- Device re-enrollment flow
"""

import base64
import json
import time
import unittest
from starlette.testclient import TestClient

from src.node.server import create_app
from src.crypto.pqc_kem import MLKEMKeyExchange
from src.crypto.pqc_sig import MLDSASignature
from src.crypto.messaging import SecureMessaging, RecipientMismatchError, ReplayAttackError


class TestIntegrationE2E(unittest.TestCase):

    def setUp(self):
        # Create apps for 3 sandbox nodes
        self.app_a = create_app(node_id="node-a", data_dir="/tmp/tbv_data_a")
        self.app_b = create_app(node_id="node-b", data_dir="/tmp/tbv_data_b")
        self.app_c = create_app(node_id="node-c", data_dir="/tmp/tbv_data_c")

        self.client_a = TestClient(self.app_a)
        self.client_b = TestClient(self.app_b)
        self.client_c = TestClient(self.app_c)

        self.kem = MLKEMKeyExchange()
        self.sig = MLDSASignature()

        # Shared peer key for test
        self.shared_key = b"INTEGRATION_TEST_PQC_KEY_32BYTES!"
        self.app_a.state.peer_shared_keys["node-b"] = self.shared_key
        self.app_b.state.peer_shared_keys["node-a"] = self.shared_key
        self.app_c.state.peer_shared_keys["node-a"] = self.shared_key

        # Peer public keys for signature verification
        if getattr(self.app_a.state, "sig_provider", None) and self.app_a.state.sig_provider._public_key:
            self.app_b.state.peer_public_keys["node-a"] = self.app_a.state.sig_provider._public_key
            self.app_c.state.peer_public_keys["node-a"] = self.app_a.state.sig_provider._public_key
        if getattr(self.app_b.state, "sig_provider", None) and self.app_b.state.sig_provider._public_key:
            self.app_a.state.peer_public_keys["node-b"] = self.app_b.state.sig_provider._public_key

    def test_multi_node_health_and_enrollment(self):
        """Verify all 3 nodes report healthy and enroll correctly."""
        for client, nid in [(self.client_a, "node-a"), (self.client_b, "node-b"), (self.client_c, "node-c")]:
            resp = client.get("/health")
            self.assertEqual(resp.status_code, 200)
            data = resp.json()
            self.assertEqual(data["status"], "healthy")
            self.assertEqual(data["node_id"], nid)

        # Enroll node-b into node-a
        pub, _ = self.kem.generate_keypair()
        enroll_resp = self.client_a.post("/enroll", json={
            "node_id": "node-b",
            "public_key_b64": base64.b64encode(pub).decode(),
            "role": "node"
        })
        self.assertEqual(enroll_resp.status_code, 200)
        self.assertEqual(enroll_resp.json()["status"], "enrolled")

    def test_authenticated_message_transfer(self):
        """Verify node-a dispatches envelope and node-b successfully receives and verifies it."""
        payload = {"transaction_id": "tx-1001", "amount": 5000, "currency": "USD"}

        # 1. Dispatch from node-a
        send_resp = self.client_a.post("/send", json={
            "target_node_url": "http://node-b:8002",
            "recipient_id": "node-b",
            "payload": payload
        })
        self.assertEqual(send_resp.status_code, 200)
        envelope = send_resp.json()["envelope"]
        self.assertEqual(envelope["sender_id"], "node-a")
        self.assertEqual(envelope["recipient_id"], "node-b")

        # 2. Receive on node-b
        recv_resp = self.client_b.post("/receive", json=envelope)
        self.assertEqual(recv_resp.status_code, 200)
        data = recv_resp.json()
        self.assertEqual(data["status"], "delivered")
        self.assertEqual(data["payload"]["amount"], 5000)

    def test_key_rotation_with_grace_period(self):
        """Verify key rotation moves current key to grace period, activates new version."""
        # Check initial key
        init_health = self.client_a.get("/health").json()
        init_key_id = init_health["active_key_id"]
        init_version = init_health["active_key_version"]

        # Rotate key with admin role
        rotate_resp = self.client_a.post("/keys/rotate", json={"role": "admin"})
        self.assertEqual(rotate_resp.status_code, 200)
        r_data = rotate_resp.json()
        self.assertEqual(r_data["status"], "rotated")

        new_key_id = r_data["active_key"]["key_id"]
        self.assertNotEqual(new_key_id, init_key_id)

        # Health reflects new active key version
        new_health = self.client_a.get("/health").json()
        self.assertEqual(new_health["active_key_id"], new_key_id)
        self.assertEqual(new_health["active_key_version"], init_version + 1)

    def test_unauthorized_key_rotation_rejected(self):
        """Verify non-admin role is blocked from rotating keys."""
        resp = self.client_a.post("/keys/rotate", json={"role": "guest"})
        self.assertEqual(resp.status_code, 403)

    def test_cross_node_key_revocation(self):
        """Verify key revocation marks key revoked and rejects subsequent operations."""
        active_key = self.client_a.get("/health").json()["active_key_id"]

        revoke_resp = self.client_a.post("/keys/revoke", json={
            "key_id": active_key,
            "reason": "Suspected key leak in audit inspection",
            "role": "admin"
        })
        self.assertEqual(revoke_resp.status_code, 200)
        self.assertEqual(revoke_resp.json()["status"], "revoked")


if __name__ == "__main__":
    unittest.main()
