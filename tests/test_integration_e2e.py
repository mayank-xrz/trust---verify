"""HTTP tests of the demo node's recipient-specific protected transport."""

import secrets
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

from demo.node.server import create_app


class TestIntegrationE2E(unittest.TestCase):

    def setUp(self):
        state = tempfile.TemporaryDirectory(prefix="tbv_integration_")
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        token = secrets.token_urlsafe(32)
        self.operator = {"Authorization": f"Bearer {token}"}
        self.client_a, self.client_b, self.client_c = (
            self.create_node(node, token) for node in ("node-a", "node-b", "node-c")
        )
        self.token = token

    def create_node(self, node_id, token):
        client = TestClient(
            create_app(
                node_id=node_id,
                data_dir=str(self.state / node_id),
                grace_period_seconds=30,
                peer_enroll_token=token,
            )
        )
        self.addCleanup(client.close)
        return client

    def enroll_peer(self, client, bundle):
        response = client.post("/peers", json=bundle, headers=self.operator)
        self.assertEqual(response.status_code, 200, response.text)

    def connect(self, sender, receiver):
        self.enroll_peer(sender, receiver.get("/keys/public").json())
        self.enroll_peer(receiver, sender.get("/keys/public").json())

    def send(self, sender, recipient, payload):
        response = sender.post(
            "/send",
            json={"target_node_url": f"http://{recipient}", "recipient_id": recipient, "payload": payload},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["envelope"]

    def assert_delivered(self, receiver, envelope, payload):
        response = receiver.post("/receive", json=envelope)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["payload"], payload)
        self.assertTrue(response.json()["record_hash"])

    def assert_rejected(self, receiver, envelope, detail, status=400):
        response = receiver.post("/receive", json=envelope)
        self.assertEqual(response.status_code, status, response.text)
        self.assertIn(detail, response.json()["detail"])

    def test_multi_node_health_and_enrollment(self):
        for client, node_id in (
            (self.client_a, "node-a"), (self.client_b, "node-b"), (self.client_c, "node-c")
        ):
            self.assertEqual(client.get("/health").json()["node_id"], node_id)
            bundle = client.get("/keys/public").json()
            self.assertEqual(bundle["node_id"], node_id)
            self.assertEqual(
                set(bundle),
                {"node_id", "signing_public_key_b64", "kem_key_id", "kem_key_version", "kem_public_key_b64"},
            )

        bundle = self.client_b.get("/keys/public").json()
        self.assertEqual(self.client_a.post("/peers", json=bundle).status_code, 401)
        self.enroll_peer(self.client_a, bundle)
        self.enroll_peer(self.client_a, bundle)
        invalid_bundle = dict(bundle, kem_public_key_b64=bundle["signing_public_key_b64"])
        self.assertEqual(
            self.client_a.post("/peers", json=invalid_bundle, headers=self.operator).status_code,
            422,
        )
        conflicting_bundle = dict(
            bundle, signing_public_key_b64=self.client_c.get("/keys/public").json()["signing_public_key_b64"]
        )
        self.assertEqual(
            self.client_a.post("/peers", json=conflicting_bundle, headers=self.operator).status_code,
            409,
        )

    def test_protected_transfer_for_multiple_recipients(self):
        payload = {"memo": "PQC protected transfer"}
        request = {"target_node_url": "http://node-b", "recipient_id": "node-b", "payload": payload}
        self.assertEqual(self.client_a.post("/send", json=request).status_code, 403)

        self.enroll_peer(self.client_a, self.client_b.get("/keys/public").json())
        first = self.send(self.client_a, "node-b", payload)
        self.assert_rejected(self.client_b, first, "Sender transport keys are not enrolled", 403)
        self.connect(self.client_a, self.client_b)
        self.connect(self.client_a, self.client_c)
        second = self.send(self.client_a, "node-b", payload)
        third = self.send(self.client_a, "node-c", payload)

        self.assertNotEqual(first["kem_ciphertext"], second["kem_ciphertext"])
        self.assertNotEqual(first["key_id"], third["key_id"])
        self.assert_rejected(self.client_c, first, "Recipient binding violation")
        self.assert_delivered(self.client_b, first, payload)
        self.assert_delivered(self.client_b, second, payload)
        self.assert_delivered(self.client_c, third, payload)
        self.assert_rejected(self.client_b, first, "Duplicate message_id")

    def test_envelope_requires_signed_key_id_and_kem_ciphertext(self):
        self.connect(self.client_a, self.client_b)
        payload = {"message": "authenticated metadata"}
        envelope = self.send(self.client_a, "node-b", payload)
        other = self.send(self.client_a, "node-b", payload)

        self.assert_rejected(self.client_b, dict(envelope, key_id="unrecognized"), "signature")
        self.assert_rejected(
            self.client_b, dict(envelope, kem_ciphertext=other["kem_ciphertext"]), "signature"
        )
        self.assert_delivered(self.client_b, envelope, payload)

    def test_rotation_grace_survives_restart_and_enforces_cutoff(self):
        self.connect(self.client_a, self.client_b)
        old_bundle = self.client_b.get("/keys/public").json()
        old_message = self.send(self.client_a, "node-b", {"phase": "grace"})
        late_message = self.send(self.client_a, "node-b", {"phase": "after cutoff"})
        rotate = self.client_b.post("/keys/rotate", json={"role": "admin"})
        self.assertEqual(rotate.status_code, 200, rotate.text)
        new_bundle = self.client_b.get("/keys/public").json()
        self.assertNotEqual(new_bundle["kem_key_id"], old_bundle["kem_key_id"])
        cutoff = self.client_b.app.state.key_manager.keys[old_bundle["kem_key_id"]].grace_period_cutoff

        restarted = self.create_node("node-b", self.token)
        self.enroll_peer(restarted, self.client_a.get("/keys/public").json())
        self.assert_delivered(restarted, old_message, {"phase": "grace"})
        with patch("src.identity.key_manager.time.time", return_value=cutoff):
            self.assert_rejected(restarted, late_message, "Recipient key is expired")

        self.enroll_peer(self.client_a, new_bundle)
        stale = self.client_a.post("/peers", json=old_bundle, headers=self.operator)
        self.assertEqual(stale.status_code, 409)
        current = self.send(self.client_a, "node-b", {"phase": "new key"})
        self.assert_delivered(restarted, current, {"phase": "new key"})

    def test_revocation_isolates_recipient_and_replacement_restores_access(self):
        self.connect(self.client_a, self.client_b)
        self.connect(self.client_a, self.client_c)
        addressed_to_b = self.send(self.client_a, "node-b", {"message": "in flight"})
        addressed_to_c = self.send(self.client_a, "node-c", {"message": "unaffected"})
        revoked = self.client_b.post(
            "/keys/revoke", json={"key_id": addressed_to_b["key_id"], "role": "admin"}
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assert_rejected(self.client_b, addressed_to_b, "Recipient key is revoked")
        self.assert_delivered(self.client_c, addressed_to_c, {"message": "unaffected"})

        self.assertEqual(self.client_b.post("/keys/rotate", json={"role": "admin"}).status_code, 200)
        self.enroll_peer(self.client_a, self.client_b.get("/keys/public").json())
        new_message = self.send(self.client_a, "node-b", {"message": "replacement key"})
        self.assert_delivered(self.client_b, new_message, {"message": "replacement key"})

    def test_unauthorized_key_rotation_rejected(self):
        response = self.client_a.post("/keys/rotate", json={"role": "guest"})
        self.assertEqual(response.status_code, 403)
