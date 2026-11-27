"""HTTP tests of the demo node's recipient-specific protected transport."""

import json
import os
import secrets
import sqlite3
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from starlette.testclient import TestClient

from demo.node.operator_cli import OperatorCLI
from demo.node.server import create_app


class TestIntegrationE2E(unittest.TestCase):

    def setUp(self):
        state = tempfile.TemporaryDirectory(prefix="tbv_integration_")
        self.addCleanup(state.cleanup)
        self.state = Path(state.name)
        self.peer_token = secrets.token_urlsafe(32)
        self.operator_token = secrets.token_urlsafe(32)
        self.enterContext(patch.dict(os.environ, {"DEMO_SANDBOX_ENABLED": "1"}))
        self.sync_token = secrets.token_urlsafe(32)
        nodes = ("node-a", "node-b", "node-c")
        self.recipient_tokens = {node: secrets.token_urlsafe(32) for node in nodes}
        self.client_a, self.client_b, self.client_c = (self.create_node(node) for node in nodes)

    @staticmethod
    def bearer(token):
        return {"Authorization": f"Bearer {token}"}

    def create_node(self, node_id):
        client = TestClient(
            create_app(
                node_id=node_id,
                data_dir=str(self.state / node_id),
                grace_period_seconds=30,
                peer_enroll_token=self.peer_token,
                operator_token=self.operator_token,
                recipient_token=self.recipient_tokens[node_id],
                revocation_sync_token=self.sync_token,
            )
        )
        self.addCleanup(client.close)
        return client

    def enroll_peer(self, client, bundle):
        response = client.post("/peers", json=bundle, headers=self.bearer(self.peer_token))
        self.assertEqual(response.status_code, 200, response.text)

    def connect(self, sender, receiver):
        self.enroll_peer(sender, receiver.get("/keys/public").json())
        self.enroll_peer(receiver, sender.get("/keys/public").json())

    def send(self, sender, recipient, payload):
        response = sender.post(
            "/send",
            headers=self.bearer(self.operator_token),
            json={"target_node_url": f"http://{recipient}", "recipient_id": recipient, "payload": payload},
        )
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()["envelope"]

    def receive(self, receiver, envelope):
        response = receiver.post("/receive", json=envelope)
        self.assertEqual(response.status_code, 200, response.text)
        receipt = response.json()
        self.assertEqual(set(receipt), {"status", "receipt_id", "message_id", "sequence", "record_hash"})
        self.assertEqual(receipt["message_id"], envelope["message_id"])
        self.assertEqual(receipt["status"], "delivered")
        self.assertTrue(receipt["record_hash"])
        return f"/inbox/{receipt['receipt_id']}"

    def assert_readable(self, receiver, path, payload):
        token = self.recipient_tokens[receiver.app.state.node_id]
        response = receiver.get(path, headers=self.bearer(token))
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()["payload"], payload)
        self.assertEqual(response.headers["Cache-Control"], "no-store")

    def assert_delivered(self, receiver, envelope, payload):
        self.assert_readable(receiver, self.receive(receiver, envelope), payload)

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
            self.client_a.post("/peers", json=invalid_bundle, headers=self.bearer(self.peer_token)).status_code,
            422,
        )
        conflicting_bundle = dict(
            bundle, signing_public_key_b64=self.client_c.get("/keys/public").json()["signing_public_key_b64"]
        )
        self.assertEqual(
            self.client_a.post("/peers", json=conflicting_bundle, headers=self.bearer(self.peer_token)).status_code,
            409,
        )

    def test_protected_transfer_for_multiple_recipients(self):
        payload = {"memo": "PQC protected transfer"}
        request = {"target_node_url": "http://node-b", "recipient_id": "node-b", "payload": payload}
        self.assertEqual(self.client_a.post("/send", json=request, headers=self.bearer(self.operator_token)).status_code, 403)

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
        self.assert_rejected(self.client_b, first, "Duplicate message rejected")

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
        rotate = self.client_b.post("/keys/rotate", headers=self.bearer(self.operator_token))
        self.assertEqual(rotate.status_code, 200, rotate.text)
        new_bundle = self.client_b.get("/keys/public").json()
        self.assertNotEqual(new_bundle["kem_key_id"], old_bundle["kem_key_id"])
        cutoff = self.client_b.app.state.key_manager.keys[old_bundle["kem_key_id"]].grace_period_cutoff

        restarted = self.create_node("node-b")
        self.enroll_peer(restarted, self.client_a.get("/keys/public").json())
        old_receipt = self.receive(restarted, old_message)
        self.assert_readable(restarted, old_receipt, {"phase": "grace"})
        with patch("src.identity.key_manager.time.time", return_value=cutoff):
            self.assert_rejected(restarted, late_message, "Recipient key is expired")
            self.assertEqual(
                restarted.get(old_receipt, headers=self.bearer(self.recipient_tokens["node-b"])).status_code,
                410,
            )

        self.enroll_peer(self.client_a, new_bundle)
        stale = self.client_a.post("/peers", json=old_bundle, headers=self.bearer(self.peer_token))
        self.assertEqual(stale.status_code, 409)
        current = self.send(self.client_a, "node-b", {"phase": "new key"})
        self.assert_delivered(restarted, current, {"phase": "new key"})

    def test_revocation_isolates_recipient_and_replacement_restores_access(self):
        self.connect(self.client_a, self.client_b)
        self.connect(self.client_a, self.client_c)
        addressed_to_b = self.send(self.client_a, "node-b", {"message": "in flight"})
        addressed_to_c = self.send(self.client_a, "node-c", {"message": "unaffected"})
        revoked = self.client_b.post(
            "/keys/revoke", json={"key_id": addressed_to_b["key_id"]},
            headers=self.bearer(self.operator_token),
        )
        self.assertEqual(revoked.status_code, 200, revoked.text)
        self.assert_rejected(self.client_b, addressed_to_b, "Recipient key is revoked")
        self.assert_delivered(self.client_c, addressed_to_c, {"message": "unaffected"})

        self.assertEqual(
            self.client_b.post("/keys/rotate", headers=self.bearer(self.operator_token)).status_code, 200
        )
        self.enroll_peer(self.client_a, self.client_b.get("/keys/public").json())
        new_message = self.send(self.client_a, "node-b", {"message": "replacement key"})
        self.assert_delivered(self.client_b, new_message, {"message": "replacement key"})

    def test_peer_revocation_blocks_new_sends_after_restart(self):
        old = self.client_b.get("/keys/public").json()
        self.enroll_peer(self.client_a, old)
        event = {
            "key_id": old["kem_key_id"],
            "target_node_id": "node-b",
            "revocation_id": "test-revocation",
        }
        for _ in range(2):
            response = self.client_a.post(
                "/internal/keys/revoke", json=event, headers=self.bearer(self.sync_token),
            )
            self.assertEqual(response.status_code, 200, response.text)
            self.assertEqual(response.json()["revocation_id"], event["revocation_id"])

        restarted = self.create_node("node-a")
        self.enroll_peer(restarted, old)
        blocked = restarted.post(
            "/send", json={"recipient_id": "node-b", "payload": {}},
            headers=self.bearer(self.operator_token),
        )
        self.assertEqual(blocked.status_code, 409)
        self.assertEqual(blocked.json()["detail"], "Peer recipient key is revoked")

        rotated = self.client_b.post("/keys/rotate", headers=self.bearer(self.operator_token))
        self.assertEqual(rotated.status_code, 200, rotated.text)
        self.connect(restarted, self.client_b)
        payload = {"message": "replacement key"}
        self.assert_delivered(self.client_b, self.send(restarted, "node-b", payload), payload)

    def test_key_administration_requires_its_own_credential_and_records_operator(self):
        client = self.client_a
        key_id = client.get("/health").json()["active_key_id"]
        body = {"role": "admin", "requested_by": "unverified", "key_id": key_id}
        for headers in ({}, self.bearer(self.peer_token), self.bearer(self.sync_token)):
            self.assertEqual(client.post("/keys/rotate", json=body, headers=headers).status_code, 401)
            self.assertEqual(client.post("/keys/revoke", json=body, headers=headers).status_code, 401)
        self.assertEqual(client.get("/health").json()["active_key_id"], key_id)

        operator = self.bearer(self.operator_token)
        self.assertEqual(client.post("/internal/keys/revoke", json=body, headers=operator).status_code, 401)
        self.assertEqual(client.post("/keys/rotate", json=body, headers=operator).status_code, 200)
        self.assertEqual(client.post("/keys/revoke", json=body, headers=operator).status_code, 200)
        with Path(client.app.state.audit_logger.log_file_path).open() as log:
            records = [json.loads(line) for line in log if line.strip() and not line.startswith("#")]
        actors = {record["action"]: record["subject"] for record in records}
        self.assertEqual(actors["ROTATE_KEY_SUCCESS"], "demo-operator")
        self.assertEqual(actors["REVOKE_KEY_SUCCESS"], "demo-operator")
        self.assertEqual(actors["OPERATOR_AUTH_DENIED"], "unauthenticated")

    def test_key_administration_alert_points_to_each_recorded_denial(self):
        client = self.client_b
        for _ in range(2):
            self.assertEqual(client.post("/keys/rotate").status_code, 401)

        dashboard = client.get("/api/sandbox/state", headers=self.bearer(self.operator_token)).json()
        cli_metrics = client.get("/metrics", headers=self.bearer(self.operator_token)).json()
        denials = {
            record["event_id"]: record for record in dashboard["audit"]["recent_entries"]
            if record["action"] == "OPERATOR_AUTH_DENIED"
        }
        self.assertEqual(len(denials), 2)
        for feed in (dashboard["alerts"], cli_metrics["alerts"]):
            alerts = [alert for alert in feed if alert["rule_name"] == "UNAUTHORIZED_KEY_ADMINISTRATION"]
            self.assertCountEqual([alert["evidence"]["event_id"] for alert in alerts], denials.keys())
            for alert in alerts:
                evidence = alert["evidence"]
                record = denials[evidence["event_id"]]
                self.assertEqual(alert["severity"], "HIGH")
                self.assertEqual(alert["subject"], "unauthenticated")
                self.assertEqual(alert["service"], "node-b")
                self.assertEqual(alert["resource"], "/keys/rotate")
                for field in ("subject", "service", "resource", "timestamp_ns"):
                    self.assertEqual(alert[field], record[field])
                for field in ("sequence", "action", "status"):
                    self.assertEqual(evidence[field], record[field])
                self.assertEqual(evidence["status"], "DENIED")

        output = StringIO()
        with patch("demo.node.operator_cli.http_request", return_value=(200, cli_metrics)):
            with redirect_stdout(output):
                OperatorCLI({"node-b": "http://node-b"}).alerts()
        for detail in ("Subject: unauthenticated", "Service: node-b", "UNAUTHORIZED_KEY_ADMINISTRATION", *denials):
            self.assertIn(detail, output.getvalue())

    def test_sandbox_audit_tamper_demo_preserves_node_audit_evidence(self):
        client = self.client_b
        self.assertEqual(client.post("/keys/rotate").status_code, 401)
        log_path = Path(client.app.state.audit_logger.log_file_path)
        original_log = log_path.read_bytes()

        for action, expected_validity in (("tamper", False), ("restore", True), ("verify", True)):
            with self.subTest(action=action):
                response = client.post(
                    "/api/sandbox/audit/tamper", json={"action": action},
                    headers=self.bearer(self.operator_token),
                )
                self.assertEqual(response.status_code, 200)
                self.assertIs(response.json()["verification"]["is_valid"], expected_validity)
                self.assertEqual(log_path.read_bytes(), original_log)

        self.assertEqual(client.get("/logs/verify", headers=self.bearer(self.operator_token)).status_code, 200)

    def test_receipt_is_public_and_inbox_requires_the_intended_recipients_credential(self):
        self.connect(self.client_a, self.client_b)
        payload = {"message": "only node-b can read this"}
        envelope = self.send(self.client_a, "node-b", payload)
        path = self.receive(self.client_b, envelope)
        for headers in ({}, self.bearer(self.operator_token), self.bearer(self.recipient_tokens["node-c"])):
            self.assertEqual(self.client_b.get(path, headers=headers).status_code, 401)
        self.assert_readable(self.client_b, path, payload)
        with sqlite3.connect(self.state / "node-b" / "node-b_inbox.sqlite3") as db:
            stored, = db.execute("SELECT envelope FROM deliveries").fetchone()
        self.assertNotIn(payload["message"], stored)

    def test_concurrent_delivery_and_replay_after_receiver_restart(self):
        self.connect(self.client_a, self.client_b)
        payload = {"message": "accept once"}
        envelope = self.send(self.client_a, "node-b", payload)
        with ThreadPoolExecutor(max_workers=2) as pool:
            responses = list(pool.map(lambda _: self.client_b.post("/receive", json=envelope), range(2)))
        self.assertEqual(sorted(response.status_code for response in responses), [200, 400])
        receipt = next(response.json()["receipt_id"] for response in responses if response.is_success)
        self.client_b.close()

        restarted = self.create_node("node-b")
        self.enroll_peer(restarted, self.client_a.get("/keys/public").json())
        self.assert_rejected(restarted, envelope, "Duplicate message rejected")
        self.assert_readable(restarted, f"/inbox/{receipt}", payload)
        self.assert_delivered(restarted, self.send(self.client_a, "node-b", payload), payload)
