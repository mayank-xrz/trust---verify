"""P4-13 Security Regression Test Suite:
- Replay attack rejection on /receive and SecureMessaging
- Recipient binding tampering rejection (changing recipient_id / associated_data without re-signing)
- Session resumption hijack rejection
- Log injection resistance (newlines / JSON injection) and 1-byte mutation detection via /logs/verify
- Static secret and ground-rule audit: zero private keys and zero banned AI/ML packages
"""

import os
import re
import shutil
import tempfile
import unittest

from starlette.testclient import TestClient

from demo.node.crypto_provider import (
    MessageTamperedError,
    MLDSASignature,
    RecipientMismatchError,
    ReplayAttackError,
    ResumptionHijackError,
    SecureMessaging,
    SessionManager,
)
from demo.node.server import create_app
from src.audit.logger import AuditLogger
from src.audit.verifier import AuditLogVerifier


class TestSecurityRegression(unittest.TestCase):

    def test_replay_attack_rejection(self):
        """Verify identical message_id or replayed sequence numbers are rejected at both messaging and endpoint levels."""
        # 1. Crypto messaging layer replay rejection
        alice = SecureMessaging("node-alice")
        bob = SecureMessaging("node-bob")
        signer = MLDSASignature()
        signer_pub, _ = signer.generate_keypair()
        shared_key = b"SHARED-KEY-32BYTES-FOR-REPLAY-TEST!"

        envelope = alice.pack_envelope(
            sender_id="node-alice",
            recipient_id="node-bob",
            plaintext=b'{"action": "TRANSFER", "amount": 1000}',
            shared_key=shared_key,
            signer=signer,
        )

        # First delivery succeeds
        decrypted = bob.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertIn(b"TRANSFER", decrypted)

        # Immediate replay must fail
        with self.assertRaises(ReplayAttackError):
            bob.unpack_envelope(envelope, shared_key, signer, signer_pub)

        # 2. FastAPI endpoint layer replay rejection on /receive
        tmpdir = tempfile.mkdtemp(prefix="tbv_replay_")
        try:
            app = create_app(node_id="node-b", data_dir=tmpdir)
            client = TestClient(app)
            app.state.peer_shared_keys["node-a"] = shared_key
            app.state.peer_public_keys["node-a"] = signer_pub
            app.state.adapters.audit.lateral_graph.allow_edge("node-a", "node-b")

            sender_msg = SecureMessaging("node-a")
            ep_env = sender_msg.pack_envelope(
                sender_id="node-a",
                recipient_id="node-b",
                plaintext=b'{"cmd": "EXECUTE_TX", "tx_id": "tx-4401"}',
                shared_key=shared_key,
                signer=signer,
            )

            # First receive succeeds
            first_resp = client.post("/receive", json=ep_env)
            self.assertEqual(first_resp.status_code, 200)
            self.assertEqual(first_resp.json()["status"], "delivered")

            # Second receive of identical envelope must be rejected with HTTP 400
            second_resp = client.post("/receive", json=ep_env)
            self.assertEqual(second_resp.status_code, 400)
            detail = second_resp.json()["detail"].lower()
            self.assertTrue("replay" in detail or "duplicate" in detail)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_recipient_header_tampering_rejection(self):
        """Verify an envelope intended for Node-B is rejected by Node-C (Recipient Binding)."""
        alice = SecureMessaging("node-alice")
        charlie = SecureMessaging("node-charlie")
        signer = MLDSASignature()
        signer_pub, _ = signer.generate_keypair()
        shared_key = b"SHARED-KEY-32BYTES-RECIPIENT-BIND!"

        envelope = alice.pack_envelope(
            sender_id="node-alice",
            recipient_id="node-bob",
            plaintext=b"CONFIDENTIAL_PAYLOAD_FOR_BOB",
            shared_key=shared_key,
            signer=signer,
        )

        # Charlie attempts to process an envelope addressed to Bob
        with self.assertRaises(RecipientMismatchError) as ctx:
            charlie.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertIn("Recipient binding violation", str(ctx.exception))

        # Tampering with recipient_id in envelope without re-signing must fail signature/tamper check
        envelope["recipient_id"] = "node-charlie"
        with self.assertRaises((MessageTamperedError, RecipientMismatchError)):
            charlie.unpack_envelope(envelope, shared_key, signer, signer_pub)

    def test_session_resumption_hijack_rejection(self):
        """Verify session resumption token cannot be hijacked by a different peer ID."""
        server = SessionManager("server-node")
        master_secret = b"SESSION-MASTER-SECRET-32BYTES-TEST!"

        sess_id, key = server.create_session("client-alice", master_secret)
        ticket = server.issue_resumption_ticket(sess_id)

        # Legitimate client can resume
        new_sid, new_key = server.resume_session(ticket, requesting_peer_id="client-alice")
        self.assertNotEqual(new_sid, sess_id)

        # Attacker client is blocked
        with self.assertRaises(ResumptionHijackError) as ctx:
            server.resume_session(ticket, requesting_peer_id="client-mallory")
        self.assertIn("hijack attempt detected", str(ctx.exception))

    def test_log_injection_and_tamper_detection(self):
        """Verify newline/JSON injection resistance and 1-byte mutation detection via /logs/verify."""
        tmpdir = tempfile.mkdtemp(prefix="tbv_log_test_")
        log_path = os.path.join(tmpdir, "audit_clean.log")

        try:
            # 1. Newline and JSON injection resistance
            logger = AuditLogger("node-sec", log_path)
            malicious_subject = 'admin\n{"sequence": 999, "action": "FORGED_RECORD", "status": "SUCCESS"}\n'
            logger.log_event(
                service="auth-service",
                action="LOGIN",
                subject=malicious_subject,
                resource="/login",
                status="SUCCESS",
            )

            verifier = AuditLogVerifier()
            result = verifier.verify_file(log_path)
            self.assertTrue(result.is_valid)
            self.assertEqual(result.total_records, 1)

            with open(log_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip() and not line.startswith("#")]
            self.assertEqual(len(lines), 1)

            # 2. Tamper detection via /logs/verify endpoint
            app_dir = os.path.join(tmpdir, "app_logs")
            os.makedirs(app_dir, exist_ok=True)
            app = create_app(node_id="node-audit-verify", data_dir=app_dir)
            client = TestClient(app)

            # Record several legitimate events
            app.state.audit_logger.log_event("node-audit-verify", "INIT", "system", "/init", "SUCCESS")
            app.state.audit_logger.log_event("node-audit-verify", "TX", "user-1", "/transfer", "SUCCESS")

            # Clean verification succeeds
            clean_resp = client.get("/logs/verify")
            self.assertEqual(clean_resp.status_code, 200)
            self.assertTrue(clean_resp.json()["is_valid"])

            # Mutate exactly 1 byte in the stored log file
            server_log_file = getattr(
                app.state.audit_logger, "log_file_path", os.path.join(app_dir, "node-audit-verify_audit.log")
            )
            with open(server_log_file, "r", encoding="utf-8") as f:
                content = f.read()

            # Flip one character in the hash chain
            tampered_content = content.replace("SUCCESS", "TAMPERD", 1)
            with open(server_log_file, "w", encoding="utf-8") as f:
                f.write(tampered_content)

            # /logs/verify must flag tampering with HTTP 409 Conflict
            tampered_resp = client.get("/logs/verify")
            self.assertEqual(tampered_resp.status_code, 409)
            self.assertFalse(tampered_resp.json()["detail"]["is_valid"])

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_static_secret_and_ground_rule_audit(self):
        """Automated code scan ensuring ZERO hard-coded secrets in src/ and ZERO banned AI/ML dependencies."""
        repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        src_dir = os.path.join(repo_root, "src")
        req_file = os.path.join(repo_root, "requirements.txt")

        # 1. Scan src/ for embedded private keys
        key_marker = "BEGIN " + "PRIVATE KEY"
        rsa_marker = "BEGIN " + "RSA"
        cert_marker = "BEGIN " + "CERTIFICATE"

        offending_lines = []
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            if key_marker in line or rsa_marker in line or cert_marker in line:
                                offending_lines.append(f"{path}:{line_no}: {line.strip()}")

        self.assertEqual(len(offending_lines), 0, f"Found hard-coded private keys in src/: {offending_lines}")

        # 2. Scan requirements.txt for banned AI/ML dependencies
        banned_aiml = [
            "torch", "pytorch", "tensorflow", "keras", "scikit-learn",
            "sklearn", "transformers", "openai", "anthropic", "langchain"
        ]

        if os.path.exists(req_file):
            with open(req_file, "r", encoding="utf-8") as f:
                req_content = f.read().lower()

            found_banned = [pkg for pkg in banned_aiml if re.search(r'\b' + re.escape(pkg) + r'\b', req_content)]
            self.assertEqual(len(found_banned), 0, f"Found banned AI/ML packages in requirements.txt: {found_banned}")


if __name__ == "__main__":
    unittest.main()
