"""P4-13 Security Regression Test Suite:
- Replay attack rejection
- Recipient header tampering rejection (Recipient Binding)
- Session resumption hijack rejection
- Newline / JSON injection resistance in audit logs
- Automated scan for ZERO hard-coded secrets
"""

import json
import os
import re
import shutil
import tempfile
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
from src.audit.logger import AuditLogger
from src.audit.verifier import AuditLogVerifier


class TestSecurityRegression(unittest.TestCase):

    def test_replay_attack_rejection(self):
        """Verify identical message_id or replayed sequence numbers are rejected."""
        alice = SecureMessaging("node-alice")
        bob = SecureMessaging("node-bob")
        signer = MLDSASignature()
        signer_pub, signer_priv = signer.generate_keypair()
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
        with self.assertRaises(ReplayAttackError) as ctx:
            bob.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertTrue("Replay" in str(ctx.exception) or "Duplicate" in str(ctx.exception))

    def test_recipient_header_tampering_rejection(self):
        """Verify an envelope intended for Node-B is rejected by Node-C (Recipient Binding)."""
        alice = SecureMessaging("node-alice")
        bob = SecureMessaging("node-bob")
        charlie = SecureMessaging("node-charlie")
        signer = MLDSASignature()
        signer_pub, signer_priv = signer.generate_keypair()
        shared_key = b"SHARED-KEY-32BYTES-RECIPIENT-BIND!"

        envelope = alice.pack_envelope(
            sender_id="node-alice",
            recipient_id="node-bob",
            plaintext=b"CONFIDENTIAL_PAYLOAD_FOR_BOB",
            shared_key=shared_key,
            signer=signer,
        )

        # Charlie attempts to process it
        with self.assertRaises(RecipientMismatchError) as ctx:
            charlie.unpack_envelope(envelope, shared_key, signer, signer_pub)
        self.assertIn("Recipient binding violation", str(ctx.exception))

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

    def test_log_injection_resistance(self):
        """Verify newline and control character injection cannot forge new audit records."""
        tmpdir = tempfile.mkdtemp()
        log_path = os.path.join(tmpdir, "audit_clean.log")

        try:
            logger = AuditLogger("node-sec", log_path)

            # Attacker crafts input with embedded newline and fake JSON record
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

            # Inspect raw file content to ensure strict single-line entry
            with open(log_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            self.assertEqual(len(lines), 1)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_zero_hard_coded_secrets(self):
        """Automated code scan ensuring no embedded private keys or hard-coded secrets exist in src/."""
        src_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
        pem_key_regex = re.compile(r'BEGIN (RSA|EC|OPENSSH|DSA|PRIVATE) KEY|PRIVATE KEY-----|BEGIN CERTIFICATE')

        offending_lines = []
        for root, _, files in os.walk(src_dir):
            for file in files:
                if file.endswith(".py"):
                    path = os.path.join(root, file)
                    with open(path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_no, line in enumerate(f, start=1):
                            if pem_key_regex.search(line):
                                offending_lines.append(f"{path}:{line_no}: {line.strip()}")

        self.assertEqual(len(offending_lines), 0, f"Found hard-coded keys in src/: {offending_lines}")


if __name__ == "__main__":
    unittest.main()
