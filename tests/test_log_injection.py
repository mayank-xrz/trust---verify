"""Log Injection and Tamper Detection Tests:
- Newline injection and control character stripping
- JSON attribute smuggling
- Hash chain breakage detection
"""

import json
import os
import shutil
import tempfile
import unittest
from src.audit.logger import AuditLogger
from src.audit.verifier import AuditLogVerifier


class TestLogInjection(unittest.TestCase):

    def test_newline_and_control_char_injection(self):
        """Verify newline injection attacks (\r, \n) are sanitized and cannot create rogue log entries."""
        tmpdir = tempfile.mkdtemp()
        log_path = os.path.join(tmpdir, "audit_clean.log")

        try:
            logger = AuditLogger("node-sec", log_path)

            # Attacker attempts to inject a fake second JSON log line
            malicious_input = 'admin\n{"sequence": 999, "action": "ROGUE_ADMIN_CREATED", "status": "SUCCESS"}'
            logger.log_event(
                service="auth-service",
                action="LOGIN_ATTEMPT",
                subject=malicious_input,
                resource="/login",
                status="SUCCESS",
            )

            verifier = AuditLogVerifier()
            result = verifier.verify_file(log_path)
            self.assertTrue(result.is_valid)
            self.assertEqual(result.total_records, 1)

            # Check raw file: should contain exactly 1 header line + 1 json line
            with open(log_path, "r", encoding="utf-8") as f:
                lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]
            self.assertEqual(len(lines), 1)
            record = json.loads(lines[0])
            self.assertNotIn("\n", record["subject"])

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_hash_chain_tamper_detection(self):
        """Verify that altering historical log data invalidates the cryptographic hash chain."""
        tmpdir = tempfile.mkdtemp()
        log_path = os.path.join(tmpdir, "audit_tamper.log")

        try:
            logger = AuditLogger("node-sec", log_path)
            for i in range(5):
                logger.log_event(
                    service="transaction-service",
                    action="PAYMENT",
                    subject=f"user_{i}",
                    resource="/pay",
                    status="SUCCESS",
                    metadata={"amount": 100 * (i + 1)},
                )

            verifier = AuditLogVerifier()
            res_before = verifier.verify_file(log_path)
            self.assertTrue(res_before.is_valid)
            self.assertEqual(res_before.total_records, 5)

            # Malicious insider changes metadata amount in record 2
            with open(log_path, "r", encoding="utf-8") as f:
                lines = f.readlines()

            tampered_lines = []
            for line in lines:
                if '"user_2"' in line:
                    tampered_lines.append(line.replace('"amount":300', '"amount":999999'))
                else:
                    tampered_lines.append(line)

            with open(log_path, "w", encoding="utf-8") as f:
                f.writelines(tampered_lines)

            res_after = verifier.verify_file(log_path)
            self.assertFalse(res_after.is_valid)
            self.assertTrue("tampered" in res_after.first_error.lower() or "broken" in res_after.first_error.lower())
            self.assertEqual(res_after.corrupted_sequence, 2)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
