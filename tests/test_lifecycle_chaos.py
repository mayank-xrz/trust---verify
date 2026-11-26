"""Lifecycle Chaos Test Suite:
- Mid-rotation crash simulation & WAL recovery
- Corrupt backup detection & integrity rejection
- Multi-node revocation broadcast & propagation latency tracking
"""

import json
import os
import shutil
import tempfile
import time
import unittest
from src.identity.key_manager import KeyManager, KeyStateEnum
from src.identity.recovery import WALManager
from src.identity.backup import BackupManager, BackupIntegrityError
from src.identity.revocation import RevocationCoordinator


class TestLifecycleChaos(unittest.TestCase):

    def test_wal_mid_rotation_crash_recovery(self):
        """Simulates a power loss/crash during atomic key rotation and verifies WAL consistency."""
        tmpdir = tempfile.mkdtemp()
        wal_path = os.path.join(tmpdir, "test_wal.log")

        try:
            wal = WALManager(wal_path)
            km = KeyManager("node-alpha", grace_period_seconds=10.0, wal_manager=wal)

            # Initial key enrollment
            km.enroll_initial_key("ML-KEM-768", b"PUBKEY_V1_MOCK", b"PRIVKEY_V1_MOCK")
            old_key_id = km.active_key_id

            # Rotate key
            km.rotate_key(b"PUBKEY_V2_MOCK", b"PRIVKEY_V2_MOCK")
            new_key_id = km.active_key_id
            self.assertNotEqual(new_key_id, old_key_id)

            # Simulate torn write / mid-crash append in WAL
            with open(wal_path, "a", encoding="utf-8") as f:
                f.write("corrupted_checksum {\"op\": \"HALF_WRITTEN_CORRUPTED\n")

            # Crash recovery: new WAL manager instance inspects the file
            recovery_wal = WALManager(wal_path)
            valid_entries = recovery_wal.read_valid_entries()

            # All valid entries prior to corruption must be safely parsed, and corrupted tail ignored
            op_types = [e["op"] for e in valid_entries]
            self.assertIn("ENROLL_KEY", op_types)
            self.assertIn("ROTATE_KEY_BEGIN", op_types)
            self.assertIn("ROTATE_KEY_COMMIT", op_types)
            self.assertNotIn("HALF_WRITTEN_CORRUPTED", op_types)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_backup_tampering_detection(self):
        """Verify that tampering with 1 byte of a backup snapshot raises BackupIntegrityError."""
        tmpdir = tempfile.mkdtemp()
        backup_file = os.path.join(tmpdir, "snapshot.tbv.json")
        master_key = b"BACKUP-SUPER-SECRET-MASTER-KEY-32B!"

        try:
            bm = BackupManager(master_key)
            state_to_save = {
                "node_id": "node-alpha",
                "active_key": "key-alpha-1234",
                "epoch": 42,
            }

            # Create valid backup
            manifest = bm.create_backup(state_to_save, backup_file)
            self.assertTrue(manifest["mac"])

            # Restore from valid backup
            restored = bm.verify_and_restore(backup_file)
            self.assertEqual(restored["epoch"], 42)

            # Malicious attacker alters payload_b64 inside the backup file
            with open(backup_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            # Flip characters in payload_b64
            orig_b64 = data["payload_b64"]
            data["payload_b64"] = orig_b64[:-2] + ("AA" if orig_b64[-2:] != "AA" else "ZZ")

            with open(backup_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

            # Restore must fail due to HMAC signature / checksum mismatch
            with self.assertRaises(BackupIntegrityError) as ctx:
                bm.verify_and_restore(backup_file)
            self.assertTrue("Tampering detected" in str(ctx.exception) or "mismatch" in str(ctx.exception))

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_revocation_broadcast_latency(self):
        """Verify revocation broadcast propagation across a 5-node cluster."""
        coord = RevocationCoordinator("node-lead")
        cluster_nodes = ["node-lead", "node-1", "node-2", "node-3", "node-4"]
        coord.register_cluster_nodes(cluster_nodes)

        # Issue revocation
        rev_event = coord.create_revocation("key-compromised-99", "node-3", "Suspected side-channel leak")
        self.assertTrue(coord.is_revoked("key-compromised-99"))

        # Simulate progressive peer acknowledgments with small synthetic delays
        time.sleep(0.01)
        coord.acknowledge_revocation(rev_event.revocation_id, "node-1")
        coord.acknowledge_revocation(rev_event.revocation_id, "node-2")
        coord.acknowledge_revocation(rev_event.revocation_id, "node-3")
        coord.acknowledge_revocation(rev_event.revocation_id, "node-4")

        metrics = coord.compute_propagation_metrics(rev_event.revocation_id)
        self.assertEqual(metrics["acknowledged_nodes"], 5)
        self.assertEqual(metrics["coverage_pct"], 100.0)
        self.assertGreaterEqual(metrics["max_latency_ms"], 0.0)


if __name__ == "__main__":
    unittest.main()
