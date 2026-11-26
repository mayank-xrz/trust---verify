"""P4-12 Lifecycle Chaos Test Suite:
- Simulated mid-rotation crash and WAL recovery to a single consistent key version
- Persistence of revoked key status across crash recovery and restarts
- Continued accessibility of protected data after recovery
- Corrupted backup detection (HMAC-SHA3-512 & SHA-256 mismatch) without loading unverified key material
"""

import base64
import json
import os
import shutil
import tempfile
import time
import unittest

from src.identity.key_manager import KeyManager, KeyRecord, KeyStateEnum
from src.identity.recovery import WALManager
from src.identity.backup import BackupManager, BackupIntegrityError


def replay_wal_to_key_manager(node_id: str, wal_manager: WALManager, grace_period_seconds: float = 10.0) -> KeyManager:
    """Replays validated WAL entries onto a fresh KeyManager instance (crash recovery)."""
    km = KeyManager(node_id, grace_period_seconds=grace_period_seconds, wal_manager=wal_manager)
    valid_entries = wal_manager.read_valid_entries()
    pending_rotation = None

    for entry in valid_entries:
        op = entry.get("op")
        payload = entry.get("payload", {})

        if op == "ENROLL_KEY":
            record = KeyRecord.from_dict(payload)
            km.keys[record.key_id] = record
            km.active_key_id = record.key_id
            km.key_history.append(record.key_id)

        elif op == "ROTATE_KEY_BEGIN":
            # Uncommitted rotation intent recorded; hold until ROTATE_KEY_COMMIT
            pending_rotation = payload

        elif op == "ROTATE_KEY_COMMIT":
            if pending_rotation:
                new_rec = KeyRecord.from_dict(pending_rotation["new_key_record"])
                old_id = pending_rotation.get("old_key_id")
                if old_id and old_id in km.keys:
                    km.keys[old_id].state = KeyStateEnum.GRACE_PERIOD
                    km.keys[old_id].grace_period_cutoff = time.time() + grace_period_seconds
                km.keys[new_rec.key_id] = new_rec
                km.active_key_id = new_rec.key_id
                km.key_history.append(new_rec.key_id)
                pending_rotation = None

        elif op == "REVOKE_KEY":
            key_id = payload.get("key_id")
            reason = payload.get("reason", "")
            if key_id in km.keys:
                km.keys[key_id].state = KeyStateEnum.REVOKED
                km.keys[key_id].revocation_reason = reason
                km.keys[key_id].private_key_b64 = ""
                if km.active_key_id == key_id:
                    km.active_key_id = None

        elif op == "ENFORCE_CUTOFFS":
            for kid in payload.get("expired_key_ids", []):
                if kid in km.keys:
                    km.keys[kid].state = KeyStateEnum.EXPIRED
                    km.keys[kid].private_key_b64 = ""

    return km


class TestLifecycleChaos(unittest.TestCase):

    def test_interrupted_rotation_crash_recovery(self):
        """Simulates crash mid-rotation (partial write), verifies clean recovery to consistent version, and data access."""
        tmpdir = tempfile.mkdtemp(prefix="tbv_chaos_")
        wal_path = os.path.join(tmpdir, "chaos_wal.log")

        try:
            wal = WALManager(wal_path)
            km = KeyManager("node-alpha", grace_period_seconds=10.0, wal_manager=wal)

            # 1. Initial key enrollment (v1)
            v1_pub = b"PUBKEY_V1_MOCK_BYTES_32BYTES_OK!"
            v1_priv = b"PRIVKEY_V1_MOCK_BYTES_32BYTES_OK"
            rec_v1 = km.enroll_initial_key("ML-KEM-768", v1_pub, v1_priv)
            v1_key_id = rec_v1.key_id
            self.assertEqual(km.active_key_id, v1_key_id)

            # Protect test data with v1 key
            retrieved_key_pre = km.get_key_for_decryption(v1_key_id)
            self.assertIsNotNone(retrieved_key_pre)

            # 2. Simulate mid-rotation crash: ROTATE_KEY_BEGIN appended, but system crashes before COMMIT
            v2_pub = b"PUBKEY_V2_MOCK_BYTES_32BYTES_OK!"
            v2_priv = b"PRIVKEY_V2_MOCK_BYTES_32BYTES_OK"
            uncommitted_v2 = KeyRecord(
                key_id="key-uncommitted-v2",
                owner_node_id="node-alpha",
                algorithm="ML-KEM-768",
                public_key_b64=base64.b64encode(v2_pub).decode("ascii"),
                private_key_b64=base64.b64encode(v2_priv).decode("ascii"),
                state=KeyStateEnum.ACTIVE,
                created_at=time.time(),
                version=2,
            )
            wal.append_entry("ROTATE_KEY_BEGIN", {
                "old_key_id": v1_key_id,
                "new_key_record": uncommitted_v2.to_dict(include_private=True),
            })

            # Append corrupted / torn write simulating power cut mid-disk write
            with open(wal_path, "a", encoding="utf-8") as f:
                f.write("corrupt_chk {\"op\": \"TORN_WRITE_CORRUPTED_MID_ROTATION\n")

            # 3. Crash recovery: new node / key manager boots from WAL
            recovery_wal = WALManager(wal_path)
            recovered_km = replay_wal_to_key_manager("node-alpha", recovery_wal)

            # Uncommitted rotation was discarded; active key remains consistent v1
            self.assertEqual(recovered_km.active_key_id, v1_key_id)
            self.assertNotIn("key-uncommitted-v2", recovered_km.keys)
            self.assertEqual(recovered_km.keys[v1_key_id].state, KeyStateEnum.ACTIVE)

            # Protected data remains accessible with recovered key
            recovered_key_v1 = recovered_km.get_key_for_decryption(v1_key_id)
            self.assertIsNotNone(recovered_key_v1)
            self.assertEqual(recovered_key_v1.key_id, v1_key_id)

            # 4. Truncate corrupted tail to valid entries as part of crash recovery
            valid_entries = recovery_wal.read_valid_entries()
            with open(wal_path, "w", encoding="utf-8") as f:
                f.write("# TBV WAL V1\n")
            clean_wal = WALManager(wal_path)
            for entry in valid_entries:
                clean_wal.append_entry(entry["op"], entry["payload"])

            # 5. Now perform a complete, committed rotation to v2
            recovered_km.wal_manager = clean_wal
            new_rec, _ = recovered_km.rotate_key(v2_pub, v2_priv)
            v2_key_id = new_rec.key_id

            # Append another torn write after valid commit to test trailing corruption tolerance
            with open(wal_path, "a", encoding="utf-8") as f:
                f.write("bad_hash_tail {\"op\": \"TORN_TAIL_AFTER_COMMIT\n")

            # Recover again
            recovered_km2 = replay_wal_to_key_manager("node-alpha", WALManager(wal_path))
            self.assertEqual(recovered_km2.active_key_id, v2_key_id)
            self.assertEqual(recovered_km2.keys[v2_key_id].state, KeyStateEnum.ACTIVE)

            # 6. Revoke v1 key and verify revocation persists across recovery
            valid_entries2 = WALManager(wal_path).read_valid_entries()
            with open(wal_path, "w", encoding="utf-8") as f:
                f.write("# TBV WAL V1\n")
            clean_wal2 = WALManager(wal_path)
            for entry in valid_entries2:
                clean_wal2.append_entry(entry["op"], entry["payload"])

            recovered_km2.wal_manager = clean_wal2
            recovered_km2.revoke_key(v1_key_id, "Key retired and compromised")

            recovered_km3 = replay_wal_to_key_manager("node-alpha", WALManager(wal_path))

            # Revoked key stays revoked, decryption is denied
            self.assertEqual(recovered_km3.keys[v1_key_id].state, KeyStateEnum.REVOKED)
            self.assertIsNone(recovered_km3.get_key_for_decryption(v1_key_id))

            # Active v2 key continues to be accessible
            self.assertIsNotNone(recovered_km3.get_key_for_decryption(v2_key_id))
            self.assertEqual(recovered_km3.get_active_key().key_id, v2_key_id)

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_backup_integrity_verification(self):
        """Verify that tampering with 1 byte of a backup snapshot raises BackupIntegrityError without loading keys."""
        tmpdir = tempfile.mkdtemp(prefix="tbv_backup_")
        backup_file = os.path.join(tmpdir, "snapshot.tbv.json")
        master_key = b"BACKUP-SUPER-SECRET-MASTER-KEY-32B!"

        try:
            bm = BackupManager(master_key)
            state_to_save = {
                "node_id": "node-alpha",
                "active_key": "key-alpha-1234",
                "epoch": 42,
                "private_material": "ENC_BLOB_PQC_KEY_MATERIAL",
            }

            # 1. Create valid signed/authenticated backup
            manifest = bm.create_backup(state_to_save, backup_file)
            self.assertTrue(manifest["mac"])
            self.assertTrue(manifest["payload_sha256"])

            # 2. Restore from valid backup succeeds
            restored = bm.verify_and_restore(backup_file)
            self.assertEqual(restored["epoch"], 42)
            self.assertEqual(restored["private_material"], "ENC_BLOB_PQC_KEY_MATERIAL")

            # 3. Attacker modifies 1 byte in payload_b64
            with open(backup_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            orig_b64 = data["payload_b64"]
            # Flip last valid character
            flipped_char = "B" if orig_b64[-2] != "B" else "C"
            data["payload_b64"] = orig_b64[:-2] + flipped_char + orig_b64[-1]

            with open(backup_file, "w", encoding="utf-8") as f:
                json.dump(data, f)

            # Restore must fail due to checksum / MAC mismatch without loading unverified keys
            with self.assertRaises(BackupIntegrityError) as ctx:
                bm.verify_and_restore(backup_file)
            self.assertTrue(
                "mismatch" in str(ctx.exception).lower() or "tampering" in str(ctx.exception).lower()
            )

        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
