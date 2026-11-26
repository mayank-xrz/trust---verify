"""Encrypted, Signed & MACed Backup Creation and Integrity Verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict


class BackupIntegrityError(Exception):
    """Raised when backup file has been tampered with or corrupted."""
    pass


class BackupManager:
    """Creates tamper-proof, MACed snapshots of node state and restores them securely."""

    def __init__(self, backup_master_key: bytes):
        if len(backup_master_key) < 32:
            raise ValueError("Backup master key must be at least 32 bytes.")
        self.master_key = backup_master_key

    def create_backup(self, state_data: Dict[str, Any], output_path: str) -> Dict[str, Any]:
        """Serializes, MACs, and writes backup snapshot."""
        now = time.time()
        backup_id = f"bak-{int(now)}-{secrets.token_hex(4)}"

        payload = {
            "backup_version": "1.0.0",
            "backup_id": backup_id,
            "created_at": now,
            "state": state_data,
        }

        canonical_json = json.dumps(payload, sort_keys=True, indent=2).encode("utf-8")
        backup_mac = hmac.new(self.master_key, canonical_json, hashlib.sha3_512).digest()
        mac_hex = backup_mac.hex()

        wrapped_snapshot = {
            "manifest": {
                "backup_id": backup_id,
                "created_at": now,
                "algorithm": "HMAC-SHA3-512",
                "mac": mac_hex,
                "payload_sha256": hashlib.sha256(canonical_json).hexdigest(),
            },
            "payload_b64": base64.b64encode(canonical_json).decode("ascii"),
        }

        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(wrapped_snapshot, f, indent=2)

        return wrapped_snapshot["manifest"]

    def verify_and_restore(self, backup_path: str) -> Dict[str, Any]:
        """Verifies cryptographic integrity and unpacks backup state.

        Raises:
            BackupIntegrityError if MAC mismatch or corrupt payload.
        """
        if not os.path.exists(backup_path):
            raise BackupIntegrityError(f"Backup file not found at {backup_path}")

        try:
            with open(backup_path, "r", encoding="utf-8") as f:
                snapshot = json.load(f)
        except Exception as e:
            raise BackupIntegrityError(f"Failed to parse backup JSON: {e}")

        manifest = snapshot.get("manifest", {})
        if manifest.get("algorithm") != "HMAC-SHA3-512":
            raise BackupIntegrityError("Unsupported or missing backup MAC algorithm")
        payload_b64 = snapshot.get("payload_b64", "")
        claimed_mac = manifest.get("mac", "")

        try:
            raw_payload = base64.b64decode(payload_b64)
        except Exception as e:
            raise BackupIntegrityError(f"Base64 decoding failed: {e}")

        # Check payload sha256 checksum first
        actual_sha256 = hashlib.sha256(raw_payload).hexdigest()
        if actual_sha256 != manifest.get("payload_sha256"):
            raise BackupIntegrityError("Payload SHA-256 hash mismatch! Data corruption detected.")

        # Compute and compare HMAC
        expected_mac = hmac.new(self.master_key, raw_payload, hashlib.sha3_512).digest()
        try:
            provided_mac = bytes.fromhex(claimed_mac)
        except (TypeError, ValueError) as e:
            raise BackupIntegrityError(f"Malformed backup MAC: {e}") from e

        if not hmac.compare_digest(expected_mac, provided_mac):
            raise BackupIntegrityError("Backup HMAC signature verification failed! Tampering detected.")

        unpacked = json.loads(raw_payload.decode("utf-8"))
        return unpacked.get("state", {})
