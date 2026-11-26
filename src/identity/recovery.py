"""Crash Recovery with Write-Ahead Log (WAL) & Device Re-enrollment."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional, Tuple


class WALManager:
    """Append-only Write-Ahead Log for atomic state updates and crash recovery."""

    def __init__(self, wal_path: str):
        self.wal_path = wal_path
        self._ensure_file()

    def _ensure_file(self) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.wal_path)), exist_ok=True)
        fd = os.open(self.wal_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            if os.fstat(f.fileno()).st_size == 0:
                f.write("# TBV WAL V1\n")

    def append_entry(self, op_type: str, payload: Dict[str, Any]) -> int:
        """Appends an fsynced transaction entry to the WAL."""
        entry = {
            "op": op_type,
            "ts_ns": time.time_ns(),
            "payload": payload,
        }
        line = json.dumps(entry, sort_keys=True)
        checksum = hashlib.sha256(line.encode("utf-8")).hexdigest()
        full_line = f"{checksum} {line}\n"

        with open(self.wal_path, "a", encoding="utf-8") as f:
            f.write(full_line)
            f.flush()
            os.fsync(f.fileno())

        return entry["ts_ns"]

    def read_valid_entries(self) -> List[Dict[str, Any]]:
        """Reads and validates entries from the WAL, ignoring corrupted trailing records (e.g., from mid-write crash)."""
        valid_entries = []
        if not os.path.exists(self.wal_path):
            return valid_entries

        with open(self.wal_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(" ", 1)
                if len(parts) != 2:
                    continue
                checksum, json_str = parts
                expected = hashlib.sha256(json_str.encode("utf-8")).hexdigest()
                if checksum != expected:
                    # Corruption detected (e.g., torn write during crash)
                    break
                try:
                    obj = json.loads(json_str)
                    valid_entries.append(obj)
                except json.JSONDecodeError:
                    break

        return valid_entries


class DeviceReEnrollment:
    """Secure device re-enrollment flow using challenge-response and attestation."""

    def __init__(self, cluster_secret: bytes):
        self.cluster_secret = cluster_secret
        self.pending_challenges: Dict[str, Tuple[bytes, float]] = {}

    def issue_challenge(self, node_id: str, ttl_seconds: float = 60.0) -> bytes:
        """Issues an ephemeral random challenge nonce for re-enrolling node."""
        nonce = secrets.token_bytes(32)
        self.pending_challenges[node_id] = (nonce, time.time() + ttl_seconds)
        return nonce

    def verify_re_enrollment(
        self,
        node_id: str,
        challenge_response: bytes,
        new_public_key: bytes,
        proof_signature: bytes,
        *,
        verifier: Optional[Any] = None,
    ) -> bool:
        """Verifies proof of possession and authorization for device replacement."""
        pending = self.pending_challenges.get(node_id)
        if not pending:
            return False

        nonce, exp = pending
        del self.pending_challenges[node_id]
        if time.time() > exp:
            return False

        if not new_public_key or not proof_signature:
            return False

        # Expected response combines cluster secret + nonce + new public key
        expected_response = hashlib.sha3_256(self.cluster_secret + nonce + new_public_key).digest()
        if not hmac.compare_digest(challenge_response, expected_response):
            return False

        # Verify proof-of-possession signature over domain-separated binding using new_public_key
        signed_msg = b"track4/v1/reenroll\x00" + node_id.encode("utf-8") + b"\x00" + nonce + new_public_key
        if verifier is not None:
            return bool(verifier(new_public_key, signed_msg, proof_signature))

        try:
            from pqcrypto.sign import ml_dsa_65

            from src.crypto._pqcrypto_compat import sig_verify

            return bool(sig_verify(ml_dsa_65, new_public_key, signed_msg, proof_signature))
        except Exception:
            return False
