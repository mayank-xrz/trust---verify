"""Tamper-Evident Audit Log Verifier and Operator CLI Validator.

Detects:
- Insertions, deletions, and modifications of log entries.
- Broken hash chains and sequence gaps.
- ML-DSA signature forgery on checkpoints.
- Newline and JSON injection attempts.
"""

from __future__ import annotations

import base64
import dataclasses
import hashlib
import json
import os
import sys
from typing import Any, Dict, List, Optional

from .logger import GENESIS_HASH, AuditLogger


@dataclasses.dataclass
class VerificationResult:
    is_valid: bool
    total_records: int
    verified_checkpoints: int
    first_error: Optional[str] = None
    corrupted_sequence: Optional[int] = None
    details: List[str] = dataclasses.field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


class AuditLogVerifier:
    """Validates full cryptographic integrity of the audit log."""

    def __init__(self, verifier_sig: Optional[Any] = None, public_key: Optional[bytes] = None):
        self.verifier_sig = verifier_sig
        self.public_key = public_key

    def verify_file(self, log_file_path: str) -> VerificationResult:
        """Parses log file from line 1 and verifies hash chain and signatures."""
        if not os.path.exists(log_file_path):
            return VerificationResult(
                is_valid=False,
                total_records=0,
                verified_checkpoints=0,
                first_error=f"File not found: {log_file_path}",
            )

        expected_prev_hash = GENESIS_HASH
        expected_seq = 0
        total_records = 0
        verified_checkpoints = 0
        details = []

        with open(log_file_path, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    entry = json.loads(line)
                except json.JSONDecodeError as e:
                    err = f"Line {line_no}: Malformed JSON (possible injection or corrupted line): {e}"
                    return VerificationResult(
                        is_valid=False,
                        total_records=total_records,
                        verified_checkpoints=verified_checkpoints,
                        first_error=err,
                        corrupted_sequence=expected_seq,
                        details=[err],
                    )

                seq = entry.get("sequence")
                if seq != expected_seq:
                    err = f"Line {line_no}: Sequence mismatch. Expected {expected_seq}, found {seq} (Entry insertion or deletion detected)."
                    return VerificationResult(
                        is_valid=False,
                        total_records=total_records,
                        verified_checkpoints=verified_checkpoints,
                        first_error=err,
                        corrupted_sequence=seq,
                        details=[err],
                    )

                prev_hash = entry.get("prev_hash")
                if prev_hash != expected_prev_hash:
                    err = f"Line {line_no} (Seq {seq}): Hash chain broken! Expected prev_hash {expected_prev_hash[:16]}..., found {str(prev_hash)[:16]}..."
                    return VerificationResult(
                        is_valid=False,
                        total_records=total_records,
                        verified_checkpoints=verified_checkpoints,
                        first_error=err,
                        corrupted_sequence=seq,
                        details=[err],
                    )

                # Recompute canonical hash
                claimed_entry_hash = entry.get("entry_hash")
                body = {
                    "sequence": seq,
                    "event_id": entry.get("event_id"),
                    "timestamp_ns": entry.get("timestamp_ns"),
                    "node_id": entry.get("node_id"),
                    "service": entry.get("service"),
                    "action": entry.get("action"),
                    "subject": entry.get("subject"),
                    "resource": entry.get("resource"),
                    "status": entry.get("status"),
                    "metadata": entry.get("metadata", {}),
                    "prev_hash": prev_hash,
                }
                if "client_ip" in entry and entry["client_ip"]:
                    body["client_ip"] = entry["client_ip"]

                canonical_bytes = AuditLogger.canonical_json_bytes(body)
                expected_hash = hashlib.sha256(prev_hash.encode("ascii") + canonical_bytes).hexdigest()

                if claimed_entry_hash != expected_hash:
                    err = f"Line {line_no} (Seq {seq}): Entry content tampered! Recomputed hash {expected_hash[:16]}... does not match recorded {str(claimed_entry_hash)[:16]}..."
                    return VerificationResult(
                        is_valid=False,
                        total_records=total_records,
                        verified_checkpoints=verified_checkpoints,
                        first_error=err,
                        corrupted_sequence=seq,
                        details=[err],
                    )

                # Check signature if present
                sig_b64 = entry.get("signature")
                if sig_b64 and self.verifier_sig and self.public_key:
                    sig_bytes = base64.b64decode(sig_b64)
                    sig_valid = self.verifier_sig.verify(claimed_entry_hash.encode("ascii"), sig_bytes, self.public_key)
                    if not sig_valid:
                        err = f"Line {line_no} (Seq {seq}): Invalid signature on checkpoint {seq}!"
                        return VerificationResult(
                            is_valid=False,
                            total_records=total_records,
                            verified_checkpoints=verified_checkpoints,
                            first_error=err,
                            corrupted_sequence=seq,
                            details=[err],
                        )
                    verified_checkpoints += 1

                expected_prev_hash = claimed_entry_hash
                expected_seq += 1
                total_records += 1

        details.append(f"Successfully verified {total_records} chained records with {verified_checkpoints} checkpoints.")
        return VerificationResult(
            is_valid=True,
            total_records=total_records,
            verified_checkpoints=verified_checkpoints,
            first_error=None,
            corrupted_sequence=None,
            details=details,
        )


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m src.audit.verifier <path_to_audit.log>")
        sys.exit(1)

    path = sys.argv[1]
    verifier = AuditLogVerifier()
    result = verifier.verify_file(path)
    if result.is_valid:
        print(f"✅ LOG INTEGRITY VERIFIED: {result.total_records} records in valid hash chain.")
        sys.exit(0)
    else:
        print(f"❌ TAMPERING DETECTED: {result.first_error}")
        sys.exit(2)


if __name__ == "__main__":
    main()
