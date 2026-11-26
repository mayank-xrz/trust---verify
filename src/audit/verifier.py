"""Tamper-Evident Audit Log Verifier and Operator CLI Validator.

Detects:
- Insertions, deletions, and modifications of log entries.
- Broken hash chains and sequence gaps.
- ML-DSA signature forgery on checkpoints.
- Newline and JSON injection attempts.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import json
import os
import sys
import tempfile
from typing import Any, Dict, List, Optional

from pqcrypto.sign import ml_dsa_65

from .logger import GENESIS_HASH, AuditLogger


def _sig_keygen():
    return ml_dsa_65.keygen()


def _sig_sign(secret_key: bytes, message: bytes) -> bytes:
    return ml_dsa_65.sign(secret_key, message)


def _sig_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    try:
        result = ml_dsa_65.verify(public_key, message, signature)
    except Exception:
        return False
    return result is not False


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
    """Validates full cryptographic integrity of the audit log, including out-of-band anchors."""

    def __init__(
        self,
        verifier_sig: Optional[Any] = None,
        public_key: Optional[bytes] = None,
        require_signatures: bool = False,
        require_signed_checkpoint: bool = False,
    ):
        self.verifier_sig = verifier_sig
        self.public_key = public_key
        self.require_signatures = require_signatures
        self.require_signed_checkpoint = require_signed_checkpoint or require_signatures

    @staticmethod
    def save_anchor(log_file_path: str, anchor_path: str) -> Dict[str, Any]:
        """Persist out-of-band genesis and tip hashes so whole-log replacement is detectable."""
        entries: List[Dict[str, Any]] = []
        with open(log_file_path, "r", encoding="utf-8") as f:
            for raw in f:
                s = raw.strip()
                if s and not s.startswith("#"):
                    entries.append(json.loads(s))
        anchor = {
            "total_records": len(entries),
            "genesis_hash": entries[0]["entry_hash"] if entries else GENESIS_HASH,
            "last_seq": entries[-1]["sequence"] if entries else -1,
            "last_hash": entries[-1]["entry_hash"] if entries else GENESIS_HASH,
        }
        with open(anchor_path, "w", encoding="utf-8") as f:
            json.dump(anchor, f, sort_keys=True)
        return anchor

    def verify_file(
        self,
        log_file_path: str,
        *,
        anchor: Optional[Dict[str, Any]] = None,
        anchor_path: Optional[str] = None,
    ) -> VerificationResult:
        """Parses log file from line 1 and verifies hash chain, signatures, and optional out-of-band anchor."""
        if anchor is None and anchor_path is not None:
            if not os.path.exists(anchor_path):
                return VerificationResult(
                    is_valid=False,
                    total_records=0,
                    verified_checkpoints=0,
                    first_error=f"Anchor file not found: {anchor_path}",
                )
            with open(anchor_path, "r", encoding="utf-8") as af:
                anchor = json.load(af)
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
        genesis_entry_hash: Optional[str] = None
        seen_hashes: Dict[int, str] = {}
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

                # Check signature if present.  Library callers that only want a
                # chain check may omit a key; the operator CLI sets
                # require_signatures=True so a signed checkpoint without a
                # pinned key is rejected fail-closed instead of silently
                # skipped (which would make a forged checkpoint look valid).
                sig_b64 = entry.get("signature")
                if sig_b64 and self.public_key is None:
                    if not self.require_signatures:
                        sig_b64 = None
                    else:
                        err = (
                            f"Line {line_no} (Seq {seq}): checkpoint signature present "
                            "but no public key supplied for verification."
                        )
                        return VerificationResult(
                            is_valid=False,
                            total_records=total_records,
                            verified_checkpoints=verified_checkpoints,
                            first_error=err,
                            corrupted_sequence=seq,
                            details=[err],
                        )
                if sig_b64:
                    try:
                        sig_bytes = base64.b64decode(sig_b64, validate=True)
                    except Exception:
                        err = f"Line {line_no} (Seq {seq}): malformed checkpoint signature encoding."
                        return VerificationResult(
                            is_valid=False,
                            total_records=total_records,
                            verified_checkpoints=verified_checkpoints,
                            first_error=err,
                            corrupted_sequence=seq,
                            details=[err],
                        )
                    if self.verifier_sig is not None:
                        sig_valid = self.verifier_sig.verify(
                            claimed_entry_hash.encode("ascii"), sig_bytes, self.public_key
                        )
                    else:
                        sig_valid = _sig_verify(
                            self.public_key,
                            claimed_entry_hash.encode("ascii"),
                            sig_bytes,
                        )
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

                if genesis_entry_hash is None:
                    genesis_entry_hash = claimed_entry_hash
                seen_hashes[seq] = claimed_entry_hash
                expected_prev_hash = claimed_entry_hash
                expected_seq += 1
                total_records += 1

        if (self.require_signed_checkpoint or (self.verifier_sig and self.public_key)) and total_records > 0 and verified_checkpoints == 0:
            err = "No signed checkpoint found; whole-file replacement cannot be ruled out."
            return VerificationResult(
                is_valid=False,
                total_records=total_records,
                verified_checkpoints=verified_checkpoints,
                first_error=err,
                corrupted_sequence=0,
                details=[err],
            )

        if anchor is not None:
            exp_total = int(anchor.get("total_records", 0))
            if total_records < exp_total:
                err = f"Whole-log truncation/replacement detected: expected >= {exp_total} records, got {total_records}."
                return VerificationResult(
                    is_valid=False,
                    total_records=total_records,
                    verified_checkpoints=verified_checkpoints,
                    first_error=err,
                    corrupted_sequence=0,
                    details=[err],
                )
            if exp_total > 0:
                if genesis_entry_hash != anchor.get("genesis_hash"):
                    err = "Whole-log replacement detected: genesis hash does not match out-of-band anchor."
                    return VerificationResult(
                        is_valid=False,
                        total_records=total_records,
                        verified_checkpoints=verified_checkpoints,
                        first_error=err,
                        corrupted_sequence=0,
                        details=[err],
                    )
                last_seq = int(anchor.get("last_seq", -1))
                if last_seq >= 0 and seen_hashes.get(last_seq) != anchor.get("last_hash"):
                    err = f"Whole-log replacement detected: anchored hash at seq {last_seq} mismatch."
                    return VerificationResult(
                        is_valid=False,
                        total_records=total_records,
                        verified_checkpoints=verified_checkpoints,
                        first_error=err,
                        corrupted_sequence=last_seq,
                        details=[err],
                    )

        details.append(f"Successfully verified {total_records} chained records with {verified_checkpoints} checkpoints.")
        return VerificationResult(
            is_valid=True,
            total_records=total_records,
            verified_checkpoints=verified_checkpoints,
            first_error=None,
            corrupted_sequence=None,
            details=details,
        )


class _MLDSASigner:
    def __init__(self, secret_key: bytes) -> None:
        self._secret_key = secret_key

    def sign(self, data: bytes) -> bytes:
        return _sig_sign(self._secret_key, data)


def _load_public_key(args: argparse.Namespace) -> Optional[bytes]:
    if args.public_key:
        return base64.b64decode(args.public_key, validate=True)
    if args.public_key_file:
        raw = open(args.public_key_file, "rb").read().strip()
        try:
            return base64.b64decode(raw, validate=True)
        except Exception:
            return raw
    return None


def run_self_test() -> int:
    """Create a signed log, verify it, and assert a forged checkpoint is rejected."""
    public_key, secret_key = _sig_keygen()
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, "self-test.log")
        logger = AuditLogger("self-test", path, signer=_MLDSASigner(secret_key), checkpoint_interval=1)
        for i in range(3):
            logger.log_event("svc", "op", f"s{i}", "res")
        clean = AuditLogVerifier(public_key=public_key, require_signatures=True).verify_file(path)
        if not clean.is_valid or clean.verified_checkpoints != 3:
            print(f"❌ SELF-TEST FAILED: {clean.first_error}")
            return 1

        lines = open(path, "r", encoding="utf-8").read().splitlines()
        forged = False
        for idx, line in enumerate(lines):
            if not line.strip() or line.startswith("#"):
                continue
            rec = json.loads(line)
            if rec.get("signature"):
                rec["signature"] = base64.b64encode(b"\x00" * 64).decode("ascii")
                lines[idx] = json.dumps(rec, separators=(",", ":"))
                forged = True
                break
        if not forged:
            print("❌ SELF-TEST FAILED: no signed checkpoint produced")
            return 1
        open(path, "w", encoding="utf-8").write("\n".join(lines) + "\n")
        tampered = AuditLogVerifier(public_key=public_key, require_signatures=True).verify_file(path)
        if tampered.is_valid:
            print("❌ SELF-TEST FAILED: forged checkpoint accepted")
            return 1

    print(json.dumps({
        "self_test": "PASS",
        "clean_records": clean.total_records,
        "verified_checkpoints": clean.verified_checkpoints,
        "forged_checkpoint_rejected": True,
    }, indent=2))
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m src.audit.verifier",
        description="Verify an audit log hash chain and ML-DSA-65 checkpoint signatures.",
    )
    parser.add_argument("log_file", nargs="?", default=None)
    parser.add_argument("--chain", action="store_true", help="verify the hash chain (default)")
    parser.add_argument("--checkpoints", action="store_true", help="verify checkpoint signatures")
    parser.add_argument("--public-key", default=None, help="base64 ML-DSA-65 public key")
    parser.add_argument("--public-key-file", default=None, help="file containing the public key")
    parser.add_argument("--self-test", action="store_true", help="run a signed-log self-test")
    args = parser.parse_args(argv)

    if args.log_file is None:
        # No log path: `--chain --checkpoints` is the documented operator
        # contract probe, so run the built-in signed-log self-test instead of
        # silently succeeding on nothing.
        if args.chain or args.checkpoints or args.self_test:
            return run_self_test()
        parser.print_usage()
        return 1

    try:
        public_key = _load_public_key(args)
    except Exception as exc:
        print(f"❌ Invalid public key: {exc}")
        return 2

    verifier = AuditLogVerifier(public_key=public_key, require_signatures=True)
    result = verifier.verify_file(args.log_file)
    if result.is_valid:
        print(
            f"✅ LOG INTEGRITY VERIFIED: {result.total_records} records, "
            f"{result.verified_checkpoints} checkpoints."
        )
        return 0
    print(f"❌ TAMPERING DETECTED: {result.first_error}")
    return 2


if __name__ == "__main__":
    sys.exit(main())
