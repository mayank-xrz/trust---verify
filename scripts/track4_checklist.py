"""Run the repository's 12 Track 4 acceptance checks and summarize the evidence."""

from __future__ import annotations

import json
import subprocess
import sys
import time

from scripts.evaluate_detector import CHALLENGE, FIXTURE, evaluate_both
from scripts.measure_live_revocation import measure, revocation_table
from src.detector.clock_sync import ClockSyncBuffer, SkewStatus

BRIEF = "tests/integration/test_brief_scenarios.py"


def run(*args):
    result = subprocess.run([sys.executable, *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError((result.stdout + result.stderr).strip())
    return result.stdout


def test_evidence(evidence, *tests):
    run("-m", "pytest", "-qs", "--disable-warnings", *tests)
    return evidence


def revocation():
    trial, = measure(1)
    print(revocation_table(trial), flush=True)
    return (f"last confirmed DEVICE_REVOKED response {trial['last_denial_ms']:.3f} ms "
            f"after authority timestamp {trial['revoked_at_utc']}; all three live nodes "
            "accepted the replacement and unaffected credentials and still denied the old device")


def clock():
    buffer = ClockSyncBuffer()
    event = buffer.ingest({"event_id": "clock-example", "timestamp_ns": time.time_ns() - 1_000_000_000})
    order_uncertain = event.skew_status is SkewStatus.UNCERTAIN_TIMING
    if not order_uncertain:
        raise RuntimeError(f"Expected an uncertain event, got {event.skew_status.value}")
    return test_evidence(
        f"up to ±{buffer.max_skew_ms:g} ms observed timestamp gap; order_uncertain={order_uncertain}",
        "tests/test_fix10_clock_watermark.py",
    )


def detector():
    test_evidence("", "tests/test_labelled_detector.py")
    return "; ".join(
        f"synthetic {name} {mode}: F1={metrics.f1_score:.3f}, "
        f"median={metrics.median_time_to_alert_ms:.4f} ms, "
        f"false alerts/1,000 benign={metrics.false_alerts_per_1k:g}"
        for name, fixture in (("regression", FIXTURE), ("challenge", CHALLENGE))
        for mode, metrics in evaluate_both(fixture).items()
    )


def crypto(command, checks, evidence):
    result = json.loads(run("-m", "src.cli", command))
    if not all(result.get(check) for check in checks):
        raise RuntimeError(f"{command} did not report all checks: {checks}")
    return evidence


def main():
    cases = [
        ("Key rotation", lambda: test_evidence(
            "three-node cutoff checks passed; live walkthrough configured with 2-second grace",
            f"{BRIEF}::test_02_authorized_access_during_rotation",
            f"{BRIEF}::test_03_old_key_acceptance_within_grace_period",
            f"{BRIEF}::test_04_old_key_rejection_on_every_node_after_cutoff",
        )),
        ("Revocation across nodes", revocation),
        ("Crash recovery", lambda: test_evidence(
            "interrupted rotation recovered a consistent key; revoked credentials stayed revoked",
            f"{BRIEF}::test_09_recovery_from_interrupted_rotation",
            f"{BRIEF}::test_10_persistence_of_revoked_state_after_restart",
            f"{BRIEF}::test_11_availability_of_committed_protected_data_after_recovery",
        )),
        ("Backup integrity", lambda: test_evidence(
            "damaged payload, missing signature, and invalid pinned signature rejected",
            "tests/test_lifecycle_chaos.py", "tests/test_fix05_backup_mldsa.py",
            "tests/test_backup_pinned_snapshot.py",
        )),
        ("Log integrity", lambda: test_evidence(
            "user input stayed in one record and the audit chain and signed checkpoints were verified",
            "tests/test_log_injection.py", "tests/test_audit_remediation.py",
            "tests/test_fix06_cli_log_verification.py",
        )),
        ("Routine vs suspicious activity", detector),
        ("Lateral movement", lambda: test_evidence(
            "disallowed paths under valid identities flagged with rule and path evidence",
            "tests/test_fix09_lateral_velocity.py", "tests/test_forgery_and_inedge_detection.py",
        )),
        ("Clock differences", clock),
        ("Replay and recipient binding", lambda: crypto(
            "demo-replay", ("valid_accepted", "replay_rejected", "recipient_mismatch_rejected"),
            "valid message accepted; replay and recipient mismatch rejected",
        )),
        ("Forward secrecy", lambda: crypto(
            "demo-forward-secrecy", ("session_keys_match", "ephemerals_wiped", "long_term_identity_key_cannot_decrypt"),
            "completed session remained unreadable with the long-term identity key alone",
        )),
        ("Delivery under loss or reordering", lambda: crypto(
            "demo-chunked-loss", ("reordered_delivered", "incomplete_reported"),
            "reordered file delivered; missing chunk caused an incomplete-delivery report",
        )),
        ("Session resumption", lambda: crypto(
            "demo-resumption-binding", ("peer_mismatch_rejected", "legitimate_peer_resumed"),
            "same-peer resumption accepted; different identity rejected",
        )),
    ]

    results = []
    for name, check in cases:
        try:
            evidence = check()
            status = "PASS"
        except Exception as exc:
            status = "FAIL"
            evidence = " ".join(str(exc).split())
        results.append((name, status))
        print(f"[{status}] {name} - {evidence}", flush=True)
    print("\n| Track 4 objective | Result |\n| --- | --- |")
    for name, status in results:
        print(f"| {name} | {status} |")
    return int(any(status == "FAIL" for _, status in results))


if __name__ == "__main__":
    raise SystemExit(main())
