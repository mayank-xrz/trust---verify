"""Integration tests for the upgraded Track 4 Interactive Workbench GUI & Sandbox API."""

from __future__ import annotations

import base64
import json
from pathlib import Path

from fastapi.testclient import TestClient

from demo.node.server import create_app
from src.audit.logger import AuditLogger


def _client(tmp_path: Path) -> TestClient:
    app = create_app(node_id="node-a", data_dir=str(tmp_path), grace_period_seconds=1.0)
    return TestClient(app)


def test_dashboard_html_and_state(tmp_path: Path) -> None:
    client = _client(tmp_path)
    html_res = client.get("/")
    assert html_res.status_code == 200
    assert "Trust, But Verify" in html_res.text
    assert "Test Files &amp; Pytest Runner" in html_res.text
    assert "PQC Messaging &amp; File Guard" in html_res.text
    assert "Keys, Devices &amp; Authority" in html_res.text
    assert "Detector &amp; Practice Logs" in html_res.text

    state = client.get("/api/sandbox/state").json()
    assert state["checklist_total"] == 12
    assert "pqcrypto" in state["crypto"]["provider"]
    assert state["policy_state"]["max_devices_per_user"] == 1
    assert state["policy_state"]["max_file_size_mb"] == 20.0


def test_pqc_v1_and_v2_paranoid_transfer(tmp_path: Path) -> None:
    client = _client(tmp_path)
    r1 = client.post(
        "/api/sandbox/pqc-transfer",
        json={"sender": "alice", "recipient": "bob", "message": "hello v1", "profile": "v1"},
    )
    assert r1.status_code == 200
    assert r1.json()["ok"] is True
    assert r1.json()["decrypted_payload"]["message"] == "hello v1"

    r2 = client.post(
        "/api/sandbox/pqc-transfer",
        json={"sender": "alice", "recipient": "charlie", "message": "hello paranoid", "profile": "v2-paranoid"},
    )
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["ok"] is True
    assert d2["profile"] == "track4/v2-paranoid"
    assert "HQC-256" in d2["kem_algorithm"]
    assert "SLH-DSA" in d2["sig_algorithm"]
    assert d2["decrypted_payload"]["message"] == "hello paranoid"


def test_file_share_policy_guard(tmp_path: Path) -> None:
    client = _client(tmp_path)

    ok_png = client.post("/api/sandbox/file-share/validate", json={"preset": "valid_png"}).json()
    assert ok_png["allowed"] is True
    assert ok_png["encrypted_roundtrip_verified"] is True

    spoofed = client.post("/api/sandbox/file-share/validate", json={"preset": "spoofed_exe"}).json()
    assert spoofed["allowed"] is False
    assert spoofed["blocked"] is True
    assert spoofed["reason"] == "magic_bytes_mismatch"

    script = client.post("/api/sandbox/file-share/validate", json={"preset": "disallowed_sh"}).json()
    assert script["blocked"] is True
    assert script["error_type"] == "MediaFormatError"

    oversized = client.post("/api/sandbox/file-share/validate", json={"preset": "oversized_21mb"}).json()
    assert oversized["blocked"] is True
    assert oversized["error_type"] == "FileSizeLimitError"


def test_device_timezone_and_authority_rollback(tmp_path: Path) -> None:
    client = _client(tmp_path)

    r_dev2 = client.post(
        "/api/sandbox/policy/device-timezone",
        json={
            "mode": "second_device",
            "user_id": "alice",
            "device_id": "dev-alice-rogue-2",
            "timezone": "Asia/Kolkata",
        },
    ).json()
    assert r_dev2["blocked"] is True
    assert r_dev2["error_type"] == "DeviceLimitExceededError"

    r_tz = client.post(
        "/api/sandbox/policy/device-timezone",
        json={
            "mode": "timezone_check",
            "user_id": "alice",
            "device_id": "dev-alice-laptop-01",
            "timezone": "America/New_York",
        },
    ).json()
    assert r_tz["blocked"] is True
    assert r_tz["error_type"] == "TimezoneMismatchError"

    r_susp = client.post(
        "/api/sandbox/authority/console-action",
        json={"mode": "suspicious", "user_id": "alice", "role": "admin", "action": "DISABLE_AUDIT"},
    ).json()
    assert r_susp["blocked"] is True
    assert r_susp["reverted"] is True
    assert r_susp["console_state"]["audit_enabled"] is True

    # Reset cleanly and confirm routine update works for a non-threatened admin
    r_reset = client.post(
        "/api/sandbox/authority/console-action",
        json={"mode": "reset"},
    ).json()
    assert r_reset["ok"] is True

    r_grant = client.post(
        "/api/sandbox/authority/console-action",
        json={"mode": "grant", "user_id": "bob", "role": "admin"},
    ).json()
    assert r_grant["allowed"] is True

    r_routine = client.post(
        "/api/sandbox/authority/console-action",
        json={"mode": "routine", "user_id": "bob", "role": "admin"},
    ).json()
    assert r_routine["allowed"] is True


def test_toolkit_adapter_and_practice_triage_routes(tmp_path: Path) -> None:
    client = _client(tmp_path)

    adp = client.post("/api/sandbox/toolkit/adapter-run", json={"mode": "full_suite"}).json()
    assert adp["ok"] is True
    assert adp["mlkem_hmac_verified"] is True
    assert len(adp["steps"]) == 7

    prac = client.post("/api/sandbox/detector/practice-events", json={"use_sample": True}).json()
    assert prac["ok"] is True
    assert prac["total_events"] >= 15
    if prac["label_matches"] != "no local labels.csv":
        assert prac["label_matches"] == "22/22"


def test_audit_file_verify_endpoint(tmp_path: Path) -> None:
    client = _client(tmp_path)
    log_path = tmp_path / "sample_audit.log"
    logger = AuditLogger("node-a", str(log_path))
    logger.log_event("node-a", "TEST_EVENT", "alice", "/brief", "SUCCESS")
    valid_text = log_path.read_text(encoding="utf-8")

    ok_res = client.post(
        "/api/sandbox/audit/verify-file",
        json={"filename": "sample_audit.log", "content": valid_text},
    ).json()
    assert ok_res["is_valid"] is True
    assert ok_res["total_records"] == 1

    tampered_text = valid_text.replace("SUCCESS", "TAMPERD", 1)
    bad_res = client.post(
        "/api/sandbox/audit/verify-file",
        json={"filename": "sample_audit.log", "content": tampered_text},
    ).json()
    assert bad_res["is_valid"] is False


def test_universal_test_bundle_and_pytest_runner(tmp_path: Path) -> None:
    client = _client(tmp_path)

    listing = client.get("/api/sandbox/tests/list").json()
    assert listing["ok"] is True
    names = {item["name"] for item in listing["test_files"]}
    assert "test_crypto_system.py" in names

    run_res = client.post(
        "/api/sandbox/tests/run",
        json={"test_files": ["test_file_and_device_policy.py"], "run_pytest": True, "include_toolkit_validator": listing["toolkit_available"]},
    ).json()
    assert run_res["ok"] is True
    assert run_res["pytest"]["passed"] is True
    assert run_res["pytest"]["counts"]["passed"] > 0

    repo_root = Path(__file__).resolve().parents[1]
    suite_bytes = (repo_root / "tests" / "test_log_injection.py").read_bytes()
    log_path = tmp_path / "uploaded_chain.log"
    logger = AuditLogger("node-a", str(log_path))
    logger.log_event("node-a", "UPLOAD_CHECK", "bob", "/file", "SUCCESS")

    csv_text = "\n".join([
        "event_id,event_time_utc,received_time_utc,source_clock_offset_ms,actor,source_service,target_service,action,role_before,role_after,outcome,approval_id,session_id,correlation_id",
        "evt-001,2026-01-15T09:00:00.000Z,2026-01-15T09:00:00.200Z,0,user-blair,admin-console,identity,role_change,viewer,operator,success,,sess-blair,flow-1",
        "evt-002,2026-01-15T09:01:00.000Z,2026-01-15T09:01:00.200Z,0,svc-w,reports,billing,read,reader,reader,deny,,sess-w,flow-2",
        "evt-003,2026-01-15T09:01:02.000Z,2026-01-15T09:01:02.200Z,0,svc-w,billing,archive,read,reader,reader,deny,,sess-w,flow-2",
    ])
    lbl_text = "\n".join([
        "event_id,label,reason",
        "evt-001,unexpected_role_change,No approval",
        "evt-002,lateral_movement_candidate,Hop 1",
        "evt-003,lateral_movement_candidate,Hop 2",
    ])

    bundle_files = [
        {
            "filename": "test_log_injection.py",
            "content_b64": base64.b64encode(suite_bytes).decode("ascii"),
            "mime_type": "text/x-python",
        },
        {
            "filename": "uploaded_chain.log",
            "content_b64": base64.b64encode(log_path.read_bytes()).decode("ascii"),
            "mime_type": "text/plain",
        },
        {
            "filename": "events.csv",
            "content_b64": base64.b64encode(csv_text.encode("utf-8")).decode("ascii"),
            "mime_type": "text/csv",
        },
        {
            "filename": "approvals.json",
            "content_b64": base64.b64encode(json.dumps({"changes": []}).encode("utf-8")).decode("ascii"),
            "mime_type": "application/json",
        },
        {
            "filename": "labels.csv",
            "content_b64": base64.b64encode(lbl_text.encode("utf-8")).decode("ascii"),
            "mime_type": "text/csv",
        },
        {
            "filename": "fake.png",
            "content_b64": base64.b64encode(b"MZ\x90\x00" + b"\x00" * 32).decode("ascii"),
            "mime_type": "image/png",
        },
    ]

    bundle_res = client.post("/api/sandbox/files/check-bundle", json={"files": bundle_files}).json()
    assert bundle_res["ok"] is True
    assert bundle_res["summary"]["total_files"] == 6
    assert bundle_res["summary"]["passed"] == 5
    assert bundle_res["summary"]["blocked_or_failed"] == 1
    assert bundle_res["practice_triage"]["label_matches"] == "3/3"
