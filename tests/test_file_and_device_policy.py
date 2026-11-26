"""Tests for 20 MB file-sharing limit, default media formats, and 1-device-per-user policy."""

from __future__ import annotations
from pathlib import Path

import pytest

from src.audit.verifier import AuditLogVerifier
from src.crypto import (
    DEFAULT_MEDIA_FORMATS,
    DeviceLimitExceededError,
    DevicePolicyError,
    FilePolicyError,
    FileSizeLimitError,
    MAX_DEVICES_PER_USER,
    MAX_FILE_SIZE_BYTES,
    MediaFormatError,
    SecureCryptoSystem,
    SingleDeviceRegistry,
    TimezoneMismatchError,
    validate_shared_file,
)
from src.crypto.primitives import CryptoError, signing_keypair
from src.crypto.session import TrustRegistry
from tests.conftest import read_audit_events


def _png_bytes(payload_size: int = 64) -> bytes:
    return b"\x89PNG\r\n\x1a\n" + (b"\x00" * max(0, payload_size - 8))


def _mp4_bytes(payload_size: int = 64) -> bytes:
    return b"\x00\x00\x00\x18ftypmp42" + (b"\x00" * max(0, payload_size - 12))


def test_file_size_limit_20mb_enforced(tmp_path: Path) -> None:
    assert MAX_FILE_SIZE_BYTES == 20 * 1024 * 1024

    # Exact 20 MB valid PNG succeeds
    ok = validate_shared_file("photo.png", _png_bytes(MAX_FILE_SIZE_BYTES))
    assert ok["size"] == MAX_FILE_SIZE_BYTES
    assert ok["mime_type"] == "image/png"

    # 20 MB + 1 byte fails closed
    with pytest.raises(FileSizeLimitError):
        validate_shared_file("too_big.png", _png_bytes(MAX_FILE_SIZE_BYTES + 1))

    # Empty file rejected
    with pytest.raises(FilePolicyError):
        validate_shared_file("empty.png", b"")


def test_default_media_formats_and_magic_bytes_enforced() -> None:
    # Standard media formats accepted with matching magic bytes
    samples = {
        "img.jpg": b"\xff\xd8\xff\xe0" + b"A" * 20,
        "anim.gif": b"GIF89a" + b"A" * 20,
        "clip.mp4": _mp4_bytes(32),
        "track.mp3": b"ID3" + b"\x00" * 20,
        "voice.wav": b"RIFF\x00\x00\x00\x00WAVEfmt ",
        "doc.pdf": b"%PDF-1.7\n...",
        "notes.txt": b"hello plaintext media",
        "meta.json": b'{"ok": true}',
    }
    for name, content in samples.items():
        res = validate_shared_file(name, content)
        assert res["extension"] in DEFAULT_MEDIA_FORMATS

    # Executable / script / SVG formats rejected
    for bad_name, bad_data in (
        ("payload.exe", b"MZ\x90\x00"),
        ("run.sh", b"#!/bin/sh\nrm -rf /"),
        ("xss.svg", b"<svg onload=alert(1)>"),
        ("evil.js", b"console.log(1)"),
        ("../../escape.png", _png_bytes(32)),
    ):
        with pytest.raises(MediaFormatError):
            validate_shared_file(bad_name, bad_data)

    # Spoofed extension (EXE magic disguised as .png) rejected
    with pytest.raises(MediaFormatError) as exc_info:
        validate_shared_file("fake.png", b"MZ\x90\x00" + b"\x00" * 32)
    assert exc_info.value.reason == "magic_bytes_mismatch"


def test_single_device_per_user_enforced(tmp_path: Path) -> None:
    assert MAX_DEVICES_PER_USER == 1
    reg = SingleDeviceRegistry(tmp_path / "devices.db")
    reg.register_device("alice", "phone-1")
    assert reg.active_device("alice") == "phone-1"

    # Second simultaneous device for alice rejected
    with pytest.raises(DeviceLimitExceededError):
        reg.register_device("alice", "laptop-2")

    # Different user bob can still register his 1 device
    reg.register_device("bob", "desktop-1")
    assert reg.active_device("bob") == "desktop-1"

    # Replacing phone-1 -> phone-2 atomically revokes phone-1 and leaves 1 active device
    reg.replace_device("alice", "phone-1", "phone-2")
    assert reg.active_device("alice") == "phone-2"
    with pytest.raises(DevicePolicyError):
        reg.register_device("alice", "phone-1")  # revoked device cannot re-register

    # TrustRegistry also enforces 1 active device per user
    treg = TrustRegistry()
    pk1, _ = signing_keypair()
    pk2, _ = signing_keypair()
    treg.enroll("alice", "phone-1", pk1)
    with pytest.raises(CryptoError):
        treg.enroll("alice", "laptop-2", pk2)
    treg.revoke("alice", "phone-1")
    treg.enroll("alice", "laptop-2", pk2)


def test_secure_crypto_system_file_share_and_device_policy_end_to_end(tmp_path: Path) -> None:
    alice = SecureCryptoSystem(identity="alice", device="dev-a1", state_dir=tmp_path / "alice")
    bob = SecureCryptoSystem(identity="bob", device="dev-b1", state_dir=tmp_path / "bob")

    hello = bob.create_hello()
    init_msg, ak = alice.initiate_session(hello, bob.signing_public_key)
    bob.accept_session(init_msg, alice.signing_public_key)

    # Share valid PNG media through encrypted chunked pipeline
    png = _png_bytes(150_000)
    chunks = alice.share_file(ak.session_id, "vacation.png", png, chunk_size=65536)
    assert len(chunks) == 3

    received = None
    for env in reversed(chunks):  # out-of-order delivery
        received = bob.receive_file_chunk(env, alice.signing_public_key)
    assert received is not None
    meta, data = received
    assert meta["filename"] == "vacation.png"
    assert meta["mime_type"] == "image/png"
    assert data == png

    # Oversized (> 20 MB) rejected & audited
    with pytest.raises(FileSizeLimitError):
        alice.share_file(ak.session_id, "huge.png", _png_bytes(MAX_FILE_SIZE_BYTES + 1))

    # Disallowed format rejected & audited
    with pytest.raises(MediaFormatError):
        alice.share_file(ak.session_id, "malware.exe", b"MZ\x90\x00" * 10)

    # Second device for alice rejected by bob
    alice_dev2 = SecureCryptoSystem(identity="alice", device="dev-a2", state_dir=tmp_path / "alice2")
    hello2 = bob.create_hello()
    with pytest.raises(DeviceLimitExceededError):
        init2, _ = alice_dev2.initiate_session(hello2, bob.signing_public_key)
        bob.accept_session(init2, alice_dev2.signing_public_key)

    events = read_audit_events(tmp_path / "bob" / "crypto_audit.log")
    assert any(
        e["action"] == "message_rejected" and e["metadata"]["reason"] == "device_limit_exceeded"
        for e in events
    )


def test_different_timezone_access_rejected_and_logs_threat(tmp_path: Path) -> None:
    alice = SecureCryptoSystem(
        identity="alice",
        device="dev-a1",
        state_dir=tmp_path / "alice",
        timezone="Asia/Kolkata",
    )
    bob = SecureCryptoSystem(
        identity="bob",
        device="dev-b1",
        state_dir=tmp_path / "bob",
        timezone="Asia/Kolkata",
    )

    hello = bob.create_hello()
    init_msg, ak = alice.initiate_session(hello, bob.signing_public_key)
    bob.accept_session(init_msg, alice.signing_public_key)

    # Same timezone access succeeds
    env1 = alice.encrypt(ak.session_id, b"same-tz-ok")
    assert bob.decrypt(env1, alice.signing_public_key, request_timezone="Asia/Kolkata") == b"same-tz-ok"

    # Access request from a different timezone -> rejected + threat log recorded
    env2 = alice.encrypt(ak.session_id, b"different-tz-attack")
    with pytest.raises(TimezoneMismatchError):
        bob.decrypt(env2, alice.signing_public_key, request_timezone="America/New_York")

    threats = bob.get_threat_logs()
    assert len(threats) == 1
    assert threats[0]["threat"] == "ANOMALOUS_TIMEZONE_ACCESS"
    assert threats[0]["last_timezone"] == "Asia/Kolkata"
    assert threats[0]["request_timezone"] == "America/New_York"
    assert threats[0]["last_device"] == "dev-a1"
    assert "differs from last login" in threats[0]["detail"]

    events = read_audit_events(tmp_path / "bob" / "crypto_audit.log")
    assert any(
        e["action"] == "message_rejected"
        and e["metadata"]["reason"] == "timezone_mismatch_threat"
        and e["metadata"]["threat"] == "ANOMALOUS_TIMEZONE_ACCESS"
        for e in events
    )
    assert AuditLogVerifier().verify_file(str(tmp_path / "bob" / "crypto_audit.log")).is_valid

    # Revoked device also cannot resume an existing session
    ticket = bob.issue_resumption_ticket(ak.session_id)
    bob.device_registry.revoke_device("alice", "dev-a1")
    nonce = b"N" * 16
    pop = bob.resumption_store.create_proof_of_possession(ak.resumption_secret, nonce, "th-rev")
    with pytest.raises(DevicePolicyError):
        bob.resume_session(
            ticket,
            presented_identity="alice",
            presented_device="dev-a1",
            fresh_nonce=nonce,
            proof_of_possession=pop,
            new_transcript_hash="th-rev",
        )


def test_track4_service_timezone_anomaly_rejection_and_threat_log(tmp_path: Path) -> None:
    import json
    import os
    import subprocess
    import sys

    root_dir = Path(__file__).resolve().parents[1]
    env = {**os.environ, "TRACK4_STATE_DIR": str(tmp_path)}

    def call(req):
        res = subprocess.run(
            [sys.executable, str(root_dir / "track4_service.py")],
            input=json.dumps(req),
            text=True,
            capture_output=True,
            env=env,
        )
        assert res.returncode == 0, res.stderr
        return json.loads(res.stdout)

    assert call({
        "op": "setup",
        "owners": {"f1": "alice"},
        "contents": {"f1": "vault-data"},
        "disabled": [],
        "key_material": "k",
    }) == {"ready": True}

    # Initial login from Asia/Kolkata succeeds
    assert call({
        "op": "read",
        "actor": "alice",
        "asset": "f1",
        "request_id": "tz-1",
        "device": "phone-1",
        "timezone": "Asia/Kolkata",
    }) == {"decision": "allow", "body": "vault-data"}

    # Query from different timezone is rejected with threat entry logged
    assert call({
        "op": "read",
        "actor": "alice",
        "asset": "f1",
        "request_id": "tz-2",
        "device": "phone-1",
        "timezone": "Europe/London",
    }) == {"decision": "deny"}

    state = json.loads((tmp_path / "track4-local" / "state.json").read_text(encoding="utf-8"))
    threat_entries = [e for e in state["audit_log"] if e.get("request_id") == "tz-2"]
    assert len(threat_entries) == 1
    assert threat_entries[0]["decision"] == "deny"
    assert threat_entries[0]["threat"]["threat"] == "ANOMALOUS_TIMEZONE_ACCESS"
    assert threat_entries[0]["threat"]["last_timezone"] == "Asia/Kolkata"
    assert threat_entries[0]["threat"]["request_timezone"] == "Europe/London"

