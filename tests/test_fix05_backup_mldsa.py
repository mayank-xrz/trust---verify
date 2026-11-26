"""FIX-05 regression tests: backup manifests are signed with ML-DSA-65."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pqcrypto.sign import ml_dsa_65

from src.crypto._pqcrypto_compat import sig_keygen, sig_verify
from src.identity_keys.backup import BACKUP_MAGIC
from src.identity_keys.crypto import b64d, canonical_json_bytes
from src.identity_keys.errors import IntegrityError as DomainIntegrityError
from tests.test_part4_backup import bkp_env  # noqa: F401  (pytest fixture)


def _envelope(path: Path) -> dict:
    raw = path.read_bytes()
    env_len = int.from_bytes(raw[len(BACKUP_MAGIC): len(BACKUP_MAGIC) + 4], "big")
    start = len(BACKUP_MAGIC) + 4
    return json.loads(raw[start: start + env_len].decode("utf-8"))


def _create(bkp_env, path: Path, priv: bytes) -> dict:  # noqa: F811
    bkp_env["bkp_svc"].create_backup(
        bkp_env["admin_ctx"],
        path,
        signing_privkey=priv,
        passphrase=bkp_env["passphrase"],
    )
    return _envelope(path)


def _rewrite(path: Path, envelope: dict) -> None:
    raw = path.read_bytes()
    env_len = int.from_bytes(raw[len(BACKUP_MAGIC): len(BACKUP_MAGIC) + 4], "big")
    start = len(BACKUP_MAGIC) + 4
    ciphertext = raw[start + env_len:]
    env_bytes = canonical_json_bytes(envelope)
    path.write_bytes(BACKUP_MAGIC + len(env_bytes).to_bytes(4, "big") + env_bytes + ciphertext)


def test_backup_manifest_is_mldsa_signed(bkp_env, tmp_path: Path) -> None:  # noqa: F811
    public_key, private_key = sig_keygen(ml_dsa_65)
    path = tmp_path / "mldsa.tbvbkp"
    envelope = _create(bkp_env, path, private_key)

    manifest = envelope["manifest"]
    assert manifest["signature_algorithm"] == "ML-DSA-65"
    assert sig_verify(
        ml_dsa_65,
        public_key,
        canonical_json_bytes(manifest),
        b64d(envelope["manifest_sig_b64"]),
    )


def test_restore_accepts_mldsa_and_rejects_wrong_key(bkp_env, tmp_path: Path) -> None:  # noqa: F811
    public_key, private_key = sig_keygen(ml_dsa_65)
    wrong_public, _ = sig_keygen(ml_dsa_65)
    path = tmp_path / "restore.tbvbkp"
    _create(bkp_env, path, private_key)

    restored = bkp_env["bkp_svc"].restore_backup(
        bkp_env["admin_ctx"],
        path,
        pinned_pubkey=public_key,
        passphrase=bkp_env["passphrase"],
    )
    assert restored["restored"] is True

    with pytest.raises(DomainIntegrityError) as excinfo:
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            path,
            pinned_pubkey=wrong_public,
            passphrase=bkp_env["passphrase"],
        )
    assert excinfo.value.reason_code == "STEP2_BAD_SIGNATURE"


def test_tampered_manifest_fails_mldsa_verification(bkp_env, tmp_path: Path) -> None:  # noqa: F811
    public_key, private_key = sig_keygen(ml_dsa_65)
    path = tmp_path / "tampered.tbvbkp"
    envelope = _create(bkp_env, path, private_key)
    manifest = envelope["manifest"]
    manifest["node_id"] = "evil-node"
    _rewrite(path, envelope)

    with pytest.raises(DomainIntegrityError) as excinfo:
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            path,
            pinned_pubkey=public_key,
            passphrase=bkp_env["passphrase"],
        )
    assert excinfo.value.reason_code == "STEP2_BAD_SIGNATURE"


def test_restore_rejects_missing_signature_with_intact_payload(bkp_env, tmp_path: Path) -> None:  # noqa: F811
    public_key, private_key = sig_keygen(ml_dsa_65)
    path = tmp_path / "unsigned.tbvbkp"
    envelope = _create(bkp_env, path, private_key)
    del envelope["manifest_sig_b64"]
    _rewrite(path, envelope)
    with pytest.raises(DomainIntegrityError) as excinfo:
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"], path, pinned_pubkey=public_key, passphrase=bkp_env["passphrase"]
        )
    assert excinfo.value.reason_code == "STEP2_MISSING_SIGNATURE"


def test_restore_rejects_checksum_updated_without_valid_signature(bkp_env, tmp_path: Path) -> None:  # noqa: F811
    public_key, private_key = sig_keygen(ml_dsa_65)
    path = tmp_path / "invalid-checkpoint.tbvbkp"
    envelope = _create(bkp_env, path, private_key)
    raw = path.read_bytes()
    start = len(BACKUP_MAGIC) + 4
    size = int.from_bytes(raw[len(BACKUP_MAGIC):start], "big")
    payload = bytearray(raw[start + size:])
    payload[-1] ^= 1
    envelope["manifest"]["ciphertext_sha256"] = hashlib.sha256(payload).hexdigest()
    header = canonical_json_bytes(envelope)
    path.write_bytes(BACKUP_MAGIC + len(header).to_bytes(4, "big") + header + payload)
    with pytest.raises(DomainIntegrityError) as excinfo:
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"], path, pinned_pubkey=public_key, passphrase=bkp_env["passphrase"]
        )
    assert excinfo.value.reason_code == "STEP2_BAD_SIGNATURE"
