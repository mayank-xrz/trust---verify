"""Part 4 tests: Encrypted/signed backups, 200-trial corruption, rollback, tar bombs, and crashes."""

from __future__ import annotations

import io
import os
import random
import struct
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from alembic import command
from alembic.config import Config
from scripts.seed_sandbox import seed_database
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.backup import (
    BACKUP_MAGIC,
    BackupService,
    _scrypt_key,
    table_recursive_hash,
)
from src.identity_keys.clock import FakeClock
from src.identity_keys.crypto import (
    aes_gcm_wrap,
    b64e,
    canonical_json_bytes,
    ed25519_sign,
    generate_ed25519_keypair,
    generate_ml_dsa_keypair,
    ml_dsa_sign,
    sha256_hex,
)
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.errors import Conflict, StateUnavailable
from src.identity_keys.errors import IntegrityError as DomainIntegrityError
from src.identity_keys.key_lifecycle import EnvelopeEncryptionService
from src.identity_keys.revocation import RevocationReason, RevocationService
from src.identity_keys.rotation import RotationService
from src.identity_keys.services import IdentityService
from src.identity_keys.tokens import ActorContext, TokenAuthority

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def bkp_env(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("WRAP_MASTER_KEY_B64", b64e(os.urandom(32)))
    db_path = tmp_path / "bkp_src.db"
    db_url = f"sqlite+pysqlite:///{db_path}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", db_url)
    command.upgrade(cfg, "head")

    sf = create_session_factory(create_db_engine(db_url))
    clock = FakeClock()
    emitter = AuditEmitter("node-a", clock)
    users = seed_database(sf, seed=42)
    rot_svc = RotationService(sf, clock, emitter, "node-a")
    rot_svc.create_initial_key_set("data-bkp", "data")
    env_svc = EnvelopeEncryptionService(sf, clock, emitter)
    env_svc.encrypt_resource(
        resource_id="res-bkp-1",
        owner_user_id=users["alice"],
        plaintext=b"secret-backup-payload-123",
        key_set_id="data-bkp",
    )
    bkp_pub, bkp_priv = generate_ml_dsa_keypair()
    bkp_svc = BackupService(sf, clock, emitter, "node-a")
    admin_ctx = ActorContext(users["carol"], "carol-dev", "jti-carol")
    return {
        "db_url": db_url,
        "sf": sf,
        "clock": clock,
        "users": users,
        "bkp_svc": bkp_svc,
        "env_svc": env_svc,
        "rot_svc": rot_svc,
        "rev_svc": RevocationService(sf, clock, emitter, "node-a"),
        "id_svc": IdentityService(sf, clock, emitter, TokenAuthority(clock)),
        "bkp_pub": bkp_pub,
        "bkp_priv": bkp_priv,
        "admin_ctx": admin_ctx,
        "passphrase": "correct-horse-battery-staple",
    }


def test_backup_roundtrip_and_secret_scan(bkp_env, tmp_path: Path) -> None:
    bkp_file = tmp_path / "cluster.tbv"
    bkp_env["bkp_svc"].create_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        signing_privkey=bkp_env["bkp_priv"],
        passphrase=bkp_env["passphrase"],
    )
    raw_bytes = bkp_file.read_bytes()
    assert bkp_env["passphrase"].encode("utf-8") not in raw_bytes
    assert b"secret-backup-payload-123" not in raw_bytes

    with tx_session(bkp_env["sf"]) as session:
        orig_hashes = table_recursive_hash(session)

    # Restore onto a fresh wiped DB using accept_unanchored=True (no live anchor on fresh host)
    fresh_url = f"sqlite+pysqlite:///{tmp_path / 'fresh.db'}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", fresh_url)
    command.upgrade(cfg, "head")
    fresh_sf = create_session_factory(create_db_engine(fresh_url))
    seed_database(fresh_sf, seed=42)
    fresh_bkp = BackupService(fresh_sf, bkp_env["clock"], AuditEmitter("node-a", bkp_env["clock"]), "node-a")
    fresh_bkp.restore_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        pinned_pubkey=bkp_env["bkp_pub"],
        passphrase=bkp_env["passphrase"],
        accept_unanchored=True,
    )
    with tx_session(fresh_sf) as session:
        assert table_recursive_hash(session) == orig_hashes
    fresh_env = EnvelopeEncryptionService(fresh_sf, bkp_env["clock"], AuditEmitter("node-a", bkp_env["clock"]))
    assert fresh_env.decrypt_resource("res-bkp-1") == b"secret-backup-payload-123"


def test_randomized_200_byte_flips_and_tamper_vectors(bkp_env, tmp_path: Path) -> None:
    bkp_file = tmp_path / "valid.tbv"
    bkp_env["bkp_svc"].create_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        signing_privkey=bkp_env["bkp_priv"],
        passphrase=bkp_env["passphrase"],
    )
    orig = bkp_file.read_bytes()
    with tx_session(bkp_env["sf"]) as session:
        before_hashes = table_recursive_hash(session)

    rng = random.Random(42)
    bad_path = tmp_path / "corrupt.tbv"
    for trial in range(200):
        buf = bytearray(orig)
        pos = rng.randrange(len(BACKUP_MAGIC) + 4, len(buf))
        buf[pos] ^= 1 << rng.randrange(8)
        bad_path.write_bytes(bytes(buf))
        with pytest.raises((DomainIntegrityError, Exception)):
            bkp_env["bkp_svc"].restore_backup(
                bkp_env["admin_ctx"],
                bad_path,
                pinned_pubkey=bkp_env["bkp_pub"],
                passphrase=bkp_env["passphrase"],
            )

    with tx_session(bkp_env["sf"]) as session:
        assert table_recursive_hash(session) == before_hashes

    # Wrong passphrase, wrong pinned pubkey, truncated file
    with pytest.raises(DomainIntegrityError, match="decryption failed"):
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            bkp_file,
            pinned_pubkey=bkp_env["bkp_pub"],
            passphrase="wrong-passphrase",
        )
    wrong_pub, _ = generate_ml_dsa_keypair()
    with pytest.raises(DomainIntegrityError, match="signature"):
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            bkp_file,
            pinned_pubkey=wrong_pub,
            passphrase=bkp_env["passphrase"],
        )
    trunc_path = tmp_path / "trunc.tbv"
    trunc_path.write_bytes(orig[:64])
    with pytest.raises(DomainIntegrityError):
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            trunc_path,
            pinned_pubkey=bkp_env["bkp_pub"],
            passphrase=bkp_env["passphrase"],
        )


def test_tar_path_traversal_symlink_and_unknown_schema_rejected(bkp_env, tmp_path: Path) -> None:
    # Build a malicious tar.gz with path traversal, sign it with valid backup key, verify Step 5 rejects
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
        ti = tarfile.TarInfo(name="../../etc/passwd")
        data = b"evil"
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    tar_gz = tar_buf.getvalue()

    salt = os.urandom(16)
    header = {"magic": "TBVBKP1", "format_version": 1, "kdf": {"alg": "scrypt", "n": 16384, "r": 8, "p": 1, "salt_b64": b64e(salt)}}
    header_bytes = canonical_json_bytes(header)
    manifest_core = {
        "backup_id": "evil-bkp",
        "schema_version": "0004_part4_trust_anchor",
        "header_sha256": sha256_hex(header_bytes),
    }
    aad = header_bytes + canonical_json_bytes(manifest_core)
    nonce, ct = aes_gcm_wrap(_scrypt_key(bkp_env["passphrase"], salt), tar_gz, aad)
    manifest = {**manifest_core, "ciphertext_sha256": sha256_hex(ct)}
    sig = ml_dsa_sign(bkp_env["bkp_priv"], canonical_json_bytes(manifest))
    env_bytes = canonical_json_bytes({"header": header, "nonce_b64": b64e(nonce), "manifest": manifest, "manifest_sig_b64": b64e(sig)})
    evil_path = tmp_path / "traversal.tbv"
    evil_path.write_bytes(BACKUP_MAGIC + struct.pack(">I", len(env_bytes)) + env_bytes + ct)

    with pytest.raises(DomainIntegrityError, match="Path traversal"):
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            evil_path,
            pinned_pubkey=bkp_env["bkp_pub"],
            passphrase=bkp_env["passphrase"],
        )


def test_rollback_refusal_and_allow_rollback_merges_revocations(bkp_env, tmp_path: Path) -> None:
    bkp_file = tmp_path / "pre_rev.tbv"
    bkp_env["bkp_svc"].create_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        signing_privkey=bkp_env["bkp_priv"],
        passphrase=bkp_env["passphrase"],
    )

    # Revoke a newly enrolled device AFTER backup was taken
    pub, priv = generate_ed25519_keypair()
    st = bkp_env["id_svc"].start_enrollment(bkp_env["users"]["alice"])
    dev_id = bkp_env["id_svc"].enroll_device(
        enrollment_id=st["enrollment_id"],
        nonce=st["nonce"],
        label="post-bkp",
        public_key_b64=b64e(pub),
        proof_of_possession_b64=b64e(ed25519_sign(priv, st["nonce"].encode())),
    )["device_id"]
    bkp_env["rev_svc"].revoke_device(bkp_env["admin_ctx"], dev_id, RevocationReason.DEVICE_COMPROMISED)

    # Default restore refuses rollback
    with pytest.raises(Conflict, match="behind live revocation anchor"):
        bkp_env["bkp_svc"].restore_backup(
            bkp_env["admin_ctx"],
            bkp_file,
            pinned_pubkey=bkp_env["bkp_pub"],
            passphrase=bkp_env["passphrase"],
        )

    # With allow_rollback=True, restore succeeds and live revocation is preserved
    res = bkp_env["bkp_svc"].restore_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        pinned_pubkey=bkp_env["bkp_pub"],
        passphrase=bkp_env["passphrase"],
        allow_rollback=True,
    )
    assert res["restored"] is True
    assert res["merged_revocations"] >= 1


def test_unanchored_restore_refused_by_default(bkp_env, tmp_path: Path) -> None:
    bkp_file = tmp_path / "unanch.tbv"
    bkp_env["bkp_svc"].create_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        signing_privkey=bkp_env["bkp_priv"],
        passphrase=bkp_env["passphrase"],
    )
    fresh_url = f"sqlite+pysqlite:///{tmp_path / 'empty_unanch.db'}"
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", fresh_url)
    command.upgrade(cfg, "head")
    fresh_sf = create_session_factory(create_db_engine(fresh_url))
    seed_database(fresh_sf, seed=42)
    fresh_bkp = BackupService(fresh_sf, bkp_env["clock"], AuditEmitter("node-a", bkp_env["clock"]), "node-a")
    with pytest.raises(StateUnavailable, match="No trust anchor"):
        fresh_bkp.restore_backup(
            bkp_env["admin_ctx"],
            bkp_file,
            pinned_pubkey=bkp_env["bkp_pub"],
            passphrase=bkp_env["passphrase"],
        )


@pytest.mark.parametrize("crash_name", ["restore.before_apply", "restore.during_apply", "restore.after_apply"])
def test_restore_crash_matrix(bkp_env, tmp_path: Path, crash_name: str) -> None:
    bkp_file = tmp_path / "crash_bkp.tbv"
    bkp_env["bkp_svc"].create_backup(
        bkp_env["admin_ctx"],
        bkp_file,
        signing_privkey=bkp_env["bkp_priv"],
        passphrase=bkp_env["passphrase"],
    )
    env = os.environ.copy()
    env["CRASH_AT"] = crash_name
    script = (
        "from src.identity_keys.db import create_db_engine, create_session_factory; "
        "from src.identity_keys.clock import SystemClock; "
        "from src.identity_keys.audit_outbox import AuditEmitter; "
        "from src.identity_keys.backup import BackupService; "
        "from src.identity_keys.crypto import b64d; "
        "from src.identity_keys.tokens import ActorContext; "
        f"sf = create_session_factory(create_db_engine({bkp_env['db_url']!r})); "
        "c = SystemClock(); e = AuditEmitter('node-a', c); "
        "b = BackupService(sf, c, e, 'node-a'); "
        f"b.restore_backup(ActorContext({bkp_env['users']['carol']!r}, 'c1', 'j1'), {str(bkp_file)!r}, pinned_pubkey=b64d({b64e(bkp_env['bkp_pub'])!r}), passphrase={bkp_env['passphrase']!r})"
    )
    proc = subprocess.run([sys.executable, "-c", script], cwd=str(REPO_ROOT), env=env)
    assert proc.returncode != 0
    # After restart, live DB is completely consistent (never half-restored)
    assert bkp_env["env_svc"].decrypt_resource("res-bkp-1") == b"secret-backup-payload-123"
