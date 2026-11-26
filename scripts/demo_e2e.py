"""End-to-end Person B demonstration script producing reports/demo_run.md."""

from __future__ import annotations

import os
import secrets
import sys
import tempfile
from pathlib import Path

from alembic.config import Config

from alembic import command

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.seed_sandbox import seed_database  # noqa: E402
from src.identity_keys.audit_outbox import AuditDispatcher, AuditEmitter  # noqa: E402
from src.identity_keys.backup import BackupService  # noqa: E402
from src.identity_keys.clock import FakeClock  # noqa: E402
from src.identity_keys.crypto import b64e, ed25519_sign, generate_ed25519_keypair, generate_ml_dsa_keypair  # noqa: E402
from src.identity_keys.db import create_db_engine, create_session_factory  # noqa: E402
from src.identity_keys.errors import IntegrityError as DomainIntegrityError  # noqa: E402
from src.identity_keys.key_lifecycle import EnvelopeEncryptionService  # noqa: E402
from src.identity_keys.reenroll import ReenrollmentService  # noqa: E402
from src.identity_keys.revocation import RevocationReason, RevocationService  # noqa: E402
from src.identity_keys.rotation import RotationService  # noqa: E402
from src.identity_keys.services import AuthzService, IdentityService  # noqa: E402
from src.identity_keys.tokens import ActorContext, TokenAuthority  # noqa: E402


def main() -> int:
    results: list[tuple[str, str]] = []
    with tempfile.TemporaryDirectory(prefix="tbv-e2e-") as tmp:
        tmp_path = Path(tmp)
        os.environ["WRAP_MASTER_KEY_B64"] = b64e(os.urandom(32))
        db_url = f"sqlite+pysqlite:///{tmp_path / 'demo.db'}"
        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("sqlalchemy.url", db_url)
        command.upgrade(cfg, "head")

        sf = create_session_factory(create_db_engine(db_url))
        clock = FakeClock()
        emitter = AuditEmitter("node-a", clock)
        users = seed_database(sf, seed=42)
        admin_ctx = ActorContext(users["carol"], "carol-dev", "jti-demo")

        id_svc = IdentityService(sf, clock, emitter, TokenAuthority(clock))
        authz = AuthzService(sf, clock, emitter, "node-a")
        rot = RotationService(sf, clock, emitter, "node-a")
        rev = RevocationService(sf, clock, emitter, "node-a")
        reenroll = ReenrollmentService(sf, clock, emitter)
        env = EnvelopeEncryptionService(sf, clock, emitter)
        bkp = BackupService(sf, clock, emitter, "node-a")

        rot.create_initial_key_set("auth-demo", "auth")
        rot.create_initial_key_set("data-demo", "data")
        env.encrypt_resource(
            resource_id="brief-alpha",
            owner_user_id=users["alice"],
            plaintext=b"demo-secret-content",
            key_set_id="data-demo",
        )
        results.append(("1. Seed & Envelope Encrypt", "PASS"))

        pub, priv = generate_ed25519_keypair()
        st = id_svc.start_enrollment(users["alice"])
        did = id_svc.enroll_device(
            enrollment_id=st["enrollment_id"],
            nonce=st["nonce"],
            label="demo-dev",
            public_key_b64=b64e(pub),
            proof_of_possession_b64=b64e(ed25519_sign(priv, st["nonce"].encode())),
        )["device_id"]
        alice_ctx = ActorContext(users["alice"], did, "jti-a")
        assert authz.authorize(alice_ctx, "brief-alpha", "resource:read").allowed
        results.append(("2. Device Enroll & Authorize", "PASS"))

        v1 = rot.get_key_set_metadata("auth-demo")["active_key_version_id"]
        rot.initiate_rotation(
            key_set_id="auth-demo",
            grace_seconds=30,
            idempotency_key="demo-rot",
            actor_ctx=admin_ctx,
        )
        assert authz.authorize(alice_ctx, "brief-alpha", "resource:read", key_version_id=v1).allowed
        clock.advance(seconds=31)
        assert not authz.authorize(
            alice_ctx, "brief-alpha", "resource:read", key_version_id=v1
        ).allowed
        results.append(("3. Key Rotation Grace & Hard Cutoff", "PASS"))

        rev.revoke_device(admin_ctx, did, RevocationReason.DEVICE_LOST)
        assert not authz.authorize(alice_ctx, "brief-alpha", "resource:read").allowed
        codes = reenroll.generate_recovery_codes(users["alice"], count=2)
        beg = reenroll.begin_reenrollment(users["alice"])
        p2, k2 = generate_ed25519_keypair()
        done = reenroll.complete_reenrollment(
            enrollment_id=beg["enrollment_id"],
            nonce=beg["nonce"],
            label="demo-dev-2",
            new_public_key_b64=b64e(p2),
            pop_signature_b64=b64e(ed25519_sign(k2, beg["nonce"].encode())),
            old_device_ids=[did],
            recovery_code=codes[0],
        )
        assert authz.authorize(
            ActorContext(users["alice"], done["device_id"], "j2"), "brief-alpha", "resource:read"
        ).allowed
        results.append(("4. Revocation & Secure Re-Enrollment", "PASS"))

        bpub, bpriv = generate_ml_dsa_keypair()
        bpath = tmp_path / "demo.tbv"
        backup_passphrase = secrets.token_urlsafe(32)
        bkp.create_backup(admin_ctx, bpath, signing_privkey=bpriv, passphrase=backup_passphrase)
        raw = bytearray(bpath.read_bytes())
        raw[-1] ^= 0xFF
        bad = tmp_path / "bad.tbv"
        bad.write_bytes(bytes(raw))
        try:
            bkp.restore_backup(admin_ctx, bad, pinned_pubkey=bpub, passphrase=backup_passphrase)
            results.append(("5. Backup Tamper Detection", "FAIL"))
            return 1
        except DomainIntegrityError:
            results.append(("5. Backup Tamper Detection", "PASS"))

        disp = AuditDispatcher(sf, clock, "node-a", log_file_path=str(tmp_path / "audit.log"))
        delivered = disp.dispatch_pending()
        assert delivered >= 5
        results.append((f"6. Transactional Audit Dispatch ({delivered} events)", "PASS"))

    report = ["# End-to-End Demo Run", "", "| Step | Outcome |", "| --- | --- |"]
    for step, status in results:
        report.append(f"| {step} | {status} |")
        print(f"{status}: {step}")
    reports_dir = REPO_ROOT / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (reports_dir / "demo_run.md").write_text("\n".join(report) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
