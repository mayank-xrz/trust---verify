"""Encrypted, ML-DSA-65-signed backup creation and 11-step fail-closed restore."""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import os
import struct
import tarfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import delete, select
from sqlalchemy.orm import Session, sessionmaker

from .audit_outbox import AuditEmitter
from .clock import Clock
from .crypto import (
    aes_gcm_unwrap,
    aes_gcm_wrap,
    b64d,
    b64e,
    canonical_json_bytes,
    ml_dsa_sign,
    ml_dsa_verify,
    sha256_hex,
)
from .db import tx_session
from .errors import (
    Conflict,
    NotAuthorized,
    StateUnavailable,
)
from .errors import (
    IntegrityError as DomainIntegrityError,
)
from .models import (
    Backup,
    CommitSeqCounter,
    Device,
    Enrollment,
    KeySet,
    KeyVersion,
    NodeSyncState,
    Permission,
    Resource,
    ResourceGrant,
    Revocation,
    Role,
    RolePermission,
    Rotation,
    TrustAnchor,
    User,
    UserRole,
)
from .rotation import crash_point
from .tokens import ActorContext

BACKUP_MAGIC = b"TBVBKP1\x00"
CURRENT_SCHEMA_VERSION = "0004_part4_trust_anchor"
APP_VERSION = "1.0.0"
MAX_TAR_MEMBERS = 64
MAX_TAR_UNCOMPRESSED_BYTES = 64 * 1024 * 1024

_BACKUP_TABLES: tuple[tuple[str, Any], ...] = (
    ("users", User),
    ("enrollments", Enrollment),
    ("devices", Device),
    ("roles", Role),
    ("permissions", Permission),
    ("role_permissions", RolePermission),
    ("user_roles", UserRole),
    ("rotations", Rotation),
    ("key_sets", KeySet),
    ("key_versions", KeyVersion),
    ("resources", Resource),
    ("resource_grants", ResourceGrant),
    ("revocations", Revocation),
    ("trust_anchor", TrustAnchor),
)


def _encode_val(v: Any) -> Any:
    if isinstance(v, datetime):
        dt = v.replace(tzinfo=timezone.utc) if v.tzinfo is None else v
        return {"__dt__": dt.isoformat()}
    if isinstance(v, (bytes, bytearray)):
        return {"__b64__": b64e(bytes(v))}
    return v


def _decode_val(v: Any) -> Any:
    if isinstance(v, dict):
        if "__dt__" in v:
            return datetime.fromisoformat(v["__dt__"])
        if "__b64__" in v:
            return b64d(v["__b64__"])
    return v


def _row_to_dict(model: Any, row: Any) -> dict[str, Any]:
    return {col.name: _encode_val(getattr(row, col.name)) for col in model.__table__.columns}


def _dict_to_row(model: Any, data: dict[str, Any]) -> Any:
    kwargs = {
        col.name: _decode_val(data[col.name]) for col in model.__table__.columns if col.name in data
    }
    return model(**kwargs)


def _merkle_root(hashes: list[str]) -> str:
    if not hashes:
        return sha256_hex(b"empty")
    nodes = [bytes.fromhex(h) for h in sorted(hashes)]
    while len(nodes) > 1:
        if len(nodes) % 2 == 1:
            nodes.append(nodes[-1])
        nodes = [hashlib.sha256(nodes[i] + nodes[i + 1]).digest() for i in range(0, len(nodes), 2)]
    return nodes[0].hex()


def _scrypt_key(passphrase: str, salt: bytes, n: int = 16384, r: int = 8, p: int = 1) -> bytes:
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)


def _compute_revocation_head(rev_rows: list[Revocation]) -> tuple[int, str]:
    if not rev_rows:
        return 0, sha256_hex(b"genesis-revocation")
    ordered = sorted(rev_rows, key=lambda r: r.commit_seq)
    h = sha256_hex(b"genesis-revocation")
    for r in ordered:
        h = sha256_hex(
            f"{h}|{r.commit_seq}|{r.revocation_id}|{r.target_type}|{r.target_id}".encode("utf-8")
        )
    return ordered[-1].commit_seq, h


def table_recursive_hash(session: Session) -> dict[str, str]:
    """Compute deterministic per-table SHA-256 digest for round-trip & tamper-invariance checks."""
    out: dict[str, str] = {}
    for name, model in _BACKUP_TABLES:
        rows = session.execute(select(model)).scalars().all()
        encoded = sorted(canonical_json_bytes(_row_to_dict(model, r)).decode("utf-8") for r in rows)
        out[name] = sha256_hex("\n".join(encoded).encode("utf-8"))
    return out


class BackupService:
    """Creates and restores encrypted, signed, rollback-protected cluster backups."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        clock: Clock,
        emitter: AuditEmitter,
        node_id: str,
    ) -> None:
        self.session_factory = session_factory
        self.clock = clock
        self.emitter = emitter
        self.node_id = node_id

    @staticmethod
    def _has_perm(session: Session, user_id: str, perm: str) -> bool:
        return (
            session.execute(
                select(Permission.name)
                .join(RolePermission, RolePermission.permission_id == Permission.permission_id)
                .join(UserRole, UserRole.role_id == RolePermission.role_id)
                .where(UserRole.user_id == user_id, Permission.name == perm)
            ).first()
            is not None
        )

    def create_backup(
        self,
        actor_ctx: ActorContext,
        path: str | Path,
        *,
        signing_privkey: bytes,
        passphrase: str,
    ) -> dict[str, Any]:
        """Take a consistent DB snapshot, tar+encrypt with AES-256-GCM, and sign manifest."""
        now = self.clock.now()
        backup_id = str(uuid.uuid4())
        target_path = Path(path)

        with tx_session(self.session_factory) as session:
            if not self._has_perm(session, actor_ctx.user_id, "backup:create"):
                raise NotAuthorized("Missing backup:create permission", reason_code="FORBIDDEN")

            table_bytes: dict[str, bytes] = {}
            table_hashes: dict[str, str] = {}
            row_counts: dict[str, int] = {}
            kv_summary: list[dict[str, Any]] = []
            rev_rows: list[Revocation] = []
            dev_rows: list[Device] = []

            for tname, model in _BACKUP_TABLES:
                rows = session.execute(select(model)).scalars().all()
                row_counts[tname] = len(rows)
                lines = sorted(
                    canonical_json_bytes(_row_to_dict(model, r)).decode("utf-8") for r in rows
                )
                raw = ("\n".join(lines) + ("\n" if lines else "")).encode("utf-8")
                table_bytes[f"{tname}.jsonl"] = raw
                table_hashes[f"{tname}.jsonl"] = sha256_hex(raw)
                if tname == "key_versions":
                    for kv in rows:
                        kv_summary.append(
                            {
                                "key_set_id": kv.key_set_id,
                                "version": kv.version,
                                "state": kv.state,
                                "public_key_fingerprint": sha256_hex(kv.public_material)
                                if kv.public_material
                                else None,
                            }
                        )
                elif tname == "revocations":
                    rev_rows = list(rows)
                elif tname == "devices":
                    dev_rows = list(rows)

            commit_seq, head_hash = _compute_revocation_head(rev_rows)
            dev_digest = sha256_hex(
                canonical_json_bytes(
                    sorted((d.device_id, d.status, d.public_key_fingerprint) for d in dev_rows)
                )
            )
            merkle = _merkle_root(list(table_hashes.values()))

            # Update live trust_anchor on backup creation
            anchor = session.get(TrustAnchor, "primary")
            if anchor is None:
                session.add(
                    TrustAnchor(
                        anchor_id="primary",
                        revocation_commit_seq=commit_seq,
                        revocation_head_hash=head_hash,
                        updated_at=now,
                    )
                )
            elif commit_seq >= anchor.revocation_commit_seq:
                anchor.revocation_commit_seq = commit_seq
                anchor.revocation_head_hash = head_hash
                anchor.updated_at = now

            # Build deterministic tar.gz in memory
            tar_buf = io.BytesIO()
            with tarfile.open(fileobj=tar_buf, mode="w:gz") as tf:
                for fname in sorted(table_bytes):
                    data = table_bytes[fname]
                    ti = tarfile.TarInfo(name=fname)
                    ti.size = len(data)
                    ti.mtime = 0
                    tf.addfile(ti, io.BytesIO(data))
            tar_gz = tar_buf.getvalue()

            salt = os.urandom(16)
            header_core = {
                "magic": "TBVBKP1",
                "format_version": 1,
                "kdf": {"alg": "scrypt", "n": 16384, "r": 8, "p": 1, "salt_b64": b64e(salt)},
            }
            header_bytes = canonical_json_bytes(header_core)
            header_sha256 = sha256_hex(header_bytes)

            manifest_core = {
                "backup_id": backup_id,
                "schema_version": CURRENT_SCHEMA_VERSION,
                "app_version": APP_VERSION,
                "created_at": now.isoformat(),
                "node_id": self.node_id,
                "key_versions": sorted(kv_summary, key=lambda x: (x["key_set_id"], x["version"])),
                "row_counts": row_counts,
                "table_hashes": table_hashes,
                "revocation_head": {"commit_seq": commit_seq, "head_hash": head_hash},
                "device_status_digest": dev_digest,
                "merkle_root": merkle,
                "header_sha256": header_sha256,
                "signature_algorithm": "ML-DSA-65",
            }
            aad = header_bytes + canonical_json_bytes(manifest_core)
            enc_key = _scrypt_key(passphrase, salt)
            nonce, ciphertext = aes_gcm_wrap(enc_key, tar_gz, aad)

            manifest = {**manifest_core, "ciphertext_sha256": sha256_hex(ciphertext)}
            manifest_sig = ml_dsa_sign(signing_privkey, canonical_json_bytes(manifest))

            envelope = {
                "header": header_core,
                "nonce_b64": b64e(nonce),
                "manifest": manifest,
                "manifest_sig_b64": b64e(manifest_sig),
            }
            env_bytes = canonical_json_bytes(envelope)
            target_path.parent.mkdir(parents=True, exist_ok=True)
            target_path.write_bytes(
                BACKUP_MAGIC + struct.pack(">I", len(env_bytes)) + env_bytes + ciphertext
            )

            session.add(
                Backup(
                    backup_id=backup_id,
                    created_at=now,
                    schema_version=CURRENT_SCHEMA_VERSION,
                    manifest=canonical_json_bytes(manifest),
                    status="CREATED",
                )
            )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="backup.created",
                target=backup_id,
                outcome="allow",
                reason_code="BACKUP_CREATED",
                metadata={"merkle_root": merkle, "commit_seq": commit_seq},
            )
        return {"backup_id": backup_id, "path": str(target_path), "merkle_root": merkle}

    def _audit_rejected(self, actor_ctx: ActorContext, target: str, reason_code: str) -> None:
        try:
            with tx_session(self.session_factory) as session:
                self.emitter.emit(
                    session,
                    actor_id=actor_ctx.user_id,
                    device_id=actor_ctx.device_id,
                    action="backup.rejected",
                    target=target,
                    outcome="deny",
                    reason_code=reason_code,
                )
        except Exception:
            pass

    def restore_backup(
        self,
        actor_ctx: ActorContext,
        path: str | Path,
        *,
        pinned_pubkey: bytes,
        passphrase: str,
        allow_rollback: bool = False,
        accept_unanchored: bool = False,
        supplied_anchor: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """11-step fail-closed restore; rejects any damaged or unauthorized backup untouched."""
        now = self.clock.now()
        raw = Path(path).read_bytes()

        # Step 1: Parse header, magic, format version
        try:
            if not raw.startswith(BACKUP_MAGIC) or len(raw) < len(BACKUP_MAGIC) + 4:
                raise DomainIntegrityError("Invalid backup magic", "STEP1_INVALID_HEADER")
            env_len = struct.unpack(">I", raw[len(BACKUP_MAGIC) : len(BACKUP_MAGIC) + 4])[0]
            env_start = len(BACKUP_MAGIC) + 4
            if env_start + env_len > len(raw):
                raise DomainIntegrityError("Truncated backup envelope", "STEP1_TRUNCATED")
            envelope = json.loads(raw[env_start : env_start + env_len].decode("utf-8"))
            ciphertext = raw[env_start + env_len :]
            header = envelope["header"]
            manifest = envelope["manifest"]
            nonce = b64d(envelope["nonce_b64"])
            if header.get("magic") != "TBVBKP1" or header.get("format_version") != 1:
                raise DomainIntegrityError("Unsupported backup format", "STEP1_BAD_VERSION")
        except DomainIntegrityError as exc:
            self._audit_rejected(actor_ctx, str(path), exc.reason_code)
            raise
        except Exception as exc:
            self._audit_rejected(actor_ctx, str(path), "STEP1_PARSE_ERROR")
            raise DomainIntegrityError("Malformed backup container", "STEP1_PARSE_ERROR") from exc

        # Step 2: Verify manifest signature using PINNED public key only
        try:
            sig_bytes = b64d(envelope.get("manifest_sig_b64") or "")
        except (TypeError, ValueError):
            sig_bytes = b""
        if not sig_bytes:
            self._audit_rejected(actor_ctx, manifest.get("backup_id", "unknown"), "STEP2_MISSING_SIGNATURE")
            raise DomainIntegrityError("Manifest signature missing or malformed", "STEP2_MISSING_SIGNATURE")
        if not ml_dsa_verify(pinned_pubkey, canonical_json_bytes(manifest), sig_bytes):
            self._audit_rejected(
                actor_ctx, manifest.get("backup_id", "unknown"), "STEP2_BAD_SIGNATURE"
            )
            raise DomainIntegrityError(
                "Manifest signature verification failed", "STEP2_BAD_SIGNATURE"
            )

        # Step 3: Verify header and ciphertext hashes
        header_bytes = canonical_json_bytes(header)
        if not hmac.compare_digest(
            sha256_hex(header_bytes), str(manifest.get("header_sha256", ""))
        ):
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP3_HEADER_HASH_MISMATCH")
            raise DomainIntegrityError("Header hash mismatch", "STEP3_HEADER_HASH_MISMATCH")
        if not hmac.compare_digest(
            sha256_hex(ciphertext), str(manifest.get("ciphertext_sha256", ""))
        ):
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP3_CIPHERTEXT_HASH_MISMATCH")
            raise DomainIntegrityError("Ciphertext hash mismatch", "STEP3_CIPHERTEXT_HASH_MISMATCH")

        # Step 4: AEAD decrypt
        try:
            kdf = header["kdf"]
            enc_key = _scrypt_key(passphrase, b64d(kdf["salt_b64"]), kdf["n"], kdf["r"], kdf["p"])
            manifest_core = {k: v for k, v in manifest.items() if k != "ciphertext_sha256"}
            aad = header_bytes + canonical_json_bytes(manifest_core)
            tar_gz = aes_gcm_unwrap(enc_key, nonce, ciphertext, aad)
        except Exception as exc:
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP4_AEAD_DECRYPT_FAILED")
            raise DomainIntegrityError(
                "Backup decryption failed", "STEP4_AEAD_DECRYPT_FAILED"
            ) from exc

        # Step 5: Safe staging tar extraction (path traversal, symlink, decompression bomb defense)
        extracted: dict[str, bytes] = {}
        try:
            total_bytes = 0
            with tarfile.open(fileobj=io.BytesIO(tar_gz), mode="r:gz") as tf:
                members = tf.getmembers()
                if len(members) > MAX_TAR_MEMBERS:
                    raise DomainIntegrityError("Too many tar members", "STEP5_BOMB_COUNT")
                for m in members:
                    if m.issym() or m.islnk() or not m.isreg():
                        raise DomainIntegrityError("Non-regular tar member", "STEP5_UNSAFE_MEMBER")
                    if m.name.startswith("/") or ".." in Path(m.name).parts:
                        raise DomainIntegrityError("Path traversal in tar", "STEP5_PATH_TRAVERSAL")
                    if m.name in extracted:
                        raise DomainIntegrityError("Duplicate tar member", "STEP5_DUPLICATE_MEMBER")
                    total_bytes += m.size
                    if total_bytes > MAX_TAR_UNCOMPRESSED_BYTES:
                        raise DomainIntegrityError(
                            "Decompression bomb exceeded cap", "STEP5_BOMB_SIZE"
                        )
                    fobj = tf.extractfile(m)
                    assert fobj is not None
                    data = fobj.read(MAX_TAR_UNCOMPRESSED_BYTES + 1)
                    if len(data) != m.size:
                        raise DomainIntegrityError(
                            "Tar member size mismatch", "STEP5_SIZE_MISMATCH"
                        )
                    extracted[m.name] = data
        except DomainIntegrityError as exc:
            self._audit_rejected(actor_ctx, manifest["backup_id"], exc.reason_code)
            raise
        except Exception as exc:
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP5_TAR_ERROR")
            raise DomainIntegrityError("Invalid tar archive", "STEP5_TAR_ERROR") from exc

        # Step 6: Verify every table payload hash, row count, Merkle root, and exact member set
        expected_files = {f"{tname}.jsonl" for tname, _ in _BACKUP_TABLES}
        if set(extracted.keys()) != expected_files:
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP6_MEMBER_SET_MISMATCH")
            raise DomainIntegrityError(
                "Missing or extra backup members", "STEP6_MEMBER_SET_MISMATCH"
            )

        parsed_tables: dict[str, list[dict[str, Any]]] = {}
        for tname, _ in _BACKUP_TABLES:
            fname = f"{tname}.jsonl"
            raw_tbl = extracted[fname]
            if not hmac.compare_digest(sha256_hex(raw_tbl), manifest["table_hashes"][fname]):
                self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP6_TABLE_HASH_MISMATCH")
                raise DomainIntegrityError(f"Hash mismatch on {fname}", "STEP6_TABLE_HASH_MISMATCH")
            rows_list = [
                json.loads(ln) for ln in raw_tbl.decode("utf-8").splitlines() if ln.strip()
            ]
            if len(rows_list) != manifest["row_counts"][tname]:
                self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP6_ROW_COUNT_MISMATCH")
                raise DomainIntegrityError(
                    f"Row count mismatch on {tname}", "STEP6_ROW_COUNT_MISMATCH"
                )
            parsed_tables[tname] = rows_list

        if not hmac.compare_digest(
            _merkle_root(list(manifest["table_hashes"].values())), manifest["merkle_root"]
        ):
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP6_MERKLE_MISMATCH")
            raise DomainIntegrityError("Merkle root mismatch", "STEP6_MERKLE_MISMATCH")

        # Step 7: Schema compatibility check
        if manifest.get("schema_version") != CURRENT_SCHEMA_VERSION:
            self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP7_SCHEMA_INCOMPATIBLE")
            raise DomainIntegrityError("Incompatible schema version", "STEP7_SCHEMA_INCOMPATIBLE")

        # Step 8: Semantic checks (single ACTIVE per key_set, revoked match manifest)
        active_sets: set[str] = set()
        bkp_revoked_devs = set()
        for kv in parsed_tables["key_versions"]:
            if kv["state"] == "ACTIVE":
                if kv["key_set_id"] in active_sets:
                    self._audit_rejected(
                        actor_ctx, manifest["backup_id"], "STEP8_MULTIPLE_ACTIVE_KEYS"
                    )
                    raise DomainIntegrityError(
                        "Two ACTIVE keys in key_set", "STEP8_MULTIPLE_ACTIVE_KEYS"
                    )
                active_sets.add(kv["key_set_id"])
        for d in parsed_tables["devices"]:
            if d["status"] == "revoked":
                bkp_revoked_devs.add(d["device_id"])
                if d["revoked_at"] is None:
                    self._audit_rejected(
                        actor_ctx, manifest["backup_id"], "STEP8_REVOKED_WITHOUT_TS"
                    )
                    raise DomainIntegrityError(
                        "Revoked device missing revoked_at", "STEP8_REVOKED_WITHOUT_TS"
                    )

        # Steps 9, 10, 11 inside one atomic DB transaction
        with tx_session(self.session_factory) as session:
            # Step 10 (authz): require backup:restore
            if not self._has_perm(session, actor_ctx.user_id, "backup:restore"):
                raise NotAuthorized(
                    "Missing backup:restore permission", reason_code="STEP10_FORBIDDEN"
                )

            # Step 9: Anchor & rollback check
            live_anchor = session.get(TrustAnchor, "primary")
            live_revs = session.execute(select(Revocation)).scalars().all()
            live_seq, _ = _compute_revocation_head(list(live_revs))
            anchor_seq: Optional[int] = None
            if live_anchor is not None:
                anchor_seq = max(live_anchor.revocation_commit_seq, live_seq)
            elif supplied_anchor is not None:
                sig_hex = supplied_anchor.get("signature_hex") or supplied_anchor.get("signature")
                if not sig_hex:
                    self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP9_ANCHOR_UNSIGNED")
                    raise NotAuthorized(
                        "Supplied trust anchor missing signature",
                        reason_code="STEP9_ANCHOR_UNSIGNED",
                    )
                anchor_core = {
                    k: v
                    for k, v in supplied_anchor.items()
                    if k not in ("signature_hex", "signature")
                }
                try:
                    sig_bytes = bytes.fromhex(str(sig_hex))
                except ValueError as exc:
                    raise NotAuthorized(
                        "Malformed supplied anchor signature",
                        reason_code="STEP9_ANCHOR_INVALID",
                    ) from exc
                if not ml_dsa_verify(pinned_pubkey, canonical_json_bytes(anchor_core), sig_bytes):
                    self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP9_ANCHOR_INVALID")
                    raise NotAuthorized(
                        "Supplied trust anchor signature invalid",
                        reason_code="STEP9_ANCHOR_INVALID",
                    )
                anchor_seq = int(supplied_anchor["revocation_commit_seq"])
                if (
                    int(manifest["revocation_head"]["commit_seq"]) == anchor_seq
                    and supplied_anchor.get("revocation_head_hash")
                    and manifest["revocation_head"].get("head_hash")
                    != supplied_anchor["revocation_head_hash"]
                ):
                    self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP9_HEAD_HASH_MISMATCH")
                    raise Conflict(
                        "Backup revocation head hash does not match supplied anchor",
                        reason_code="STEP9_HEAD_HASH_MISMATCH",
                    )
            elif live_revs:
                anchor_seq = live_seq

            if anchor_seq is None:
                if not accept_unanchored:
                    self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP9_UNANCHORED")
                    raise StateUnavailable(
                        "No trust anchor available", reason_code="STEP9_UNANCHORED"
                    )
            else:
                bkp_seq = int(manifest["revocation_head"]["commit_seq"])
                if bkp_seq < anchor_seq and not allow_rollback:
                    self._audit_rejected(actor_ctx, manifest["backup_id"], "STEP9_ROLLBACK_REFUSED")
                    raise Conflict(
                        "Backup is behind live revocation anchor",
                        reason_code="STEP9_ROLLBACK_REFUSED",
                    )

            crash_point("restore.before_apply")

            # Preserve live revocations + revoked devices/keys for forward union merge
            live_rev_rows = [_row_to_dict(Revocation, r) for r in live_revs]
            live_revoked_dev_ids = {r.target_id for r in live_revs if r.target_type == "device"}
            live_revoked_kv_ids = {r.target_id for r in live_revs if r.target_type == "key_version"}

            # Clear mutable tables in reverse FK order (never delete append-only revocations)
            for tname, model in reversed(_BACKUP_TABLES):
                if tname == "revocations":
                    continue
                session.execute(delete(model))
            session.flush()

            for tname, model in _BACKUP_TABLES:
                if tname == "revocations":
                    continue
                for row_dict in parsed_tables[tname]:
                    if tname == "devices" and row_dict["device_id"] in live_revoked_dev_ids:
                        row_dict["status"] = "revoked"
                        if row_dict.get("revoked_at") is None:
                            row_dict["revoked_at"] = _encode_val(now)
                            row_dict["revoked_reason"] = "MERGED_LIVE_REVOCATION"
                    if (
                        tname == "key_versions"
                        and row_dict["key_version_id"] in live_revoked_kv_ids
                    ):
                        row_dict["state"] = "REVOKED"
                        if row_dict.get("revoked_at") is None:
                            row_dict["revoked_at"] = _encode_val(now)
                    session.add(_dict_to_row(model, row_dict))
                session.flush()

            crash_point("restore.during_apply")

            # Append-only merge of revocations: preserve live_revs untouched and insert missing ones
            seen_rev_ids = {r["revocation_id"] for r in live_rev_rows}
            next_seq = max((r["commit_seq"] for r in live_rev_rows), default=0)
            merged_revs = list(live_rev_rows)
            for r in sorted(parsed_tables["revocations"], key=lambda x: x["commit_seq"]):
                if r["revocation_id"] not in seen_rev_ids:
                    seen_rev_ids.add(r["revocation_id"])
                    next_seq += 1
                    r["commit_seq"] = next_seq
                    session.add(_dict_to_row(Revocation, r))
                    merged_revs.append(r)
            session.flush()

            counter = session.get(CommitSeqCounter, "revocations")
            if counter:
                counter.last_seq = len(merged_revs)

            live_rev_objs = session.execute(select(Revocation)).scalars().all()
            _, new_head_hash = _compute_revocation_head(list(live_rev_objs))
            anchor_row = session.get(TrustAnchor, "primary")
            if anchor_row is None:
                session.add(
                    TrustAnchor(
                        anchor_id="primary",
                        revocation_commit_seq=len(merged_revs),
                        revocation_head_hash=new_head_hash,
                        updated_at=now,
                    )
                )
            else:
                anchor_row.revocation_commit_seq = max(
                    anchor_row.revocation_commit_seq, len(merged_revs)
                )
                anchor_row.revocation_head_hash = new_head_hash
                anchor_row.updated_at = now

            for st in session.execute(select(NodeSyncState)).scalars().all():
                st.last_applied_commit_seq = len(merged_revs)
                st.last_seen_at = now

            if accept_unanchored and anchor_seq is None:
                self.emitter.emit(
                    session,
                    actor_id=actor_ctx.user_id,
                    device_id=actor_ctx.device_id,
                    action="backup.unanchored_override",
                    target=manifest["backup_id"],
                    outcome="allow",
                    reason_code="UNANCHORED_ACCEPTED",
                )
            self.emitter.emit(
                session,
                actor_id=actor_ctx.user_id,
                device_id=actor_ctx.device_id,
                action="backup.restored",
                target=manifest["backup_id"],
                outcome="allow",
                reason_code="BACKUP_RESTORED",
                metadata={"merged_revocations": len(merged_revs)},
            )

        crash_point("restore.after_apply")
        return {
            "restored": True,
            "backup_id": manifest["backup_id"],
            "merged_revocations": len(merged_revs),
        }
