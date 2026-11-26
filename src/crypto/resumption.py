"""Peer-Bound, Single-Use Session Resumption with Persistent Replay Protection.

Ticket fields:
- session_id
- peer_identity (plaintext, for audit)
- peer_identity_hash (SHA-256 of the bound peer identity)
- peer_device
- original_transcript_hash
- expiry
- resumption_key_id
- signature (ML-DSA-65 over the canonical ticket body)

The store persists an ML-DSA-65 ticket/PoP signing keypair in its SQLite
database so tickets remain verifiable across restarts and across store
instances sharing the same database.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Callable, Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.sign import ml_dsa_65

from src.audit.logger import AuditLogger

from ._pqcrypto_compat import sig_keygen, sig_sign, sig_verify
from .events import emit_crypto_event
from .handshake import SessionKeys

TICKET_DOMAIN = b"track4/v1/ticket\x00"
POP_DOMAIN = b"track4/v1/resume-pop\x00"


def _peer_identity_hash(peer_identity: str) -> str:
    return hashlib.sha256(peer_identity.encode("utf-8")).hexdigest()


class ResumptionError(Exception):
    """Base error for session resumption."""
    reason = "resumption_error"


class ResumptionPeerMismatchError(ResumptionError):
    reason = "resumption_peer_mismatch"


class ResumptionExpiredError(ResumptionError):
    reason = "resumption_expired"


class ResumptionReplayedError(ResumptionError):
    reason = "resumption_replayed"


class PersistentResumptionStore:
    """SQLite-backed store tracking issued and consumed resumption tickets."""

    def __init__(
        self,
        db_path: str | Path,
        *,
        audit_logger: Optional[AuditLogger] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db_path = Path(db_path)
        self.audit_logger = audit_logger
        self.clock = clock
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS resumption_tickets (
                    session_id TEXT PRIMARY KEY,
                    resumption_key_id TEXT NOT NULL,
                    peer_identity TEXT NOT NULL,
                    peer_device TEXT NOT NULL,
                    original_transcript_hash TEXT NOT NULL,
                    resumption_secret BLOB NOT NULL,
                    expiry REAL NOT NULL,
                    used INTEGER NOT NULL DEFAULT 0
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS resumption_signing_keys (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    public_key BLOB NOT NULL,
                    secret_key BLOB NOT NULL
                )
                """
            )
            row = db.execute(
                "SELECT public_key, secret_key FROM resumption_signing_keys WHERE id=1"
            ).fetchone()
            if row is None:
                public_key, secret_key = sig_keygen(ml_dsa_65)
                db.execute(
                    "INSERT INTO resumption_signing_keys (id, public_key, secret_key) VALUES (1, ?, ?)",
                    (public_key, secret_key),
                )
            else:
                public_key, secret_key = row
        self._signing_public_key = bytes(public_key)
        self._signing_secret_key = bytes(secret_key)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _canonical_ticket_body(ticket: Dict[str, object]) -> bytes:
        body = {
            "session_id": ticket["session_id"],
            "peer_identity": ticket["peer_identity"],
            "peer_identity_hash": ticket["peer_identity_hash"],
            "peer_device": ticket["peer_device"],
            "original_transcript_hash": ticket["original_transcript_hash"],
            "expiry": ticket["expiry"],
            "resumption_key_id": ticket["resumption_key_id"],
        }
        return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def issue_ticket(
        self,
        *,
        session_id: str,
        peer_identity: str,
        peer_device: str,
        original_transcript_hash: str,
        resumption_secret: bytes,
        ttl_seconds: float = 300.0,
    ) -> Dict[str, object]:
        """Create and persist a peer-bound, single-use resumption ticket."""
        resumption_key_id = "rk-" + secrets.token_hex(12)
        expiry = self.clock() + ttl_seconds
        ticket: Dict[str, object] = {
            "session_id": session_id,
            "peer_identity": peer_identity,
            "peer_identity_hash": _peer_identity_hash(peer_identity),
            "peer_device": peer_device,
            "original_transcript_hash": original_transcript_hash,
            "expiry": expiry,
            "resumption_key_id": resumption_key_id,
        }
        signature = sig_sign(
            ml_dsa_65,
            self._signing_secret_key,
            TICKET_DOMAIN + self._canonical_ticket_body(ticket),
        )
        ticket["signature"] = signature.hex()

        with self._connect() as db:
            db.execute(
                """
                INSERT OR REPLACE INTO resumption_tickets
                (session_id, resumption_key_id, peer_identity, peer_device, original_transcript_hash, resumption_secret, expiry, used)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    session_id,
                    resumption_key_id,
                    peer_identity,
                    peer_device,
                    original_transcript_hash,
                    resumption_secret,
                    expiry,
                ),
            )
        return ticket

    def create_proof_of_possession(
        self,
        resumption_secret: bytes,
        fresh_nonce: bytes,
        new_transcript_hash: str,
    ) -> str:
        """ML-DSA-65 proof of possession over the fresh nonce and new transcript.

        The signed message also binds a SHA-256 digest of the shared resumption
        secret, so a caller that does not know the secret cannot produce a
        proof that this store will accept.
        """
        msg = (
            POP_DOMAIN
            + hashlib.sha256(resumption_secret).digest()
            + fresh_nonce
            + new_transcript_hash.encode("utf-8")
        )
        return sig_sign(ml_dsa_65, self._signing_secret_key, msg).hex()

    def resume(
        self,
        ticket: Dict[str, object],
        *,
        presented_identity: str,
        presented_device: str,
        fresh_nonce: bytes,
        proof_of_possession: str,
        new_transcript_hash: str,
        local_service: str = "responder",
    ) -> Tuple[SessionKeys, Dict[str, object]]:
        """Verify peer binding, expiry, single-use status, MAC, and PoP, then derive new keys."""
        session_id = str(ticket.get("session_id", ""))
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                """
                SELECT resumption_key_id, peer_identity, peer_device, original_transcript_hash,
                       resumption_secret, expiry, used
                FROM resumption_tickets
                WHERE session_id=?
                """,
                (session_id,),
            ).fetchone()

            if row is None:
                raise ResumptionError(f"Unknown session_id: {session_id}")

            rk_id, bound_id, bound_dev, orig_th, res_secret, expiry, used = row

            # 1. Peer binding check BEFORE any key derivation.  The signed
            #    peer_identity_hash is compared in constant time as well as the
            #    plaintext fields.
            bound_hash = _peer_identity_hash(str(bound_id))
            presented_hash = ticket.get("peer_identity_hash")
            hash_ok = (
                isinstance(presented_hash, str)
                and hmac.compare_digest(presented_hash, bound_hash)
            )
            if (
                presented_identity != bound_id
                or presented_device != bound_dev
                or ticket.get("peer_identity") != bound_id
                or ticket.get("peer_device") != bound_dev
                or not hash_ok
            ):
                emit_crypto_event(
                    self.audit_logger,
                    actor=presented_identity,
                    source_service=f"{presented_identity}/{presented_device}",
                    target_service=local_service,
                    action="resumption_peer_mismatch",
                    outcome="rejected",
                    session_id=session_id,
                    reason="resumption_peer_mismatch",
                    extra={"presented_identity": presented_identity, "bound_identity": bound_id},
                )
                raise ResumptionPeerMismatchError(
                    f"Peer mismatch: presented {presented_identity}/{presented_device}, bound to {bound_id}/{bound_dev}"
                )

            # 2. Expiry check
            if self.clock() > float(expiry):
                emit_crypto_event(
                    self.audit_logger,
                    actor=presented_identity,
                    source_service=f"{presented_identity}/{presented_device}",
                    target_service=local_service,
                    action="resumption_expired",
                    outcome="rejected",
                    session_id=session_id,
                    reason="resumption_expired",
                )
                raise ResumptionExpiredError(f"Resumption ticket expired for session {session_id}")

            # 3. Single-use / replay check
            if int(used) != 0 or ticket.get("resumption_key_id") != rk_id:
                emit_crypto_event(
                    self.audit_logger,
                    actor=presented_identity,
                    source_service=f"{presented_identity}/{presented_device}",
                    target_service=local_service,
                    action="resumption_replayed",
                    outcome="rejected",
                    session_id=session_id,
                    reason="resumption_replayed",
                )
                raise ResumptionReplayedError(f"Resumption ticket already used for session {session_id}")

            # 4. Verify the ML-DSA-65 ticket signature over the canonical body
            try:
                ticket_body = self._canonical_ticket_body(ticket)
            except KeyError as exc:
                raise ResumptionError(f"Resumption ticket malformed: missing {exc}") from exc
            try:
                ticket_sig = bytes.fromhex(str(ticket.get("signature", "")))
            except ValueError as exc:
                raise ResumptionError("Resumption ticket signature invalid") from exc
            if not sig_verify(
                ml_dsa_65,
                self._signing_public_key,
                TICKET_DOMAIN + ticket_body,
                ticket_sig,
            ):
                raise ResumptionError("Resumption ticket signature invalid")

            # 5. Verify the ML-DSA-65 Proof of Possession over fresh nonce +
            #    new transcript, bound to the shared resumption secret.
            pop_msg = (
                POP_DOMAIN
                + hashlib.sha256(res_secret).digest()
                + fresh_nonce
                + new_transcript_hash.encode("utf-8")
            )
            try:
                pop_sig = bytes.fromhex(str(proof_of_possession))
            except ValueError as exc:
                raise ResumptionError("Resumption proof of possession invalid") from exc
            if not sig_verify(ml_dsa_65, self._signing_public_key, pop_msg, pop_sig):
                raise ResumptionError("Resumption proof of possession invalid")

            # 6. Mark ticket used atomically before deriving new keys
            db.execute("UPDATE resumption_tickets SET used=1 WHERE session_id=?", (session_id,))

        # 7. Derive new session keys bound to original & new handshake transcripts
        salt = hashlib.sha256(
            orig_th.encode("utf-8") + b"|" + new_transcript_hash.encode("utf-8") + b"|" + fresh_nonce
        ).digest()
        new_session_id = "sess-" + secrets.token_hex(16)
        tx_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"track4/v1/resumed-tx",
        ).derive(res_secret)
        rx_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"track4/v1/resumed-rx",
        ).derive(res_secret)
        next_res_secret = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b"track4/v1/resumed-secret",
        ).derive(res_secret)

        emit_crypto_event(
            self.audit_logger,
            actor=presented_identity,
            source_service=f"{presented_identity}/{presented_device}",
            target_service=local_service,
            action="resumption_accepted",
            outcome="accepted",
            session_id=new_session_id,
            reason="ok",
            extra={"previous_session_id": session_id},
        )

        new_keys = SessionKeys(
            session_id=new_session_id,
            transcript_hash=new_transcript_hash,
            tx_key=tx_key,
            rx_key=rx_key,
            resumption_secret=next_res_secret,
            peer_identity=bound_id,
            peer_device=bound_dev,
        )
        rotated_ticket = self.issue_ticket(
            session_id=new_session_id,
            peer_identity=bound_id,
            peer_device=bound_dev,
            original_transcript_hash=new_transcript_hash,
            resumption_secret=next_res_secret,
        )
        return new_keys, rotated_ticket
