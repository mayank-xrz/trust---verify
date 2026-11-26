"""Peer-Bound, Single-Use Session Resumption with Persistent Replay Protection.

Ticket fields:
- session_id
- peer_identity
- peer_device
- original_transcript_hash
- expiry
- resumption_key_id
- mac (HMAC-SHA256 under the session's resumption_secret)
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

from src.audit.logger import AuditLogger

from .events import emit_crypto_event
from .handshake import SessionKeys


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

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    @staticmethod
    def _canonical_ticket_body(ticket: Dict[str, object]) -> bytes:
        body = {
            "session_id": ticket["session_id"],
            "peer_identity": ticket["peer_identity"],
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
            "peer_device": peer_device,
            "original_transcript_hash": original_transcript_hash,
            "expiry": expiry,
            "resumption_key_id": resumption_key_id,
        }
        mac = hmac.new(
            resumption_secret,
            b"track4/v1/ticket\x00" + self._canonical_ticket_body(ticket),
            hashlib.sha256,
        ).hexdigest()
        ticket["mac"] = mac

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

    @staticmethod
    def create_proof_of_possession(
        resumption_secret: bytes,
        fresh_nonce: bytes,
        new_transcript_hash: str,
    ) -> str:
        """Compute proof of possession over fresh nonce and new handshake transcript."""
        msg = b"track4/v1/resume-pop\x00" + fresh_nonce + new_transcript_hash.encode("utf-8")
        return hmac.new(resumption_secret, msg, hashlib.sha256).hexdigest()

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

            # 1. Peer binding check BEFORE any key derivation
            if (
                presented_identity != bound_id
                or presented_device != bound_dev
                or ticket.get("peer_identity") != bound_id
                or ticket.get("peer_device") != bound_dev
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

            # 4. Verify ticket MAC
            expected_mac = hmac.new(
                res_secret,
                b"track4/v1/ticket\x00" + self._canonical_ticket_body(ticket),
                hashlib.sha256,
            ).hexdigest()
            if not hmac.compare_digest(str(ticket.get("mac", "")), expected_mac):
                raise ResumptionError("Resumption ticket MAC invalid")

            # 5. Verify Proof of Possession over fresh nonce + new transcript
            expected_pop = self.create_proof_of_possession(res_secret, fresh_nonce, new_transcript_hash)
            if not hmac.compare_digest(proof_of_possession, expected_pop):
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
