"""Peer-bound, one-use, persistent resumption tickets."""
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import sqlite3
import time
from contextlib import closing

from .handshake import derive
from .primitives import CryptoError, b64, canonical


class ResumptionRejected(CryptoError): pass


class TicketStore:
    def __init__(self, path, events):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.events = events
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                db.execute("CREATE TABLE IF NOT EXISTS tickets (session_id TEXT PRIMARY KEY, key_id TEXT, secret BLOB, peer_identity TEXT, peer_device TEXT, transcript_hash TEXT, expiry INTEGER, used INTEGER)")
        os.chmod(self.path, 0o600)

    @staticmethod
    def proof(secret, ticket, nonce):
        return hmac.new(secret, b"track4/v2/resume-proof\x00" + nonce + canonical(ticket), hashlib.sha256).hexdigest()

    def issue(self, session, peer_identity, peer_device, lifetime=300):
        if (peer_identity, peer_device) not in ((session.initiator, session.initiator_device),
                                               (session.responder, session.responder_device)) or session.root is None:
            raise CryptoError("invalid resumption peer")
        if type(lifetime) is not int or lifetime <= 0:
            raise CryptoError("invalid ticket lifetime")
        secret = derive(session.root, bytes.fromhex(session.transcript_hash), b"track4/v2/resumption-secret")
        ticket = {"session_id": session.session_id, "peer_identity": peer_identity,
                  "peer_device": peer_device, "original_transcript_hash": session.transcript_hash,
                  "expiry": int(time.time()) + lifetime,
                  "resumption_key_id": secrets.token_hex(16)}
        ticket["mac"] = self.proof(secret, ticket, b"ticket")
        with closing(sqlite3.connect(self.path)) as db:
            with db:
                db.execute("INSERT INTO tickets VALUES (?,?,?,?,?,?,?,0)",
                           (session.session_id, ticket["resumption_key_id"], secret, peer_identity,
                            peer_device, session.transcript_hash, ticket["expiry"]))
        return ticket, secret

    def _reject(self, action, ticket, presented_identity, bound_identity):
        self.events.emit(action, "deny", actor=presented_identity,
                         source_service=presented_identity, target_service=bound_identity,
                         session_id=str(ticket.get("session_id", "")), reason=action)
        raise ResumptionRejected(action)

    def resume(self, ticket, presented_identity, presented_device, nonce, proof,
               claimed_transcript_hash=None):
        if not isinstance(ticket, dict):
            raise ResumptionRejected("invalid ticket")
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT key_id,secret,peer_identity,peer_device,transcript_hash,expiry,used FROM tickets WHERE session_id=?", (ticket.get("session_id"),)).fetchone()
            if row is None:
                self._reject("resumption_expired", ticket, presented_identity, "")
            key_id, secret, bound_identity, bound_device, original_hash, expiry, used = row
            # This check precedes MAC verification and every key derivation.
            if (presented_identity, presented_device) != (bound_identity, bound_device):
                self._reject("resumption_peer_mismatch", ticket, presented_identity, bound_identity)
            if used:
                self._reject("resumption_replayed", ticket, presented_identity, bound_identity)
            if expiry <= time.time() or ticket.get("expiry") != expiry:
                self._reject("resumption_expired", ticket, presented_identity, bound_identity)
            if (ticket.get("resumption_key_id") != key_id or ticket.get("original_transcript_hash") != original_hash or
                claimed_transcript_hash not in (None, original_hash)):
                self._reject("resumption_peer_mismatch", ticket, presented_identity, bound_identity)
            unsigned = {k: v for k, v in ticket.items() if k != "mac"}
            expected_mac = self.proof(secret, unsigned, b"ticket")
            if not isinstance(ticket.get("mac"), str) or not hmac.compare_digest(ticket["mac"], expected_mac):
                self._reject("resumption_peer_mismatch", ticket, presented_identity, bound_identity)
            if not isinstance(nonce, bytes) or len(nonce) < 16 or not isinstance(proof, str) or not hmac.compare_digest(proof, self.proof(secret, ticket, nonce)):
                self._reject("resumption_peer_mismatch", ticket, presented_identity, bound_identity)
            db.execute("UPDATE tickets SET used=1 WHERE session_id=?", (ticket["session_id"],))
            db.execute("COMMIT")
        finally:
            if db.in_transaction:
                db.rollback()
            db.close()
        new_id = secrets.token_hex(16)
        new_transcript = {"original_session_id": ticket["session_id"], "session_id": new_id,
                          "peer_identity": presented_identity, "peer_device": presented_device,
                          "nonce": b64(nonce), "original_transcript_hash": original_hash}
        new_hash = hashlib.sha256(canonical(new_transcript)).digest()
        new_root = derive(secret + new_hash, nonce, b"track4/v2/resumed-session-root")
        self.events.emit("resumption_accepted", "allow", actor=presented_identity,
                         source_service=presented_identity, target_service=bound_identity,
                         session_id=ticket["session_id"])
        return new_id, new_root, new_transcript
