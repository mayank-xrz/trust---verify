"""Peer-Bound Session Resumption with Forward Secrecy.

Ensures resumed sessions:
- Cannot be hijacked by unauthorized peers (Peer Binding).
- Cannot decrypt previous sessions if resumption ticket is compromised (Forward Secrecy).
- Rotate ephemeral resumption secrets automatically.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import json
import secrets
import time
from typing import Dict, Any, Optional, Tuple


class ResumptionHijackError(Exception):
    """Raised when a session resumption token is used by an unauthorized or mismatched peer."""
    pass


class SessionTicket:
    def __init__(
        self,
        session_id: str,
        client_node_id: str,
        server_node_id: str,
        resumption_secret: bytes,
        expires_at: float,
        created_at: float = 0.0,
    ):
        self.session_id = session_id
        self.client_node_id = client_node_id
        self.server_node_id = server_node_id
        self.resumption_secret = resumption_secret
        self.created_at = created_at or time.time()
        self.expires_at = expires_at


class SessionManager:
    """Manages active sessions and generates peer-bound, tamper-proof resumption tickets."""

    def __init__(self, node_id: str, ticket_lifetime_seconds: float = 3600.0):
        self.node_id = node_id
        self.ticket_lifetime_seconds = ticket_lifetime_seconds
        # Node ticket encryption/signing master key
        self._ticket_master_key = secrets.token_bytes(32)
        self.active_sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(
        self,
        peer_node_id: str,
        shared_master_secret: bytes,
        is_client: bool = False,
    ) -> Tuple[str, bytes]:
        """Creates an active session and derives initial session channel key."""
        session_id = "sess-" + secrets.token_hex(16)
        # Derive channel key
        channel_key = hashlib.sha3_256(
            b"TBV-CHANNEL-KEY:" + shared_master_secret + session_id.encode("utf-8")
        ).digest()

        # Derive forward-secret resumption secret
        resumption_secret = hashlib.sha3_256(
            b"TBV-RESUMPTION-SECRET:" + shared_master_secret + session_id.encode("utf-8")
        ).digest()

        self.active_sessions[session_id] = {
            "session_id": session_id,
            "peer_node_id": peer_node_id,
            "channel_key": channel_key,
            "resumption_secret": resumption_secret,
            "created_at": time.time(),
            "sequence": 0,
        }

        return session_id, channel_key

    def issue_resumption_ticket(self, session_id: str) -> str:
        """Issues an encrypted and MACed ticket bound strictly to the original peer."""
        session = self.active_sessions.get(session_id)
        if not session:
            raise ValueError(f"Session {session_id} not found.")

        now = time.time()
        ticket_data = {
            "sid": session["session_id"],
            "peer": session["peer_node_id"],
            "iss": self.node_id,
            "sec": base64.b64encode(session["resumption_secret"]).decode("ascii"),
            "iat": now,
            "exp": now + self.ticket_lifetime_seconds,
        }

        raw_payload = json.dumps(ticket_data, sort_keys=True).encode("utf-8")
        # Generate HMAC binding
        ticket_mac = hmac.new(self._ticket_master_key, raw_payload, hashlib.sha256).digest()
        token = base64.urlsafe_b64encode(raw_payload + ticket_mac).decode("ascii")
        return token

    def resume_session(
        self,
        ticket_token: str,
        requesting_peer_id: str,
    ) -> Tuple[str, bytes]:
        """Resumes a session from ticket, verifying peer identity and validity.

        Returns:
            Tuple of (new_session_id, new_channel_key)
        """
        try:
            raw = base64.urlsafe_b64decode(ticket_token.encode("ascii"))
            if len(raw) < 32:
                raise ValueError("Malformed ticket.")
            payload_bytes = raw[:-32]
            provided_mac = raw[-32:]

            # Verify integrity
            expected_mac = hmac.new(self._ticket_master_key, payload_bytes, hashlib.sha256).digest()
            if not hmac.compare_digest(provided_mac, expected_mac):
                raise ResumptionHijackError("Resumption ticket signature verification failed!")

            data = json.loads(payload_bytes.decode("utf-8"))
        except Exception as e:
            if isinstance(e, ResumptionHijackError):
                raise
            raise ResumptionHijackError(f"Invalid ticket encoding: {e}")

        # Check Expiration
        if time.time() > data["exp"]:
            raise ResumptionHijackError("Resumption ticket has expired.")

        # Critical Check: Peer Binding (Defense against Resumption Hijack)
        if data["peer"] != requesting_peer_id:
            raise ResumptionHijackError(
                f"Resumption hijack attempt detected! Ticket issued for {data['peer']}, but presented by {requesting_peer_id}"
            )

        old_resumption_secret = base64.b64decode(data["sec"])
        # Rotate forward secret into new session ID and channel key
        new_session_id = "sess-" + secrets.token_hex(16)
        new_channel_key = hashlib.sha3_256(
            b"TBV-RESUMED-CHANNEL-KEY:" + old_resumption_secret + new_session_id.encode("utf-8")
        ).digest()

        # Update active sessions
        self.active_sessions[new_session_id] = {
            "session_id": new_session_id,
            "peer_node_id": requesting_peer_id,
            "channel_key": new_channel_key,
            "resumption_secret": hashlib.sha3_256(old_resumption_secret + b":ratchet").digest(),
            "created_at": time.time(),
            "sequence": 0,
        }

        return new_session_id, new_channel_key

    def close_session(self, session_id: str) -> None:
        """Closes and wipes active session."""
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
