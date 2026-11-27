"""Durable ciphertext inbox and replay protection for one demo node."""

import hashlib
import json
import os
import sqlite3
import uuid
from contextlib import closing
from pathlib import Path
from typing import Any

from demo.node.crypto_provider import SIGNED_ENVELOPE_FIELDS
from src.crypto.replay_cache import PersistentReplayCache, ReplayRejectedError


class RecipientInbox:
    def __init__(self, path: Path, node_id: str) -> None:
        self.path = path
        self.node_id = node_id
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        self.replay_cache = PersistentReplayCache(path)
        with closing(sqlite3.connect(path)) as db, db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS deliveries (
                    receipt_id TEXT PRIMARY KEY,
                    sender_id TEXT NOT NULL,
                    recipient_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    envelope TEXT NOT NULL,
                    sender_public_key BLOB NOT NULL,
                    UNIQUE (sender_id, recipient_id, message_id)
                )
                """
            )

            db.execute(
                """
                CREATE TABLE IF NOT EXISTS revoked_peer_keys (
                    peer_id TEXT NOT NULL,
                    key_id TEXT NOT NULL,
                    PRIMARY KEY (peer_id, key_id)
                )
                """
            )

    def revoke_peer_key(self, peer_id: str, key_id: str) -> None:
        self.revoke_peer_keys(peer_id, [key_id])

    def revoke_peer_keys(self, peer_id: str, key_ids: list[str]) -> None:
        if key_ids:
            with closing(sqlite3.connect(self.path)) as db, db:
                db.executemany(
                    "INSERT OR IGNORE INTO revoked_peer_keys VALUES (?, ?)",
                    ((peer_id, key_id) for key_id in key_ids),
                )

    def is_peer_key_revoked(self, peer_id: str, key_id: str) -> bool:
        with closing(sqlite3.connect(self.path)) as db:
            return db.execute(
                "SELECT 1 FROM revoked_peer_keys WHERE peer_id=? AND key_id=?", (peer_id, key_id)
            ).fetchone() is not None

    def accept(self, envelope: dict[str, Any], sender_public_key: bytes) -> str:
        """Record an authenticated envelope and its replay state as one delivery."""
        receipt_id = uuid.uuid4().hex
        sender_id = envelope["sender_id"]
        message_id = envelope["message_id"]
        # The demo numbers outgoing messages per peer and process signing identity.
        signer_fingerprint = hashlib.sha256(sender_public_key).hexdigest()
        encoded = json.dumps({
            field: envelope[field] for field in (*SIGNED_ENVELOPE_FIELDS, "signature") if field in envelope
        })

        def store(db: sqlite3.Connection) -> None:
            result = db.execute(
                """
                INSERT INTO deliveries VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT (sender_id, recipient_id, message_id) DO NOTHING
                """,
                (receipt_id, sender_id, self.node_id, message_id, encoded, sender_public_key),
            )
            if result.rowcount != 1:
                raise ReplayRejectedError("Duplicate message rejected")

        self.replay_cache.check_and_record(
            sender_id, self.node_id, signer_fingerprint, message_id, envelope["sequence_number"],
            on_accept=store,
        )
        return receipt_id

    def get(self, receipt_id: str) -> tuple[dict[str, Any], bytes] | None:
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute(
                "SELECT envelope, sender_public_key FROM deliveries WHERE receipt_id=? AND recipient_id=?",
                (receipt_id, self.node_id),
            ).fetchone()
        return (json.loads(row[0]), bytes(row[1])) if row is not None else None
