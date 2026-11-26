"""Persistent bounded replay ledger, scoped to sender, recipient, and session."""
import sqlite3
from pathlib import Path

from .primitives import CryptoError


class ReplayLedger:
    def __init__(self, path, max_per_session=100000, max_rows=1000000):
        self.path = Path(path)
        self.max_per_session = max_per_session
        self.max_rows = max_rows
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute("CREATE TABLE IF NOT EXISTS seen (session TEXT, sender TEXT, recipient TEXT, epoch INTEGER, counter INTEGER, PRIMARY KEY(session,sender,recipient,epoch,counter))")
            db.execute("CREATE TABLE IF NOT EXISTS completed_transfers (session TEXT, sender TEXT, recipient TEXT, transfer_id TEXT, PRIMARY KEY(session,sender,recipient,transfer_id))")

    def _connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.execute("PRAGMA busy_timeout=5000")
        return db

    def mark(self, session, sender, recipient, counter, epoch=0):
        if type(counter) is not int or not 0 <= counter < self.max_per_session:
            raise CryptoError("message counter outside supported range")
        if type(epoch) is not int or epoch < 0:
            raise CryptoError("invalid key epoch")
        db = self._connect()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                if db.execute("SELECT COUNT(*) FROM seen WHERE session=?", (session,)).fetchone()[0] >= self.max_rows:
                    raise CryptoError("replay ledger capacity reached")
                try:
                    db.execute("INSERT INTO seen VALUES (?,?,?,?,?)", (session, sender, recipient, epoch, counter))
                except sqlite3.IntegrityError as exc:
                    raise CryptoError("replay rejected") from exc
        finally:
            db.close()

    def mark_transfer(self, session, sender, recipient, transfer_id):
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT COUNT(*) FROM completed_transfers").fetchone()[0] >= self.max_rows:
                raise CryptoError("transfer ledger capacity reached")
            try:
                db.execute("INSERT INTO completed_transfers VALUES (?,?,?,?)",
                           (session, sender, recipient, transfer_id))
            except sqlite3.IntegrityError as exc:
                raise CryptoError("completed transfer replay rejected") from exc

    def transfer_completed(self, session, sender, recipient, transfer_id):
        with self._connect() as db:
            return db.execute("SELECT 1 FROM completed_transfers WHERE session=? AND sender=? AND recipient=? AND transfer_id=?",
                              (session, sender, recipient, transfer_id)).fetchone() is not None
