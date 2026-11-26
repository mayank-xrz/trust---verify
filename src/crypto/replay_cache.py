"""SQLite replay cache and durable outbound counter reservations."""
import os
from pathlib import Path
import sqlite3
from contextlib import contextmanager

from .primitives import CryptoError


class ReplayCache:
    def __init__(self, path, window=256):
        if type(window) is not int or window < 2:
            raise CryptoError("invalid replay window")
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.window = window
        with self._db() as db:
            db.execute("CREATE TABLE IF NOT EXISTS outbound (session TEXT, sender TEXT, recipient TEXT, next_counter INTEGER NOT NULL, PRIMARY KEY(session,sender,recipient))")
            db.execute("CREATE TABLE IF NOT EXISTS highest (session TEXT, sender TEXT, recipient TEXT, counter INTEGER NOT NULL, PRIMARY KEY(session,sender,recipient))")
            db.execute("CREATE TABLE IF NOT EXISTS seen (session TEXT, sender TEXT, recipient TEXT, message_id TEXT, counter INTEGER, PRIMARY KEY(session,sender,recipient,message_id,counter))")
            db.execute("CREATE UNIQUE INDEX IF NOT EXISTS seen_counter ON seen(session,sender,recipient,counter)")
            db.execute("CREATE TABLE IF NOT EXISTS sealed (session TEXT, sender TEXT, message_id TEXT, chunk_index INTEGER, PRIMARY KEY(session,sender,message_id,chunk_index))")
        os.chmod(self.path, 0o600)

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        db.execute("PRAGMA busy_timeout=10000")
        try:
            yield db
            if db.in_transaction:
                db.commit()
        except Exception:
            if db.in_transaction:
                db.rollback()
            raise
        finally:
            db.close()

    def reserve_send(self, session, sender, recipient, message_id, chunk_index):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            if db.execute("SELECT 1 FROM sealed WHERE session=? AND sender=? AND message_id=? AND chunk_index=?", (session,sender,message_id,chunk_index)).fetchone():
                raise CryptoError("message chunk already sealed")
            row = db.execute("SELECT next_counter FROM outbound WHERE session=? AND sender=? AND recipient=?", (session,sender,recipient)).fetchone()
            counter = row[0] if row else 0
            if counter >= 2**96:
                raise CryptoError("outbound counter exhausted")
            db.execute("INSERT INTO outbound VALUES (?,?,?,?) ON CONFLICT(session,sender,recipient) DO UPDATE SET next_counter=excluded.next_counter", (session,sender,recipient,counter+1))
            db.execute("INSERT INTO sealed VALUES (?,?,?,?)", (session,sender,message_id,chunk_index))
            db.execute("COMMIT")
            return counter

    def _reason(self, db, session, sender, recipient, message_id, counter):
        if type(counter) is not int or counter < 0:
            return "counter_out_of_window"
        if db.execute("SELECT 1 FROM seen WHERE session=? AND sender=? AND recipient=? AND message_id=? AND counter=?", (session,sender,recipient,message_id,counter)).fetchone():
            return "replay_rejected"
        if db.execute("SELECT 1 FROM seen WHERE session=? AND sender=? AND recipient=? AND counter=?", (session,sender,recipient,counter)).fetchone():
            return "replay_rejected"
        row = db.execute("SELECT counter FROM highest WHERE session=? AND sender=? AND recipient=?", (session,sender,recipient)).fetchone()
        highest = row[0] if row else -1
        if counter > highest + self.window or counter < max(0, highest - self.window + 1):
            return "counter_out_of_window"
        return None

    def check(self, session, sender, recipient, message_id, counter):
        with self._db() as db:
            return self._reason(db, session, sender, recipient, message_id, counter)

    def mark(self, session, sender, recipient, message_id, counter):
        with self._db() as db:
            db.execute("BEGIN IMMEDIATE")
            reason = self._reason(db, session, sender, recipient, message_id, counter)
            if reason:
                raise CryptoError(reason)
            db.execute("INSERT INTO seen VALUES (?,?,?,?,?)", (session,sender,recipient,message_id,counter))
            row = db.execute("SELECT counter FROM highest WHERE session=? AND sender=? AND recipient=?", (session,sender,recipient)).fetchone()
            if row is None or counter > row[0]:
                db.execute("INSERT INTO highest VALUES (?,?,?,?) ON CONFLICT(session,sender,recipient) DO UPDATE SET counter=excluded.counter", (session,sender,recipient,counter))
            db.execute("COMMIT")
