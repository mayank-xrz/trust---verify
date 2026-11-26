"""Persistent SQLite-backed replay cache with per-session sliding counter window.

Keyed by (sender_identity, recipient_identity, session_id, message_id, counter)
so restarts do not reopen a replay window.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Callable, Optional


class ReplayRejectedError(Exception):
    """Raised when a duplicate message or counter is replayed."""
    reason = "replay_rejected"


class CounterOutOfWindowError(Exception):
    """Raised when a counter falls outside the per-session sliding window."""
    reason = "counter_out_of_window"


class PersistentReplayCache:
    """SQLite-backed replay cache with per-session sliding counter window."""

    def __init__(self, db_path: str | Path, window_size: int = 256) -> None:
        if window_size < 1:
            raise ValueError("window_size must be >= 1")
        self.db_path = Path(db_path)
        self.window_size = window_size
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS seen_messages (
                    sender_identity TEXT NOT NULL,
                    recipient_identity TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    PRIMARY KEY (sender_identity, recipient_identity, session_id, message_id, counter)
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS session_counters (
                    sender_identity TEXT NOT NULL,
                    recipient_identity TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    PRIMARY KEY (sender_identity, recipient_identity, session_id, counter)
                )
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS session_max_counter (
                    sender_identity TEXT NOT NULL,
                    recipient_identity TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    max_counter INTEGER NOT NULL,
                    PRIMARY KEY (sender_identity, recipient_identity, session_id)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def check_and_record(
        self,
        sender_identity: str,
        recipient_identity: str,
        session_id: str,
        message_id: str,
        counter: int,
        *,
        on_accept: Optional[Callable[[sqlite3.Connection], None]] = None,
    ) -> None:
        """Persist replay state and any associated delivery in the same transaction."""
        if type(counter) is not int or counter < 0:
            raise CounterOutOfWindowError(f"Invalid negative or non-int counter: {counter}")

        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")

            # 1. Check exact replay key
            dup = db.execute(
                """
                SELECT 1 FROM seen_messages
                WHERE sender_identity=? AND recipient_identity=? AND session_id=?
                  AND message_id=? AND counter=?
                """,
                (sender_identity, recipient_identity, session_id, message_id, counter),
            ).fetchone()
            if dup is not None:
                raise ReplayRejectedError(
                    f"Duplicate message rejected: session={session_id} message_id={message_id} counter={counter}"
                )

            # 2. Check sliding counter window for this session
            row = db.execute(
                """
                SELECT max_counter FROM session_max_counter
                WHERE sender_identity=? AND recipient_identity=? AND session_id=?
                """,
                (sender_identity, recipient_identity, session_id),
            ).fetchone()
            max_counter: Optional[int] = row[0] if row is not None else None

            if max_counter is not None:
                lower_bound = max_counter - self.window_size + 1
                if counter < lower_bound:
                    raise CounterOutOfWindowError(
                        f"Counter {counter} outside sliding window [{lower_bound}, {max_counter}]"
                    )

                seen_ctr = db.execute(
                    """
                    SELECT 1 FROM session_counters
                    WHERE sender_identity=? AND recipient_identity=? AND session_id=? AND counter=?
                    """,
                    (sender_identity, recipient_identity, session_id, counter),
                ).fetchone()
                if seen_ctr is not None:
                    raise ReplayRejectedError(
                        f"Duplicate counter {counter} in session {session_id}"
                    )

            # 3. Record message key and counter
            db.execute(
                """
                INSERT INTO seen_messages (sender_identity, recipient_identity, session_id, message_id, counter)
                VALUES (?, ?, ?, ?, ?)
                """,
                (sender_identity, recipient_identity, session_id, message_id, counter),
            )
            db.execute(
                """
                INSERT INTO session_counters (sender_identity, recipient_identity, session_id, counter)
                VALUES (?, ?, ?, ?)
                """,
                (sender_identity, recipient_identity, session_id, counter),
            )

            new_max = counter if max_counter is None or counter > max_counter else max_counter
            db.execute(
                """
                INSERT INTO session_max_counter (sender_identity, recipient_identity, session_id, max_counter)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(sender_identity, recipient_identity, session_id)
                DO UPDATE SET max_counter=excluded.max_counter
                """,
                (sender_identity, recipient_identity, session_id, new_max),
            )

            # Prune counters below sliding window
            prune_below = new_max - self.window_size + 1
            db.execute(
                """
                DELETE FROM session_counters
                WHERE sender_identity=? AND recipient_identity=? AND session_id=? AND counter < ?
                """,
                (sender_identity, recipient_identity, session_id, prune_below),
            )
            if on_accept is not None:
                on_accept(db)
