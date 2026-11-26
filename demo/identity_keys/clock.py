"""Injectable timezone-aware UTC clock abstraction for deterministic testing."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Protocol


class Clock(Protocol):
    """Clock interface providing UTC timestamps and monotonic nanoseconds."""

    def now(self) -> datetime:
        """Return current timezone-aware UTC datetime."""
        ...

    def monotonic_ns(self) -> int:
        """Return monotonic clock reading in nanoseconds."""
        ...


class SystemClock:
    """Production wall + monotonic clock."""

    def now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic_ns(self) -> int:
        return time.monotonic_ns()


class FakeClock:
    """Deterministic controllable clock for unit and integration tests."""

    def __init__(
        self,
        initial: datetime | None = None,
        initial_monotonic_ns: int = 1_000_000_000,
    ) -> None:
        self._now = initial or datetime(2026, 11, 26, 12, 0, 0, tzinfo=timezone.utc)
        if self._now.tzinfo is None:
            self._now = self._now.replace(tzinfo=timezone.utc)
        self._mono_ns = initial_monotonic_ns

    def now(self) -> datetime:
        return self._now

    def monotonic_ns(self) -> int:
        return self._mono_ns

    def advance(self, seconds: float = 0.0, milliseconds: float = 0.0) -> datetime:
        """Advance both UTC wall clock and monotonic clock."""
        delta_s = seconds + (milliseconds / 1000.0)
        self._now = self._now + timedelta(seconds=delta_s)
        self._mono_ns += int(delta_s * 1_000_000_000)
        return self._now
