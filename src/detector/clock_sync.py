"""Out-of-Order Buffering, Clock Skew Tolerance & Uncertainty Flags."""

from __future__ import annotations

import dataclasses
import enum
import heapq
import time
from typing import Any, Dict, List


class SkewStatus(str, enum.Enum):
    NORMAL = "NORMAL"
    UNCERTAIN_TIMING = "UNCERTAIN_TIMING"
    CLOCK_SKEW_EXCEEDED = "CLOCK_SKEW_EXCEEDED"


@dataclasses.dataclass
class BufferedEvent:
    timestamp_ns: int
    arrival_time_sec: float
    event_id: str
    data: Dict[str, Any]
    skew_status: SkewStatus = SkewStatus.NORMAL
    skew_ms: float = 0.0
    ingestion_seq: int = 0

    def __lt__(self, other: "BufferedEvent") -> bool:
        # Order by event time, then by ingestion sequence so equal timestamps
        # preserve the order in which they arrived.
        return (self.timestamp_ns, self.ingestion_seq) < (
            other.timestamp_ns,
            other.ingestion_seq,
        )


class ClockSyncBuffer:
    """Buffers distributed audit events to absorb network jitter and clock skew.

    Events are held for `hold_window_seconds` before being released in strict chronological order.
    """

    def __init__(
        self,
        hold_window_seconds: float = 0.5,
        max_skew_ms: float = 2000.0,
        uncertainty_skew_ms: float = 500.0,
    ):
        self.hold_window_seconds = hold_window_seconds
        self.max_skew_ms = max_skew_ms
        self.uncertainty_skew_ms = uncertainty_skew_ms
        # Min-heap by (timestamp_ns, ingestion_seq): List[BufferedEvent]
        self._heap: List[BufferedEvent] = []
        self._ingestion_seq = 0
        # Highest event-time watermark (ns) that may be released.  Events with a
        # timestamp beyond the watermark are held until the watermark advances
        # (explicitly or as local wall-clock time catches up).
        self.watermark: int = 0

    def advance_watermark(self, timestamp_ns: int) -> int:
        """Advance the release watermark monotonically; never moves backwards."""
        self.watermark = max(self.watermark, int(timestamp_ns))
        return self.watermark

    def set_watermark(self, timestamp_ns: int) -> int:
        """Alias for :meth:`advance_watermark` (monotonic)."""
        return self.advance_watermark(timestamp_ns)

    def ingest(self, event_data: Dict[str, Any]) -> BufferedEvent:
        """Ingests an event, computes skew relative to local wall clock, and attaches uncertainty flags."""
        now_sec = time.time()
        event_ts_sec = event_data.get("timestamp_ns", 0) / 1_000_000_000.0
        skew_ms = abs(now_sec - event_ts_sec) * 1000.0

        if skew_ms > self.max_skew_ms:
            status = SkewStatus.CLOCK_SKEW_EXCEEDED
        elif skew_ms > self.uncertainty_skew_ms:
            status = SkewStatus.UNCERTAIN_TIMING
        else:
            status = SkewStatus.NORMAL

        event_data_copy = dict(event_data)
        event_data_copy["_skew_status"] = status.value
        event_data_copy["_skew_ms"] = round(skew_ms, 2)
        self._ingestion_seq += 1
        event_data_copy["_ingestion_seq"] = self._ingestion_seq

        be = BufferedEvent(
            timestamp_ns=event_data.get("timestamp_ns", int(now_sec * 1_000_000_000)),
            arrival_time_sec=now_sec,
            event_id=event_data.get("event_id", ""),
            data=event_data_copy,
            skew_status=status,
            skew_ms=skew_ms,
            ingestion_seq=self._ingestion_seq,
        )

        heapq.heappush(self._heap, be)
        return be

    def pop_ready_events(self, force_all: bool = False) -> List[BufferedEvent]:
        """Releases events that have been buffered longer than hold_window_seconds in monotonic order.

        Unless ``force_all`` is set, an event is released only if it has also
        fallen at or below the release watermark.  A future-dated event stays
        buffered until the watermark advances past it, so it cannot be emitted
        immediately just because the hold window elapsed.
        """
        ready = []
        now_sec = time.time()
        now_ns = int(now_sec * 1_000_000_000)
        effective_watermark = max(self.watermark, now_ns)

        while self._heap:
            oldest = self._heap[0]
            if not force_all:
                if now_sec - oldest.arrival_time_sec < self.hold_window_seconds:
                    break
                if oldest.timestamp_ns > effective_watermark:
                    # The heap is ordered by event time, so every remaining
                    # event is at or beyond this future timestamp.
                    break
            ready.append(heapq.heappop(self._heap))

        return ready

    def pending_count(self) -> int:
        return len(self._heap)
