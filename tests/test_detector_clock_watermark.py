"""Ingestion-sequence tiebreak and release watermark.

Objective 8 previously ordered equal timestamps arbitrarily (heap compared
`timestamp_ns` only) and had no watermark, so a future-dated event was released
as soon as the hold window elapsed.
"""

from __future__ import annotations

import src.detector.clock_sync as cs


def _use_time(monkeypatch, now: float) -> None:
    monkeypatch.setattr(cs.time, "time", lambda: now)


def test_equal_timestamps_preserve_ingestion_order(monkeypatch) -> None:
    now = 1_800_000_100.0
    _use_time(monkeypatch, now)
    buffer = cs.ClockSyncBuffer(hold_window_seconds=0.0)
    ts = int((now - 100) * 1e9)
    names = ["first", "second", "third", "fourth"]
    for name in names:
        buffer.ingest({"event_id": name, "timestamp_ns": ts})

    events = buffer.pop_ready_events()
    assert [e.event_id for e in events] == names
    assert [e.data["_ingestion_seq"] for e in events] == [1, 2, 3, 4]


def test_future_event_held_until_watermark_advances(monkeypatch) -> None:
    now = 1_800_000_100.0
    _use_time(monkeypatch, now)
    buffer = cs.ClockSyncBuffer(hold_window_seconds=0.5)
    future_ts = int((now + 3600) * 1e9)
    buffer.ingest({"event_id": "future", "timestamp_ns": future_ts})

    _use_time(monkeypatch, now + 0.6)
    assert [e.event_id for e in buffer.pop_ready_events()] == []

    # Explicitly advancing the watermark past the event releases it.
    buffer.advance_watermark(future_ts)
    assert [e.event_id for e in buffer.pop_ready_events()] == ["future"]


def test_ancient_event_released_only_after_hold(monkeypatch) -> None:
    now = 1_800_000_100.0
    _use_time(monkeypatch, now)
    buffer = cs.ClockSyncBuffer(hold_window_seconds=0.5)
    buffer.ingest({"event_id": "ancient", "timestamp_ns": int((now - 86400) * 1e9)})

    _use_time(monkeypatch, now + 0.1)
    assert buffer.pop_ready_events() == []

    _use_time(monkeypatch, now + 0.6)
    assert [e.event_id for e in buffer.pop_ready_events()] == ["ancient"]


def test_watermark_is_monotonic(monkeypatch) -> None:
    _use_time(monkeypatch, 1_800_000_100.0)
    buffer = cs.ClockSyncBuffer(hold_window_seconds=0.0)
    assert buffer.watermark == 0

    buffer.advance_watermark(500)
    assert buffer.watermark == 500
    buffer.set_watermark(100)  # backwards is ignored
    assert buffer.watermark == 500
    buffer.advance_watermark(900)
    assert buffer.watermark == 900


def test_force_all_still_drains_future_events(monkeypatch) -> None:
    now = 1_800_000_100.0
    _use_time(monkeypatch, now)
    buffer = cs.ClockSyncBuffer(hold_window_seconds=0.5)
    buffer.ingest({"event_id": "future", "timestamp_ns": int((now + 3600) * 1e9)})
    assert [e.event_id for e in buffer.pop_ready_events(force_all=True)] == ["future"]
