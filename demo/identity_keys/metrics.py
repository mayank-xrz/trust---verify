"""Latency percentile statistics using coordinator monotonic_ns()."""

from __future__ import annotations

import math
from typing import Any


def percentile(sorted_vals: list[float], pct: float) -> float:
    """Compute linear-interpolated percentile from a sorted list."""
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    k = (len(sorted_vals) - 1) * (pct / 100.0)
    f = math.floor(k)
    c = math.ceil(k)
    if f == c:
        return sorted_vals[int(k)]
    return sorted_vals[f] * (c - k) + sorted_vals[c] * (k - f)


def summarize_latencies_ms(samples_ms: list[float]) -> dict[str, Any]:
    """Return min, median, p95, p99, max in milliseconds."""
    s = sorted(samples_ms)
    if not s:
        return {
            "count": 0,
            "min_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "p99_ms": 0.0,
            "max_ms": 0.0,
        }
    return {
        "count": len(s),
        "min_ms": round(s[0], 3),
        "median_ms": round(percentile(s, 50.0), 3),
        "p95_ms": round(percentile(s, 95.0), 3),
        "p99_ms": round(percentile(s, 99.0), 3),
        "max_ms": round(s[-1], 3),
    }
