"""Reproducible performance measurements for the shipped paths.

Methodology (P0-3 / P2-3):
- 50 warm-up iterations per benchmark, then 3 independent measured runs.
- Each run reports p50/p95/p99 latency and throughput; the table reports the
  median across the 3 runs.
- Memory uses ``resource.getrusage(RUSAGE_SELF).ru_maxrss`` (RSS) in addition
  to ``tracemalloc`` for Python allocations.
- The envelope and ML-KEM/ML-DSA paths are the shipped ``src/crypto`` code.
- Revocation uses the shipped DB-backed ``src/identity_keys/revocation.py`` via
  ``scripts/measure_revocation.py`` (TestClient + SQLite, 5 ms probe).
- Detector accuracy is reported only for the **synthetic** labelled set from
  ``scripts/eval_detector.py`` and is labelled as such.

Limitations (do not over-claim):
- These are single-host, in-process microbenchmarks. They exclude HTTP/TLS,
  serialization, network, and database round-trips except where noted.
- p99 from a few hundred samples is a coarse tail estimate; run-to-run spread
  is reported so readers can see the noise.
- No confidence intervals or cross-machine comparisons are claimed. Re-run on
  the target host before quoting a number for capacity planning.

Outputs:
- ``reports/measurements.json`` — machine-readable results + provenance.
- ``docs/MEASUREMENTS.md`` — human-readable source of truth.
- The marked block in ``README.md`` is regenerated from the same results.

Run:
    .venv/bin/python scripts/benchmark.py
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import resource
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Any, Callable, Dict, List

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.eval_detector import run_evaluation  # noqa: E402
from src.crypto.envelope import open_envelope, seal_envelope  # noqa: E402
from src.crypto.primitives import (  # noqa: E402
    decapsulate,
    encapsulate,
    kem_keypair,
    sign,
    signing_keypair,
    verify,
)
from src.detector.rules import ContextRuleEngine  # noqa: E402

WARMUP = 50
RUNS = 3
README_START = "<!-- BENCHMARK:START -->"
README_END = "<!-- BENCHMARK:END -->"


def percentile(data: List[float], p: float) -> float:
    if not data:
        return 0.0
    ordered = sorted(data)
    k = (len(ordered) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c < len(ordered):
        return ordered[f] + (k - f) * (ordered[c] - ordered[f])
    return ordered[f]


def _median(values: List[float]) -> float:
    ordered = sorted(values)
    n = len(ordered)
    if n == 0:
        return 0.0
    mid = n // 2
    if n % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _rss_mb() -> float:
    usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # macOS reports bytes; Linux reports KiB.
    if sys.platform == "darwin":
        return usage / (1024.0 * 1024.0)
    return usage / 1024.0


def _cpu_name() -> str:
    if sys.platform == "darwin":
        try:
            return subprocess.check_output(
                ["sysctl", "-n", "machdep.cpu.brand_string"], text=True
            ).strip()
        except Exception:
            pass
    return platform.processor() or "unknown"


def _git_commit() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True
        ).strip()
    except Exception:
        return "unknown"


def _node_version() -> str:
    try:
        return subprocess.check_output(["node", "--version"], text=True).strip()
    except Exception:
        return "unavailable"


def provenance() -> Dict[str, Any]:
    return {
        "date_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit": _git_commit(),
        "os": platform.platform(),
        "cpu": _cpu_name(),
        "python": sys.version.split()[0],
        "node": _node_version(),
        "command": ".venv/bin/python scripts/benchmark.py",
        "warmup_iterations": WARMUP,
        "measured_runs": RUNS,
        "statistic": "median of per-run p50/p95/p99 and throughput",
    }


def _summarise(latencies: List[float], iterations: int, elapsed_s: float) -> Dict[str, float]:
    return {
        "p50_ms": round(percentile(latencies, 50), 4),
        "p95_ms": round(percentile(latencies, 95), 4),
        "p99_ms": round(percentile(latencies, 99), 4),
        "mean_ms": round(sum(latencies) / len(latencies), 4),
        "throughput_ops_sec": round(iterations / elapsed_s, 2) if elapsed_s > 0 else 0.0,
    }


def measure_operation(
    name: str,
    operation: Callable[[], Any],
    iterations: int,
    *,
    warmup: int = WARMUP,
    runs: int = RUNS,
) -> Dict[str, Any]:
    """Warm up, then measure ``iterations`` across ``runs`` and take medians."""
    print(f"▶ {name}: warmup={warmup}, runs={runs}, iterations={iterations}")
    for _ in range(warmup):
        operation()

    run_summaries: List[Dict[str, float]] = []
    for _ in range(runs):
        latencies: List[float] = []
        started = time.perf_counter()
        for _ in range(iterations):
            t0 = time.perf_counter()
            operation()
            latencies.append((time.perf_counter() - t0) * 1000.0)
        elapsed = time.perf_counter() - started
        run_summaries.append(_summarise(latencies, iterations, elapsed))

    return {
        "iterations_per_run": iterations,
        "warmup_iterations": warmup,
        "runs": runs,
        "p50_ms": round(_median([r["p50_ms"] for r in run_summaries]), 4),
        "p95_ms": round(_median([r["p95_ms"] for r in run_summaries]), 4),
        "p99_ms": round(_median([r["p99_ms"] for r in run_summaries]), 4),
        "mean_ms": round(_median([r["mean_ms"] for r in run_summaries]), 4),
        "throughput_ops_sec": round(_median([r["throughput_ops_sec"] for r in run_summaries]), 2),
        "per_run": run_summaries,
    }


def benchmark_envelope(iterations: int = 200) -> Dict[str, Any]:
    """Seal and open the shipped ``src/crypto/envelope.py`` path."""
    signing_pub, signing_sk = signing_keypair()
    session_key = os.urandom(32)
    payload = b'{"operation":"SECURE_TRANSFER","amount":5000,"currency":"USD"}'
    counter = 0

    def make_envelope() -> Dict[str, Any]:
        nonlocal counter
        counter += 1
        return seal_envelope(
            sender_identity="node-a",
            sender_device="dev-a",
            recipient_identity="node-b",
            recipient_device="dev-b",
            session_id="bench-session",
            session_key=session_key,
            signing_secret_key=signing_sk,
            plaintext=payload,
            counter=counter,
            message_id=f"bench-msg-{counter}",
        )

    seal_result = measure_operation("envelope seal (ML-DSA-65 + AES-256-GCM)", make_envelope, iterations)

    # Build one envelope per iteration and measure open separately.
    print(f"▶ envelope open (verify + decrypt): warmup={WARMUP}, runs={RUNS}, iterations={iterations}")
    envelopes = [make_envelope() for _ in range(WARMUP + RUNS * iterations)]
    idx = 0
    for _ in range(WARMUP):
        open_envelope(
            envelopes[idx],
            local_identity="node-b",
            local_device="dev-b",
            session_key=session_key,
            sender_public_key=signing_pub,
            check_replay=False,
        )
        idx += 1

    open_runs: List[Dict[str, float]] = []
    roundtrip_runs: List[Dict[str, float]] = []
    for _ in range(RUNS):
        open_lat: List[float] = []
        roundtrip_lat: List[float] = []
        started = time.perf_counter()
        for _ in range(iterations):
            envelope = envelopes[idx]
            idx += 1
            t0 = time.perf_counter()
            open_envelope(
                envelope,
                local_identity="node-b",
                local_device="dev-b",
                session_key=session_key,
                sender_public_key=signing_pub,
                check_replay=False,
            )
            dt = (time.perf_counter() - t0) * 1000.0
            open_lat.append(dt)
            roundtrip_lat.append(dt)
        elapsed = time.perf_counter() - started
        open_runs.append(_summarise(open_lat, iterations, elapsed))
        roundtrip_runs.append(_summarise(roundtrip_lat, iterations, elapsed))

    def med(runs: List[Dict[str, float]], key: str) -> float:
        return round(_median([r[key] for r in runs]), 4)

    return {
        "path": "src/crypto/envelope.py",
        "seal": seal_result,
        "open": {
            "iterations_per_run": iterations,
            "warmup_iterations": WARMUP,
            "runs": RUNS,
            "p50_ms": med(open_runs, "p50_ms"),
            "p95_ms": med(open_runs, "p95_ms"),
            "p99_ms": med(open_runs, "p99_ms"),
            "mean_ms": med(open_runs, "mean_ms"),
            "throughput_ops_sec": med(open_runs, "throughput_ops_sec"),
            "per_run": open_runs,
        },
    }


def benchmark_kem(iterations: int = 200) -> Dict[str, Any]:
    def exchange() -> None:
        public_key, secret_key = kem_keypair()
        ciphertext, _secret = encapsulate(public_key)
        decapsulate(secret_key, ciphertext)

    result = measure_operation("ML-KEM-768 keygen+encaps+decaps", exchange, iterations)
    result["path"] = "src/crypto/primitives.py (pqcrypto ML-KEM-768)"
    return result


def benchmark_signature(iterations: int = 200) -> Dict[str, Any]:
    public_key, secret_key = signing_keypair()
    transcript = {"operation": "BENCHMARK_TRANSACTION_PAYLOAD", "amount": 5000}

    def sign_and_verify() -> None:
        signature = sign(secret_key, "track4/v1/bench", transcript)
        verify(public_key, "track4/v1/bench", transcript, signature)

    result = measure_operation("ML-DSA-65 sign+verify", sign_and_verify, iterations)
    result["path"] = "src/crypto/primitives.py (pqcrypto ML-DSA-65)"
    return result


def benchmark_detector(iterations: int = 5000) -> Dict[str, Any]:
    """Throughput of the deterministic rule engine on routine events."""
    base = 1_700_000_000.0

    def build_events() -> List[Dict[str, Any]]:
        return [
            {
                "event_id": f"bench-{i}",
                "timestamp_ns": int((base + i) * 1_000_000_000),
                "subject": f"user-{i % 25}",
                "service": "api-gateway",
                "resource": f"/items/{i}",
                "action": "GET_ITEM",
                "status": "SUCCESS",
                "metadata": {"role": "user"},
            }
            for i in range(iterations)
        ]

    print(f"▶ detector rule evaluation: warmup={WARMUP}, runs={RUNS}, iterations={iterations}")
    warm_event = {
        "event_id": "bench-warm",
        "timestamp_ns": int(base * 1_000_000_000),
        "subject": "user-0",
        "service": "api-gateway",
        "resource": "/items/0",
        "action": "GET_ITEM",
        "status": "SUCCESS",
        "metadata": {"role": "user"},
    }
    for _ in range(WARMUP):
        ContextRuleEngine().evaluate_event(warm_event)

    run_summaries: List[Dict[str, float]] = []
    for _ in range(RUNS):
        engine = ContextRuleEngine()
        events = build_events()
        started = time.perf_counter()
        for event in events:
            engine.evaluate_event(event)
        elapsed = time.perf_counter() - started
        run_summaries.append(
            {
                "throughput_events_sec": round(iterations / elapsed, 2) if elapsed else 0.0,
                "latency_per_event_us": round(elapsed / iterations * 1e6, 4),
            }
        )

    return {
        "path": "src/detector/rules.py",
        "iterations_per_run": iterations,
        "warmup_iterations": WARMUP,
        "runs": RUNS,
        "throughput_events_sec": round(
            _median([r["throughput_events_sec"] for r in run_summaries]), 2
        ),
        "latency_per_event_us": round(
            _median([r["latency_per_event_us"] for r in run_summaries]), 4
        ),
        "per_run": run_summaries,
    }


def benchmark_revocation(m_runs: int = 20) -> Dict[str, Any]:
    """Shipped DB-backed revocation path via scripts/measure_revocation.py."""
    from scripts.measure_revocation import run_scenario

    print(f"▶ shipped DB revocation propagation (TestClient/SQLite, M={m_runs})")
    result = run_scenario(
        name="push_plus_pull",
        m_runs=m_runs,
        push_sync=True,
        pull_interval_ms=250,
        seed=42,
    )
    overall = result["overall_last_node"]
    return {
        "path": "src/identity_keys/revocation.py",
        "method": (
            "Single-coordinator time.monotonic_ns() from commit to the last of 3 nodes "
            "denying with DEVICE_REVOKED; 5 ms parallel probe; TestClient + SQLite on one host."
        ),
        "m_runs": m_runs,
        "cluster_nodes": 3,
        "p50_ms": overall["median_ms"],
        "p95_ms": overall["p95_ms"],
        "p99_ms": overall["p99_ms"],
        "min_ms": overall["min_ms"],
        "max_ms": overall["max_ms"],
        "per_node": result["per_node"],
    }


def measure_memory(iterations: int = 200) -> Dict[str, Any]:
    """RSS high-water and tracemalloc peak for the envelope path."""
    signing_pub, signing_sk = signing_keypair()
    session_key = os.urandom(32)
    payload = b"MEMORY_BENCHMARK_PAYLOAD"
    rss_before = _rss_mb()
    tracemalloc.start()
    tracemalloc.reset_peak()
    for i in range(iterations):
        envelope = seal_envelope(
            sender_identity="node-a",
            sender_device="dev-a",
            recipient_identity="node-b",
            recipient_device="dev-b",
            session_id="mem-session",
            session_key=session_key,
            signing_secret_key=signing_sk,
            plaintext=payload,
            counter=i,
            message_id=f"mem-{i}",
        )
        open_envelope(
            envelope,
            local_identity="node-b",
            local_device="dev-b",
            session_key=session_key,
            sender_public_key=signing_pub,
            check_replay=False,
        )
    _current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    rss_after = _rss_mb()
    return {
        "method": "resource.getrusage(RUSAGE_SELF).ru_maxrss + tracemalloc peak",
        "iterations": iterations,
        "rss_before_mb": round(rss_before, 3),
        "rss_after_mb": round(rss_after, 3),
        "rss_delta_mb": round(max(0.0, rss_after - rss_before), 3),
        "tracemalloc_peak_mb": round(peak / (1024.0 * 1024.0), 3),
        "note": "RSS is a process high-water mark and includes imports; delta may be 0 after allocator reuse.",
    }


def _fmt(value: float) -> str:
    return f"{value:.2f}"


def _spread(block: Dict[str, Any]) -> str:
    """Return the min-max p50 across measured runs, or an em dash."""
    runs = block.get("per_run") or []
    p50s = [r["p50_ms"] for r in runs if "p50_ms" in r]
    if not p50s:
        return "—"
    return f"{min(p50s):.4f}–{max(p50s):.4f} ms"


def render_markdown(results: Dict[str, Any]) -> str:
    prov = results["provenance"]
    env = results["envelope"]
    kem = results["kem"]
    sig = results["signature"]
    rev = results["revocation"]
    det = results["detector"]
    ev = results["detector_eval"]
    mem = results["memory"]
    cm = ev["confusion_matrix"]
    return f"""{README_START}
<!-- generated by scripts/benchmark.py; do not edit by hand -->
## Performance & detection measurements

Single source of truth: [`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md) and
[`reports/measurements.json`](reports/measurements.json). Method: {prov['warmup_iterations']}
warm-up iterations, {prov['measured_runs']} measured runs, median of per-run
p50/p95/p99 and throughput. Measured {prov['date_utc']} on {prov['cpu']},
{prov['os']}, Python {prov['python']}, Node {prov['node']}, commit
`{prov['commit']}`. Run `.venv/bin/python scripts/benchmark.py` to reproduce.
These are single-host, in-process microbenchmarks; see
[`docs/MEASUREMENTS.md`](docs/MEASUREMENTS.md) for methodology, run-to-run
spread, and limitations.

| Component | Path | p50 | p95 | p99 | Throughput |
| :--- | :--- | ---: | ---: | ---: | ---: |
| Envelope seal (ML-DSA-65 + AES-256-GCM) | `src/crypto/envelope.py` | {_fmt(env['seal']['p50_ms'])} ms | {_fmt(env['seal']['p95_ms'])} ms | {_fmt(env['seal']['p99_ms'])} ms | {_fmt(env['seal']['throughput_ops_sec'])} ops/s |
| Envelope open (verify + decrypt) | `src/crypto/envelope.py` | {_fmt(env['open']['p50_ms'])} ms | {_fmt(env['open']['p95_ms'])} ms | {_fmt(env['open']['p99_ms'])} ms | {_fmt(env['open']['throughput_ops_sec'])} ops/s |
| ML-KEM-768 keygen + encaps + decaps | `src/crypto/primitives.py` | {_fmt(kem['p50_ms'])} ms | {_fmt(kem['p95_ms'])} ms | {_fmt(kem['p99_ms'])} ms | {_fmt(kem['throughput_ops_sec'])} ops/s |
| ML-DSA-65 sign + verify | `src/crypto/primitives.py` | {_fmt(sig['p50_ms'])} ms | {_fmt(sig['p95_ms'])} ms | {_fmt(sig['p99_ms'])} ms | {_fmt(sig['throughput_ops_sec'])} ops/s |
| Revocation propagation (3 nodes) | `src/identity_keys/revocation.py` | {_fmt(rev['p50_ms'])} ms | {_fmt(rev['p95_ms'])} ms | {_fmt(rev['p99_ms'])} ms | M={rev['m_runs']} |
| Detector rule evaluation | `src/detector/rules.py` | — | — | — | {_fmt(det['throughput_events_sec'])} events/s |

**Detector accuracy is synthetic only.** The {ev['events']}-event labelled set
is hand-built for rule regression tests, not a production corpus. Confusion
matrix: TP={cm['tp']}, FP={cm['fp']}, TN={cm['tn']}, FN={cm['fn']}; precision
{ev['precision']:.2f}, recall {ev['recall']:.2f}, F1 {ev['f1']:.2f}, FP/1k
{ev['false_positives_per_1k']:.2f}. See `scripts/eval_detector.py`.

Memory: RSS high-water {_fmt(mem['rss_after_mb'])} MB
(delta {_fmt(mem['rss_delta_mb'])} MB), tracemalloc peak
{_fmt(mem['tracemalloc_peak_mb'])} MB for {mem['iterations']} seal/open
operations. RSS includes imports and is a high-water mark.
<!-- BENCHMARK:END -->"""


def write_measurements(results: Dict[str, Any]) -> None:
    reports = REPO_ROOT / "reports"
    reports.mkdir(exist_ok=True)
    (reports / "measurements.json").write_text(
        json.dumps(results, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    prov = results["provenance"]
    env = results["envelope"]
    kem = results["kem"]
    sig = results["signature"]
    rev = results["revocation"]
    det = results["detector"]
    ev = results["detector_eval"]
    mem = results["memory"]
    cm = ev["confusion_matrix"]
    md = f"""# Measurements

This file is the single source of truth for performance numbers quoted in the
README, brief, and reports. It is generated by `scripts/benchmark.py`; do not
hand-edit the table.

## Provenance

- Date (UTC): {prov['date_utc']}
- Commit: `{prov['commit']}`
- Command: `{prov['command']}`
- OS: {prov['os']}
- CPU: {prov['cpu']}
- Python: {prov['python']}
- Node: {prov['node']}
- Method: {prov['warmup_iterations']} warm-up iterations, {prov['measured_runs']}
  measured runs, median of per-run p50/p95/p99 and throughput.

## Shipped paths

| Component | Path | p50 | p95 | p99 | Throughput |
| :--- | :--- | ---: | ---: | ---: | ---: |
| Envelope seal (ML-DSA-65 + AES-256-GCM) | `src/crypto/envelope.py` | {_fmt(env['seal']['p50_ms'])} ms | {_fmt(env['seal']['p95_ms'])} ms | {_fmt(env['seal']['p99_ms'])} ms | {_fmt(env['seal']['throughput_ops_sec'])} ops/s |
| Envelope open (verify + decrypt) | `src/crypto/envelope.py` | {_fmt(env['open']['p50_ms'])} ms | {_fmt(env['open']['p95_ms'])} ms | {_fmt(env['open']['p99_ms'])} ms | {_fmt(env['open']['throughput_ops_sec'])} ops/s |
| ML-KEM-768 keygen + encaps + decaps | `src/crypto/primitives.py` | {_fmt(kem['p50_ms'])} ms | {_fmt(kem['p95_ms'])} ms | {_fmt(kem['p99_ms'])} ms | {_fmt(kem['throughput_ops_sec'])} ops/s |
| ML-DSA-65 sign + verify | `src/crypto/primitives.py` | {_fmt(sig['p50_ms'])} ms | {_fmt(sig['p95_ms'])} ms | {_fmt(sig['p99_ms'])} ms | {_fmt(sig['throughput_ops_sec'])} ops/s |
| Revocation propagation (3 nodes) | `src/identity_keys/revocation.py` | {_fmt(rev['p50_ms'])} ms | {_fmt(rev['p95_ms'])} ms | {_fmt(rev['p99_ms'])} ms | M={rev['m_runs']} |
| Detector rule evaluation | `src/detector/rules.py` | — | — | — | {_fmt(det['throughput_events_sec'])} events/s |

Revocation method: {rev['method']}

## Run-to-run spread (p50)

| Component | p50 range across runs |
| :--- | ---: |
| Envelope seal | {_spread(env['seal'])} |
| Envelope open | {_spread(env['open'])} |
| ML-KEM-768 | {_spread(kem)} |
| ML-DSA-65 | {_spread(sig)} |
| Revocation (all probes) | {_fmt(rev['min_ms'])}–{_fmt(rev['max_ms'])} ms |

## Methodology & limitations

- **In-process microbenchmarks.** Each operation is called directly in this
  Python process. The numbers exclude HTTP/TLS, serialization, network, and
  database round-trips except where explicitly noted.
- **Warm-up and runs.** {prov['warmup_iterations']} warm-up iterations per
  benchmark, then {prov['measured_runs']} independent measured runs. p50/p95/p99
  are computed within each run and the table reports the median across runs.
  Throughput is iterations divided by wall-clock time for the run.
- **Tail estimates are coarse.** p99 is derived from a few hundred samples per
  run. Treat it as an order-of-magnitude tail indicator, not a precise SLA.
- **Single host.** All numbers come from one machine ({prov['cpu']},
  {prov['os']}). CPU frequency scaling, background load, and the Python build
  affect results. Re-run `scripts/benchmark.py` on the target host; do not treat
  these as universal constants.
- **Revocation is local.** {rev['method']}
- **Detector accuracy is synthetic only.** The labelled set is hand-built for
  rule regression tests, not a production corpus.
- **Memory is a high-water mark.** RSS includes imports; the delta can be zero
  after allocator reuse. `tracemalloc` covers Python allocations only.
- **No confidence intervals.** No statistical significance or cross-machine
  comparison is claimed.

## Detector evaluation (SYNTHETIC ONLY)

The dataset is **synthetic** and hand-labelled; it is not a real-world corpus.
Do not cite these numbers as production accuracy.

| Truth \\ Prediction | Alert | Normal |
| :--- | ---: | ---: |
| Attack | {cm['tp']} (TP) | {cm['fn']} (FN) |
| Normal | {cm['fp']} (FP) | {cm['tn']} (TN) |

- Events: {ev['events']} (100 routine, 25 attack)
- Precision: {ev['precision']:.4f}
- Recall: {ev['recall']:.4f}
- F1: {ev['f1']:.4f}
- False positives per 1k: {ev['false_positives_per_1k']:.4f}
- Mean per-event evaluation latency: {ev['mtta_ms']:.4f} ms

## Memory

- Method: {mem['method']}
- RSS before: {_fmt(mem['rss_before_mb'])} MB
- RSS high-water after: {_fmt(mem['rss_after_mb'])} MB
- RSS delta: {_fmt(mem['rss_delta_mb'])} MB
- tracemalloc peak: {_fmt(mem['tracemalloc_peak_mb'])} MB
- Iterations: {mem['iterations']}
- Note: {mem['note']}
"""
    (REPO_ROOT / "docs" / "MEASUREMENTS.md").write_text(md, encoding="utf-8")


def update_readme(results: Dict[str, Any]) -> None:
    readme = REPO_ROOT / "README.md"
    text = readme.read_text(encoding="utf-8")
    block = render_markdown(results)
    start = text.find(README_START)
    end = text.find(README_END)
    if start == -1 or end == -1 or end < start:
        print("README benchmark markers not found; skipping README update.")
        return
    updated = text[:start] + block + text[end + len(README_END) :]
    readme.write_text(updated, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Measure the shipped paths.")
    parser.add_argument("--quick", action="store_true", help="smaller iteration counts for a smoke run")
    args = parser.parse_args()
    scale = 0.2 if args.quick else 1.0
    envelope_iterations = max(20, int(200 * scale))
    prim_iterations = max(20, int(200 * scale))
    detector_iterations = max(500, int(5000 * scale))
    revocation_runs = 5 if args.quick else 20

    print("=" * 72)
    print("TRUST-BUT-VERIFY MEASUREMENTS (shipped paths)")
    print("=" * 72)

    rss_start = _rss_mb()
    results: Dict[str, Any] = {
        "provenance": provenance(),
        "methodology": {
            "warmup_iterations": WARMUP,
            "measured_runs": RUNS,
            "statistic": "median of per-run p50/p95/p99 and throughput",
            "memory": "resource.getrusage(RUSAGE_SELF).ru_maxrss + tracemalloc",
            "detector_accuracy": "synthetic labelled dataset only",
            "scope": "single-host in-process microbenchmarks; excludes network/HTTP/DB except where noted",
            "tail_estimate": "p99 is coarse for a few hundred samples per run",
            "confidence_intervals": "none claimed; no cross-machine comparison",
            "spread": "per-run p50 range reported in docs/MEASUREMENTS.md",
        },
        "envelope": benchmark_envelope(envelope_iterations),
        "kem": benchmark_kem(prim_iterations),
        "signature": benchmark_signature(prim_iterations),
        "detector": benchmark_detector(detector_iterations),
        "revocation": benchmark_revocation(revocation_runs),
        "detector_eval": run_evaluation(),
        "memory": measure_memory(envelope_iterations),
    }
    results["rss_start_mb"] = round(rss_start, 3)
    results["rss_end_mb"] = round(_rss_mb(), 3)

    write_measurements(results)
    update_readme(results)
    print(render_markdown(results))
    print(f"Wrote {REPO_ROOT / 'reports' / 'measurements.json'}")
    print(f"Wrote {REPO_ROOT / 'docs' / 'MEASUREMENTS.md'}")
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
