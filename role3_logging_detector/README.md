# Track 4 — Role 3: Logging & Explainable Detection

> **Archived sub-project.** This directory is retained for provenance and is
> excluded from the root pytest run. See [../docs/ARCHIVED.md](../docs/ARCHIVED.md).
> The canonical implementation lives in `src/`.

Beginner-friendly, zero-dependency Python module for **Track 4 ("Trust, but verify")** covering:
- **Injection-proof, hash-chained `.jsonl` audit logging + verifier CLI** ([src/audit_logger.py](src/audit_logger.py))
- **Rule + graph-based detector with clock-skew handling** ([src/detector.py](src/detector.py))
- **F1, MTTA, and FP/1k evaluation** ([src/metrics.py](src/metrics.py))
- **XERJ integration** (indexes logs into `track4-audit` and alerts into `track4-alerts` on `http://127.0.0.1:9200`)

See [EXPLAIN_FOR_JUDGES.md](EXPLAIN_FOR_JUDGES.md) for a quick, plain-English guide on how to explain each piece.

## Quick Start

```bash
# 1. Run unit tests (works offline, zero dependencies)
python3 -m unittest discover -s tests -v

# 2. Run the demo (writes demo_audit.jsonl, verifies chain, detects alerts, pushes to XERJ)
python3 -m src.cli demo

# 3. Verify any audit log file
python3 -m src.cli verify-logs demo_audit.jsonl

# 4. Evaluate F1, MTTA, and false alerts per 1,000 benign events
python3 -m src.cli evaluate sample_logs/labelled_events.jsonl
```
