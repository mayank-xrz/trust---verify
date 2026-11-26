"""Regression tests for benchmark methodology and single-source-of-truth (P2-3)."""

from __future__ import annotations

import json
from pathlib import Path

from scripts.benchmark import README_END, README_START, render_markdown

ROOT = Path(__file__).resolve().parents[1]


def _results() -> dict:
    return json.loads((ROOT / "reports/measurements.json").read_text(encoding="utf-8"))


def test_provenance_is_complete_and_traceable() -> None:
    prov = _results()["provenance"]
    for key in ("date_utc", "commit", "os", "cpu", "python", "node", "command"):
        assert prov.get(key), key
    assert prov["command"] == ".venv/bin/python scripts/benchmark.py"
    assert prov["warmup_iterations"] > 0
    assert prov["measured_runs"] > 1


def test_methodology_declares_scope_and_limitations() -> None:
    method = _results()["methodology"]
    assert "single-host" in method["scope"]
    assert "synthetic" in method["detector_accuracy"]
    assert "p99" in method["tail_estimate"]
    assert "none" in method["confidence_intervals"]
    assert "per-run" in method["spread"]


def test_measurements_doc_renders_methodology_and_spread() -> None:
    text = (ROOT / "docs/MEASUREMENTS.md").read_text(encoding="utf-8")
    assert "## Methodology & limitations" in text
    assert "## Run-to-run spread (p50)" in text
    assert "In-process microbenchmarks" in text
    assert "Single host" in text
    assert "synthetic" in text.lower()
    assert "No confidence intervals" in text


def test_readme_block_is_generated_not_hand_edited() -> None:
    results = _results()
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    start = readme.index(README_START)
    end = readme.index(README_END) + len(README_END)
    assert readme[start:end] == render_markdown(results)


def test_measurements_doc_provenance_matches_json() -> None:
    results = _results()
    prov = results["provenance"]
    text = (ROOT / "docs/MEASUREMENTS.md").read_text(encoding="utf-8")
    assert prov["commit"] in text
    assert prov["date_utc"] in text
    assert prov["cpu"] in text
    assert prov["python"] in text
    assert prov["node"] in text
