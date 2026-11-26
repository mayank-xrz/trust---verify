"""Regression guard for the generated project brief (P0-5)."""

from __future__ import annotations

import re
from pathlib import Path


def test_brief_has_no_dead_demo_url() -> None:
    for name in ("docs/project_brief.html", "docs/project_brief.pdf"):
        data = Path(name).read_bytes()
        assert b"trust-but-verify.dev/demo-walkthrough" not in data


def test_brief_html_marks_video_pending_without_env() -> None:
    text = Path("docs/project_brief.html").read_text(encoding="utf-8")
    assert "Demo video:" in text
    assert "pending" in text
    assert "docs/DEMO_VIDEO.md" in text


def test_brief_pdf_is_two_pages() -> None:
    data = Path("docs/project_brief.pdf").read_bytes()
    counts = re.findall(rb"/Count\s+(\d+)", data)
    assert counts and int(counts[0]) == 2


def test_brief_uses_measured_source_and_labels_synthetic_data() -> None:
    text = Path("docs/project_brief.html").read_text(encoding="utf-8")
    assert "reports/measurements.json" in text
    assert "docs/MEASUREMENTS.md" in text
    assert "synthetic only" in text.lower()
    assert "production-grade" not in text.lower()
    assert "zero-dependency" not in text.lower()
