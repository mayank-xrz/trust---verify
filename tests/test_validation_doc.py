"""Regression tests for docs/VALIDATION.md (P2-4)."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs/VALIDATION.md"


def _text() -> str:
    return DOC.read_text(encoding="utf-8")


def test_validation_doc_covers_every_gate_command() -> None:
    text = _text()
    for command in ("make setup", "make gates", "make demo", "make bench", "make brief"):
        assert command in text, command


def test_validation_doc_has_scope_and_limitations() -> None:
    text = _text()
    assert "## 1. What is validated" in text
    assert "## 7. What is **not** validated" in text
    for limitation in ("Production scale", "Real network partitions", "PostgreSQL", "synthetic"):
        assert limitation in text, limitation
    assert "DEMO_VIDEO_URL" in text


def test_validation_doc_references_only_existing_tests() -> None:
    referenced = set(re.findall(r"`(tests/[A-Za-z0-9_/]+\.py)`", _text()))
    assert referenced, "expected at least one test reference"
    missing = sorted(path for path in referenced if not (ROOT / path).is_file())
    assert not missing, missing


def test_validation_doc_references_only_existing_docs() -> None:
    referenced = set(re.findall(r"`(docs/[A-Za-z0-9_/]+\.(?:md|html|pdf))`", _text()))
    assert referenced, "expected at least one doc reference"
    missing = sorted(path for path in referenced if not (ROOT / path).is_file())
    assert not missing, missing


def test_readme_links_the_validation_guide() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "docs/VALIDATION.md" in readme
