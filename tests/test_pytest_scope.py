"""Regression guard for the root pytest scope (P0-6)."""

from __future__ import annotations

from pathlib import Path


def test_root_pytest_excludes_archived_subprojects() -> None:
    config = Path("pyproject.toml").read_text(encoding="utf-8")
    for archived in ("role3_logging_detector", "prototypes"):
        assert f'"{archived}"' in config
        assert f"--ignore={archived}" in config
    assert Path("docs/ARCHIVED.md").exists()
