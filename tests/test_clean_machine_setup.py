"""Regression guard for clean-machine setup (P0-4)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


def test_makefile_setup_creates_venv_and_targets_use_it() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    assert "PYTHON ?= .venv/bin/python" in makefile
    assert "-m venv $(VENV)" in makefile
    assert "install -r requirements.txt" in makefile
    assert "install -r requirements-dev.txt" in makefile
    assert "core.hooksPath .githooks" in makefile
    for target in ("test:", "gates:", "bench:", "demo:"):
        assert target in makefile
    # `make test` must exercise the repository-root scope, not only tests/.
    assert "$(PYTHON) -m pytest . -q" in makefile


@pytest.mark.parametrize("use_path", [True, False])
def test_demo_script_runs_selected_interpreter(tmp_path, use_path: bool) -> None:
    interpreter = tmp_path / "test-python"
    interpreter.write_text("#!/bin/sh\nprintf 'selected interpreter\\n' >&2\nexit 73\n")
    interpreter.chmod(0o755)
    result = subprocess.run(
        ["bash", "scripts/run_demo.sh"],
        env={**os.environ, "PATH": f"{tmp_path}:{os.environ['PATH']}",
             "PYTHON": interpreter.name if use_path else str(interpreter)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 73
    assert "selected interpreter" in result.stderr


def test_demo_script_fails_closed_without_interpreter(tmp_path) -> None:
    interpreter = tmp_path / "missing-python"
    result = subprocess.run(
        ["bash", "scripts/run_demo.sh"],
        env={**os.environ, "PYTHON": str(interpreter)},
        capture_output=True,
        text=True,
    )
    assert result.returncode == 1
    assert f"Python interpreter '{interpreter}' not found" in result.stderr
    assert "Run 'make setup' first" in result.stderr


def test_readme_documents_python_311_and_venv_path() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "Python 3.11" in readme
    assert "python3.11 -m venv .venv" in readme
    assert ".venv/bin/python -m pytest . -q" in readme
