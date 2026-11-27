"""Regression guard for clean-machine setup (P0-4)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest


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
