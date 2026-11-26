"""Regression guard for clean-machine setup (P0-4)."""

from __future__ import annotations

from pathlib import Path


def test_makefile_setup_creates_venv_and_targets_use_it() -> None:
    makefile = Path("Makefile").read_text(encoding="utf-8")
    assert "PYTHON ?= .venv/bin/python" in makefile
    assert "-m venv $(VENV)" in makefile
    assert "install -r requirements.txt" in makefile
    assert "core.hooksPath .githooks" in makefile
    for target in ("test:", "gates:", "bench:", "demo:"):
        assert target in makefile
    # `make test` must exercise the repository-root scope, not only tests/.
    assert "$(PYTHON) -m pytest . -q" in makefile


def test_demo_script_uses_project_interpreter_and_fails_closed() -> None:
    script = Path("scripts/run_demo.sh").read_text(encoding="utf-8")
    assert 'PYTHON="${PYTHON:-$REPO_ROOT/.venv/bin/python}"' in script
    assert 'if [ ! -x "$PYTHON" ]' in script
    assert "Run 'make setup' first" in script
    assert "python3 -m" not in script


def test_readme_documents_python_311_and_venv_path() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "Python 3.11" in readme
    assert "python3.11 -m venv .venv" in readme
    assert ".venv/bin/python -m pytest . -q" in readme
