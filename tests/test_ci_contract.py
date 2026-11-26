"""Regression tests for the CI gate contract (P2-1)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_ci_workflow_runs_the_same_gates_as_make() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    for command in (
        "python -m ruff check .",
        "python -m mypy",
        "python -m src.cli verify-logs",
        "python -m pytest . -q",
    ):
        assert command in workflow, command


def test_ci_matrix_covers_linux_and_macos_on_python_311() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "ubuntu-latest" in workflow
    assert "macos-latest" in workflow
    assert '"3.11"' in workflow
    assert "fail-fast: false" in workflow


def test_ci_validates_compose_with_generated_secrets() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "docker compose config" in workflow
    assert "POSTGRES_PASSWORD" in workflow
    # The workflow must generate values, not commit them.
    assert "openssl rand" in workflow


def test_dev_requirements_pin_the_gate_tools() -> None:
    text = (ROOT / "requirements-dev.txt").read_text(encoding="utf-8")
    assert "-r requirements.txt" in text
    assert "ruff==" in text
    assert "mypy==" in text
