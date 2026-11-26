"""Regression tests for the P3 polish batch."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_api_uses_lifespan_instead_of_deprecated_on_event() -> None:
    source = (ROOT / "src/identity_keys/api.py").read_text(encoding="utf-8")
    assert "on_event(" not in source
    assert "lifespan=lifespan" in source
    assert "sync_mgr.start_heartbeat()" in source
    assert "sync_mgr.stop_heartbeat()" in source


def test_make_clean_removes_tool_caches() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "find . -type d -name __pycache__" in makefile
    assert ".mypy_cache" in makefile
    assert ".ruff_cache" in makefile


def test_gitignore_covers_tool_caches() -> None:
    text = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for entry in (".mypy_cache/", ".ruff_cache/", ".pytest_cache/"):
        assert entry in text, entry


def test_demo_e2e_uses_matching_mldsa_backup_keys() -> None:
    source = (ROOT / "scripts/demo_e2e.py").read_text(encoding="utf-8")
    assert "from pqcrypto.sign import ml_dsa_65" in source
    assert "sig_keygen(ml_dsa_65)" in source
    assert "bpub, bpriv = generate_ed25519_keypair()" not in source
