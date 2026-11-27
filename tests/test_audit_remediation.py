"""Regression tests backing docs/audit-remediation-ledger.md.

Each test name matches the ``Test`` column in the ledger so the documented
remediation claims are executable rather than aspirational.
"""

from __future__ import annotations

import ast
import base64
import tomllib
from pathlib import Path

from pqcrypto.kem import ml_kem_768

from src.crypto._pqcrypto_compat import kem_keygen
from src.crypto.protected_read import protected_read

ROOT = Path(__file__).resolve().parents[1]


def test_requirements_pin() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    assert "pqcrypto==0.4.0" in requirements.splitlines()
    with (ROOT / "pyproject.toml").open("rb") as file:
        project = tomllib.load(file).get("project", {})
    if "dependencies" in project:
        assert "pqcrypto==0.4.0" in project["dependencies"]
    unpinned = [
        line.strip()
        for line in requirements.splitlines()
        if line.strip()
        and not line.strip().startswith("#")
        and not line.strip().startswith("-")
        and "==" not in line
    ]
    assert unpinned == [], f"unpinned requirements: {unpinned}"


def test_requirements_demo() -> None:
    demo = (ROOT / "requirements-demo.txt").read_text(encoding="utf-8")
    assert "-r requirements.txt" in demo


def test_protected_read_response() -> None:
    public_key, _secret_key = kem_keygen(ml_kem_768)
    result = protected_read(
        "challenge",
        "stored body",
        base64.b64encode(public_key).decode("ascii"),
    )
    assert set(result) == {"ciphertext", "proof"}
    base64.b64decode(result["ciphertext"], validate=True)
    assert len(result["proof"]) == 64
    int(result["proof"], 16)


def test_root_imports() -> None:
    tree = ast.parse((ROOT / "track4_service.py").read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    assert "sqlalchemy" not in imported
    assert "alembic" not in imported


def test_single_crypto_stack() -> None:
    offenders = [
        path
        for path in (ROOT / "src" / "crypto").rglob("*.py")
        if "pqc_kem" in path.read_text(encoding="utf-8")
    ]
    assert offenders == []


def test_makefile_fallback() -> None:
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    assert "fallback active" not in makefile


def test_readme_badge() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "pytest tests/ -v" in readme
    assert "26/26 Passing" not in readme


def test_naming_consistency() -> None:
    suite = "ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1"
    primitives = (ROOT / "src" / "crypto" / "primitives.py").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert suite in primitives
    assert suite in readme
