"""Static hardening checks for the Docker sandbox (P1-4).

Docker is not required to run the Python suite; these assertions check the
compose/Dockerfile contract. Runtime `docker compose up` remains a manual or CI
job on a Docker-capable host.
"""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _compose() -> dict:
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


def test_compose_requires_secrets_and_has_no_working_defaults() -> None:
    text = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    for var in (
        "POSTGRES_PASSWORD",
        "WRAP_MASTER_KEY_B64",
        "CLUSTER_SYNC_SECRET",
        "TOKEN_SIGNING_SEED_B64",
        "ADMIN_ENROLL_TOKEN",
        "DEMO_CLUSTER_KEY_B64",
    ):
        assert f"${{{var}:?" in text, var
    assert "tbv_dev_only" not in text
    assert "|| true" not in text
    assert "dockerfile_inline" not in text


def test_compose_ports_bind_to_localhost() -> None:
    for name, service in _compose()["services"].items():
        for mapping in service.get("ports", []):
            assert str(mapping).startswith("127.0.0.1:"), (name, mapping)


def test_app_services_run_hardened() -> None:
    services = _compose()["services"]
    for name in ("migrate", "key-authority", "detector", "node-a", "node-b", "node-c"):
        svc = services[name]
        assert svc.get("read_only") is True, name
        assert "/tmp" in svc.get("tmpfs", []), name
        assert "no-new-privileges:true" in svc.get("security_opt", []), name
        assert "ALL" in svc.get("cap_drop", []), name
        assert svc.get("init") is True, name


def test_identity_nodes_wait_for_migration() -> None:
    services = _compose()["services"]
    assert services["migrate"]["command"] == ["alembic", "upgrade", "head"]
    for name in ("node-a", "node-b", "node-c"):
        depends = services[name]["depends_on"]
        assert depends["migrate"]["condition"] == "service_completed_successfully", name


def test_dockerfile_is_non_root_and_pinned() -> None:
    text = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "FROM python:3.11-slim AS builder" in text
    assert "USER tbvuser" in text
    assert "pip install --no-cache-dir -r requirements.txt" in text
    assert "pip install --no-cache-dir -r requirements-demo.txt" not in text


def test_dockerignore_excludes_secrets_and_caches() -> None:
    patterns = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for required in (".git", ".venv", ".env", "__pycache__", "*.pem", "*.key"):
        assert required in patterns, required
