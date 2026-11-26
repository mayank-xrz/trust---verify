"""Guard against documentation drifting from the implemented behavior (P1-8)."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"


def _read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def test_no_dead_demo_url_in_published_docs() -> None:
    for rel in ("README.md", "docs/SECURITY_REVIEW.md", "docs/HANDOFF_1.md"):
        assert "trust-but-verify.dev/demo-walkthrough" not in _read(rel), rel


def test_security_review_documents_crash_gate_and_readiness() -> None:
    text = _read("docs/SECURITY_REVIEW.md")
    assert "X-Admin-Enroll-Token" in text
    assert "SANDBOX_MODE=1" in text
    assert "/readyz" in text


def test_handoff_endpoints_match_the_api() -> None:
    text = _read("docs/HANDOFF_1.md")
    for endpoint in (
        "GET /healthz",
        "GET /readyz",
        "POST /api/v1/auth/challenge",
        "POST /api/v1/auth/verify",
        "POST /internal/test/arm-crash",
    ):
        assert endpoint in text, endpoint


def test_env_example_lists_every_required_compose_secret() -> None:
    text = _read("env.example")
    for name in (
        "POSTGRES_PASSWORD",
        "WRAP_MASTER_KEY_B64",
        "CLUSTER_SYNC_SECRET",
        "TOKEN_SIGNING_SEED_B64",
        "ADMIN_ENROLL_TOKEN",
        "DEMO_CLUSTER_KEY_B64",
    ):
        assert name in text, name


def test_docs_do_not_reference_removed_demo_defaults() -> None:
    for path in list(DOCS.glob("*.md")) + [ROOT / "README.md"]:
        text = path.read_text(encoding="utf-8")
        assert "DEFAULT-PUBKEY" not in text, path
        assert "DEFAULT-DEMO-SHARED-KEY" not in text, path
