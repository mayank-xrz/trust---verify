from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_submission_pins_the_official_pqcrypto_runtime() -> None:
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()

    assert "pqcrypto==0.4.0" in requirements, (
        "official Track 4 adapter contract v1 uses pqcrypto==0.4.0 in the offline "
        "Python 3.12 judging runtime"
    )
    assert "pqcrypto==1.0.0" not in requirements


def test_build_and_ci_use_the_official_python_runtime() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert dockerfile.count("FROM python:3.12-slim") == 2
    assert 'python-version: "3.12"' in workflow
    assert 'python-version: "3.11"' not in workflow
