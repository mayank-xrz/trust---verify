"""Operator CLI verifies checkpoint signatures.

The shipped verifier and `src.cli verify-logs` previously ignored the
`signature` field on checkpoint records (they only verified it when a Python
verifier object *and* a public key were passed in-process). A signed log
therefore looked valid to an operator even when a checkpoint signature was
forged, and there was no `verify_log.py` / `--chain --checkpoints` contract.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from pathlib import Path

from pqcrypto.sign import ml_dsa_65

from src.audit.logger import AuditLogger
from src.audit.verifier import AuditLogVerifier
from src.crypto._pqcrypto_compat import sig_keygen, sig_sign

REPO_ROOT = Path(__file__).resolve().parent.parent


class _Signer:
    def __init__(self, secret_key: bytes) -> None:
        self._secret_key = secret_key

    def sign(self, data: bytes) -> bytes:
        return sig_sign(ml_dsa_65, self._secret_key, data)


def _make_signed_log(path: Path, public_key: bytes, secret_key: bytes, records: int = 4) -> None:
    logger = AuditLogger("node-cli", str(path), signer=_Signer(secret_key), checkpoint_interval=1)
    for i in range(records):
        logger.log_event("svc", "op", f"subject-{i}", "res", metadata={"i": i})


def _forge_checkpoint(path: Path, secret_key: bytes, sequence: int = 2) -> None:
    lines = path.read_text(encoding="utf-8").splitlines()
    idx = next(
        i
        for i, line in enumerate(lines)
        if line.strip() and not line.startswith("#") and json.loads(line)["sequence"] == sequence
    )
    record = json.loads(lines[idx])
    record["signature"] = base64.b64encode(
        sig_sign(ml_dsa_65, secret_key, record["entry_hash"].encode("ascii"))
    ).decode("ascii")
    lines[idx] = json.dumps(record, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _run(args: list[str]) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT)
    return subprocess.run(
        [sys.executable, *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        env=env,
    )


def test_verify_log_script_runs_self_test() -> None:
    script = REPO_ROOT / "verify_log.py"
    assert script.is_file(), "operator entry point verify_log.py is missing"
    result = _run([str(script), "--chain", "--checkpoints", "--self-test"])
    assert result.returncode == 0, result.stderr
    assert '"self_test": "PASS"' in result.stdout


def test_signed_checkpoint_requires_pinned_key_in_strict_mode(tmp_path: Path) -> None:
    public_key, secret_key = sig_keygen(ml_dsa_65)
    path = tmp_path / "signed.log"
    _make_signed_log(path, public_key, secret_key)

    # Chain-only library mode stays backwards compatible (no key supplied).
    chain_only = AuditLogVerifier().verify_file(str(path))
    assert chain_only.is_valid is True

    # Strict mode (used by the operator CLI) must fail closed rather than
    # silently skipping signature verification.
    strict = AuditLogVerifier(require_signatures=True).verify_file(str(path))
    assert strict.is_valid is False
    assert "public key" in (strict.first_error or "").lower()

    # The CLI is strict by default: no key means a signed log is rejected.
    cli_no_key = _run(["-m", "src.audit.verifier", str(path), "--chain", "--checkpoints"])
    assert cli_no_key.returncode != 0


def test_verifier_cli_accepts_clean_and_rejects_forged(tmp_path: Path) -> None:
    public_key, secret_key = sig_keygen(ml_dsa_65)
    wrong_public, wrong_secret = sig_keygen(ml_dsa_65)
    pub_b64 = base64.b64encode(public_key).decode("ascii")

    clean = tmp_path / "clean.log"
    _make_signed_log(clean, public_key, secret_key)
    forged = tmp_path / "forged.log"
    _make_signed_log(forged, public_key, secret_key)
    _forge_checkpoint(forged, wrong_secret)

    clean_result = _run(
        ["-m", "src.audit.verifier", str(clean), "--chain", "--checkpoints", "--public-key", pub_b64]
    )
    assert clean_result.returncode == 0, clean_result.stdout + clean_result.stderr

    forged_result = _run(
        ["-m", "src.audit.verifier", str(forged), "--chain", "--checkpoints", "--public-key", pub_b64]
    )
    assert forged_result.returncode != 0
    assert "Invalid signature" in forged_result.stdout or "Invalid signature" in forged_result.stderr


def test_src_cli_verify_logs_accepts_public_key(tmp_path: Path) -> None:
    public_key, secret_key = sig_keygen(ml_dsa_65)
    wrong_public, wrong_secret = sig_keygen(ml_dsa_65)
    pub_b64 = base64.b64encode(public_key).decode("ascii")

    clean = tmp_path / "clean-cli.log"
    _make_signed_log(clean, public_key, secret_key)
    forged = tmp_path / "forged-cli.log"
    _make_signed_log(forged, public_key, secret_key)
    _forge_checkpoint(forged, wrong_secret)

    clean_result = _run(["-m", "src.cli", "verify-logs", "--path", str(clean), "--public-key", pub_b64])
    assert clean_result.returncode == 0, clean_result.stdout + clean_result.stderr

    forged_result = _run(["-m", "src.cli", "verify-logs", "--path", str(forged), "--public-key", pub_b64])
    assert forged_result.returncode != 0


def test_verifier_cli_checks_truncation_against_retained_anchor(tmp_path: Path) -> None:
    public, secret = sig_keygen(ml_dsa_65)
    log = tmp_path / "audit.log"
    anchor = tmp_path / "trusted-head.json"
    _make_signed_log(log, public, secret)
    command = [
        "-m", "src.audit.verifier", str(log), "--public-key", base64.b64encode(public).decode("ascii"),
    ]
    exported = _run([*command, "--print-anchor"])
    assert exported.returncode == 0, exported.stdout + exported.stderr
    anchor.write_text(exported.stdout, encoding="utf-8")
    command += ["--anchor-file", str(anchor)]
    assert _run(command).returncode == 0
    records = log.read_text(encoding="utf-8").splitlines(keepends=True)
    log.write_text("".join(records[:-1]), encoding="utf-8")
    rejected = _run(command)
    assert rejected.returncode == 2
    assert "Whole-log truncation/replacement detected" in rejected.stdout
