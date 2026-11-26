"""Check tracked, deployable text for obvious embedded credentials."""

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CREDENTIAL = re.compile(
    r"""(?ix)\b(?:password|passphrase|signing_seed(?:_b64)?|key_material|"""
    r"""wrap_master_key_b64|cluster_sync_secret|admin_enroll_token)"""
    r"""["']?\s*[:=]\s*b?["']([^"'\r\n]+)["']"""
)
FALLBACK = re.compile(r"\$\{[A-Z0-9_]*(?:PASSWORD|PASSPHRASE|SECRET|SEED|KEY_MATERIAL)[A-Z0-9_]*:-[^}]+\}")
PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----")
URL_PASSWORD = re.compile(r"\b\w[\w+.-]*://[^\s/:@$]+:([^\s/@$]+)@")


def test_no_hardcoded_secrets():
    tracked = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    findings = []
    for name in filter(None, tracked):
        path = ROOT / name
        if not path.is_file():
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        fixture = "tests" in path.relative_to(ROOT).parts or path.name.startswith("test_")
        for number, line in enumerate(source.splitlines(), 1):
            if PRIVATE_KEY.search(line) or FALLBACK.search(line) or URL_PASSWORD.search(line):
                findings.append(f"{name}:{number}")
            match = CREDENTIAL.search(line)
            # Tests use public synthetic inputs. Private PEMs and credentials in
            # URLs/defaults above are checked even inside tests.
            if match and not fixture and match[1] not in {"[REDACTED]"}:
                findings.append(f"{name}:{number}")
    assert not findings, "Hard-coded credential candidates (file:line): " + ", ".join(findings)
