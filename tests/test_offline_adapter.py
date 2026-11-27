import json
import os
import subprocess
import sys

import pytest

from src.crypto.primitives import b64, kem_keypair

OFFLINE_WORKER = """
import builtins
original_import = builtins.__import__
def without_cryptography(name, *args, **kwargs):
    if name == "cryptography" or name.startswith("cryptography."):
        raise ModuleNotFoundError(name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = without_cryptography
import track4_service
assert track4_service.AESGCM is None
track4_service.main()
"""


def invoke(tmp_path, request, offline):
    args = ["-c", OFFLINE_WORKER] if offline else ["-m", "track4_service"]
    result = subprocess.run(
        [sys.executable, *args], env={**os.environ, "TRACK4_STATE_DIR": str(tmp_path)},
        input=json.dumps(request), capture_output=True, text=True, check=True,
    )
    return json.loads(result.stdout)


@pytest.mark.parametrize("setup_offline", [False, True])
def test_adapter_backends_share_state_format_and_anchor_protected_reads(tmp_path, setup_offline):
    assert invoke(tmp_path, {
        "op": "setup", "owners": {"paper": "alice"}, "contents": {"paper": "sample ☀"}, "disabled": [],
    }, setup_offline) == {"ready": True}
    assert invoke(tmp_path, {
        "op": "read", "actor": "alice", "asset": "paper", "request_id": "plain-read",
    }, not setup_offline) == {"decision": "allow", "body": "sample ☀"}
    public, _ = kem_keypair()
    request = {
        "op": "protected_read", "actor": "alice", "asset": "paper",
        "request_id": "protected-read", "challenge": "fresh", "public_key": b64(public),
    }
    root = tmp_path / "track4-local"
    for sequence, candidate in enumerate((request, request, {
        **request, "request_id": "bad-key", "public_key": "",
    }), start=2):
        response = invoke(tmp_path, candidate, not setup_offline)
        if sequence == 2:
            assert set(response) == {"ciphertext", "proof"}
        else:
            assert response == {"decision": "deny"}
        state = json.loads((root / "state.json").read_text())
        anchor = json.loads((root / ".audit_anchor.json").read_text())
        assert anchor["last_seq"] == sequence
        assert anchor["last_hash"] == state["audit_log"][-1]["entry_hash"]
