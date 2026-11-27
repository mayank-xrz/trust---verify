import json
import os
import subprocess
import sys

from src.crypto.primitives import b64, kem_keypair


def invoke(tmp_path, request):
    result = subprocess.run(
        [sys.executable, "-m", "track4_service"],
        env={**os.environ, "TRACK4_STATE_DIR": str(tmp_path)},
        input=json.dumps(request),
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(result.stdout)


def test_adapter_state_format_and_anchor_protected_reads(tmp_path):
    assert invoke(tmp_path, {
        "op": "setup", "owners": {"paper": "alice"}, "contents": {"paper": "sample ☀"}, "disabled": [],
    }) == {"ready": True}
    assert invoke(tmp_path, {
        "op": "read", "actor": "alice", "asset": "paper", "request_id": "plain-read",
    }) == {"decision": "allow", "body": "sample ☀"}
    public, _ = kem_keypair()
    request = {
        "op": "protected_read", "actor": "alice", "asset": "paper",
        "request_id": "protected-read", "challenge": "fresh", "public_key": b64(public),
    }
    root = tmp_path / "track4-local"
    for sequence, candidate in enumerate((request, request, {
        **request, "request_id": "bad-key", "public_key": "",
    }), start=2):
        response = invoke(tmp_path, candidate)
        if sequence == 2:
            assert set(response) == {"ciphertext", "proof"}
        else:
            assert response == {"decision": "deny"}
        state = json.loads((root / "state.json").read_text())
        anchor = json.loads((root / ".audit_anchor.json").read_text())
        assert anchor["last_seq"] == sequence
        assert anchor["last_hash"] == state["audit_log"][-1]["entry_hash"]
