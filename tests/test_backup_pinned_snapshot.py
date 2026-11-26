import json
import secrets

import pytest

from src.identity.backup import BackupIntegrityError, BackupManager
from src.identity_keys.crypto import generate_ml_dsa_keypair


@pytest.mark.parametrize("missing_signature", [False, True])
def test_snapshot_requires_signature_even_with_intact_checksum(tmp_path, missing_signature):
    master = secrets.token_bytes(32)
    public, private = generate_ml_dsa_keypair()
    path = tmp_path / "snapshot.json"
    BackupManager(master, pinned_pubkey=public, signing_privkey=private).create_backup({"version": 1}, str(path))
    assert BackupManager(master, pinned_pubkey=public).verify_and_restore(str(path)) == {"version": 1}
    if missing_signature:
        snapshot = json.loads(path.read_text())
        del snapshot["manifest_sig_b64"]
        path.write_text(json.dumps(snapshot))
        verifier = BackupManager(master, pinned_pubkey=public)
    else:
        wrong_public, _ = generate_ml_dsa_keypair()
        verifier = BackupManager(master, pinned_pubkey=wrong_public)
    with pytest.raises(BackupIntegrityError, match="ML-DSA signature"):
        verifier.verify_and_restore(str(path))
