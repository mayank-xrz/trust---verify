import os
import stat

import pytest

from src.identity_keys.authority import KeyAuthority


def test_failed_initial_write_leaves_no_partial_authority_key(tmp_path, monkeypatch):
    path = tmp_path / "authority.json"

    def fail_fsync(_fd):
        raise OSError("simulated sync failure")

    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_fsync)
        with pytest.raises(OSError, match="simulated sync failure"):
            KeyAuthority(path)

    assert list(tmp_path.iterdir()) == []
    authority = KeyAuthority(path)
    assert KeyAuthority(path).public_key == authority.public_key
    assert stat.S_IMODE(path.lstat().st_mode) == 0o600
    assert not path.is_symlink()
