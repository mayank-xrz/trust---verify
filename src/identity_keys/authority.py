"""Key-authority ML-DSA-65 signing helper for rotation cutoff records.

The key-authority signing key is loaded from (in order):

* ``KEY_AUTHORITY_PRIVATE_KEY_B64`` -- base64 raw ML-DSA-65 secret key.
* ``KEY_AUTHORITY_KEY_FILE`` -- JSON file with ``public_key_b64``/``secret_key_b64``.
* a default per-host key file under the system temporary directory.

The default file is created on first use with restrictive permissions.  The
authority public key is never trusted from the cutoff row itself: verification
requires the signature to validate under the locally pinned authority key and
the recorded ``signer_key_id`` to match its SHA-256 fingerprint.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import tempfile
from pathlib import Path
from typing import Optional

from pqcrypto.sign import ml_dsa_65

from src.common.fsutil import write_secret_atomic
from src.crypto._pqcrypto_compat import sig_keygen, sig_sign, sig_verify


def _b64e(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _default_key_path() -> Path:
    configured = os.environ.get("KEY_AUTHORITY_KEY_FILE", "").strip()
    if configured:
        return Path(configured)
    return Path(tempfile.gettempdir()) / "tbv_key_authority.json"


class KeyAuthority:
    """Pinned ML-DSA-65 key authority used to sign and verify key cutoffs."""

    def __init__(self, key_path: Optional[str | Path] = None) -> None:
        self.key_path = Path(key_path) if key_path is not None else _default_key_path()
        self._public_key: Optional[bytes] = None
        self._secret_key: Optional[bytes] = None
        self._load_or_create()

    def _load_or_create(self) -> None:
        env_priv = os.environ.get("KEY_AUTHORITY_PRIVATE_KEY_B64", "").strip()
        if env_priv:
            self._secret_key = _b64d(env_priv)
            if len(self._secret_key) != ml_dsa_65.SECRET_KEY_SIZE:
                raise ValueError("KEY_AUTHORITY_PRIVATE_KEY_B64 has invalid length")
            # pqcrypto does not expose a secret->public derivation; require a pinned
            # public key alongside an environment-provided secret key.
            env_pub = os.environ.get("KEY_AUTHORITY_PUBLIC_KEY_B64", "").strip()
            if not env_pub:
                raise ValueError(
                    "KEY_AUTHORITY_PUBLIC_KEY_B64 is required when KEY_AUTHORITY_PRIVATE_KEY_B64 is set"
                )
            self._public_key = _b64d(env_pub)
            if len(self._public_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
                raise ValueError("KEY_AUTHORITY_PUBLIC_KEY_B64 has invalid length")
            return

        if self.key_path.exists():
            data = json.loads(self.key_path.read_text(encoding="utf-8"))
            self._public_key = _b64d(data["public_key_b64"])
            self._secret_key = _b64d(data["secret_key_b64"])
            if (
                len(self._public_key) != ml_dsa_65.PUBLIC_KEY_SIZE
                or len(self._secret_key) != ml_dsa_65.SECRET_KEY_SIZE
            ):
                raise ValueError("Key authority file contains invalid key material")
            return

        public_key, secret_key = sig_keygen(ml_dsa_65)
        self._public_key = bytes(public_key)
        self._secret_key = bytes(secret_key)
        payload = {
            "public_key_b64": _b64e(self._public_key),
            "secret_key_b64": _b64e(self._secret_key),
        }
        write_secret_atomic(self.key_path, json.dumps(payload).encode("utf-8"))

    @property
    def public_key(self) -> bytes:
        assert self._public_key is not None
        return self._public_key

    @property
    def key_id(self) -> str:
        return hashlib.sha256(self.public_key).hexdigest()

    def sign(self, body: bytes) -> tuple[bytes, str]:
        assert self._secret_key is not None
        return sig_sign(ml_dsa_65, self._secret_key, body), self.key_id

    def verify(self, body: bytes, signature: bytes, signer_key_id: str) -> bool:
        if signer_key_id != self.key_id:
            return False
        return sig_verify(ml_dsa_65, self.public_key, body, signature)
