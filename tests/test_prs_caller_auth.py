from datetime import timedelta

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

from src.crypto.primitives import kem_keypair
from src.identity_keys.clock import SystemClock
from src.identity_keys.crypto import b64e
from src.identity_keys.tokens import TokenAuthority
from track4_service import dispatch


def test_prs_requires_pinned_issuer_and_uses_verified_subject(tmp_path, monkeypatch):
    monkeypatch.delenv("TRACK4_TRUSTED_HARNESS")
    monkeypatch.setenv("TRACK4_STATE_DIR", str(tmp_path))
    setup = {"op": "setup", "owners": {"report": "alice"}, "contents": {"report": "brief"}, "disabled": []}
    assert dispatch(setup) == {"decision": "deny"}
    assert not (tmp_path / "track4-local").exists()

    issuer_key = Ed25519PrivateKey.generate()
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", b64e(issuer_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
    )))
    issuer = TokenAuthority(SystemClock())
    monkeypatch.setenv("TRACK4_ISSUER_PUBLIC_KEY_B64", b64e(issuer_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw,
    )))
    monkeypatch.setenv("TRACK4_ADMIN_SUBJECTS", "administrator")
    monkeypatch.setenv("TRACK4_TRUSTED_HARNESS", "1")  # Configured issuer takes precedence.

    def call(request, subject):
        token = issuer.issue(subject, "enrolled-laptop")
        return dispatch({**request, "authorization": f"Bearer {token}"})

    assert call(setup, "alice") == {"decision": "deny"}
    assert call(setup, "administrator") == {"ready": True}
    public, _ = kem_keypair()
    request = {
        "op": "protected_read", "asset": "report", "challenge": "fresh",
        "request_id": "verified-read", "public_key": b64e(public),
    }
    assert dispatch({**request, "actor": "alice"}) == {"decision": "deny"}
    assert call({**request, "actor": "alice"}, "bob") == {"decision": "deny"}
    assert call({"op": "read", "asset": "report", "request_id": "plain"}, "bob") == {"decision": "deny"}
    monkeypatch.delenv("TOKEN_SIGNING_SEED_B64")
    other_issuer = TokenAuthority(SystemClock())
    foreign_token = other_issuer.issue("alice", "device")
    assert dispatch({**request, "authorization": f"Bearer {foreign_token}"}) == {"decision": "deny"}

    class EarlierClock(SystemClock):
        def now(self):
            return super().now() - timedelta(minutes=10)

    issuer.clock = EarlierClock()
    assert call(request, "alice") == {"decision": "deny"}
    issuer.clock = SystemClock()
    assert set(call(request, "alice")) == {"ciphertext", "proof"}
    revoke = {"op": "revoke", "actor": "alice"}
    assert call(revoke, "alice") == {"decision": "deny"}
    assert call(revoke, "administrator") == {}
    assert call({**request, "challenge": "after-revocation"}, "alice") == {"decision": "deny"}
