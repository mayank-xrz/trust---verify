import base64
import hashlib
import json
from src.crypto import handshake
from src.crypto.primitives import signing_keypair
from tests.conftest import event_reasons


def test_identity_key_exposure_does_not_decrypt_past_session(channel):
    packet = channel["sender"].seal(b"past-session-secret")
    leaked_identity_key = channel["alice_sk"]
    public_transcript = channel["alice"].transcript
    assert channel["receiver"].open(packet) == b"past-session-secret"
    # Identity material plus the public transcript cannot reproduce the hybrid root.
    candidate = hashlib.sha256(leaked_identity_key + json.dumps(public_transcript, sort_keys=True).encode()).digest()
    assert candidate != channel["alice"].root
    assert handshake.attempt_identity_only_recovery(packet, leaked_identity_key,
                                                   public_transcript, channel["events"]) is None
    assert ("message_accepted", "") in event_reasons(channel)
    assert ("message_rejected", "identity_key_only_cannot_decrypt") in event_reasons(channel)


def test_ephemeral_keys_absent_after_session(channel, monkeypatch):
    captured = []
    original = handshake.ml_kem_768.keygen
    def recording_keygen():
        public, private = original()
        captured.append(private)
        return public, private
    monkeypatch.setattr(handshake.ml_kem_768, "keygen", recording_keygen)
    apk, ask = signing_keypair(); bpk, bsk = signing_keypair()
    a, b = handshake.establish("a", "one", "b", "two", ask, apk, bsk, bpk)
    root = a.root
    a.close(); b.close()
    assert a.root is None and b.root is None
    assert not any("private" in key for key in a.__dict__ | b.__dict__)
    on_disk = b"".join(p.read_bytes() for p in channel["path"].iterdir() if p.is_file())
    assert captured and captured[0] not in on_disk
    assert base64.b64encode(captured[0]) not in on_disk
    assert root not in on_disk
    assert base64.b64encode(root) not in on_disk
    assert b"past-session-secret" not in on_disk


def test_each_session_uses_fresh_ephemerals(channel):
    a = channel["alice"]
    a2, _ = handshake.establish("alice", "phone", "bob", "laptop",
                                channel["alice_sk"], channel["alice_pk"],
                                channel["bob_sk"], channel["bob_pk"])
    assert a.root != a2.root
    assert a.transcript["initiator_x25519"] != a2.transcript["initiator_x25519"]
    assert a.transcript["responder_mlkem"] != a2.transcript["responder_mlkem"]
