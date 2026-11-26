import copy
import pytest
from src.crypto.envelope import (RecipientMismatch, ReplayRejected, CounterOutOfWindow,
                                 AEADFailed, EnvelopeCodec)
from src.crypto.handshake import verify_handshake
from src.crypto.replay_cache import ReplayCache
from src.crypto.primitives import CryptoError, b64, unb64
from tests.conftest import event_reasons


def test_valid_message_accepted(channel):
    packet = channel["sender"].seal(b"control")
    assert channel["receiver"].open(packet) == b"control"
    assert ("message_accepted", "") in event_reasons(channel)
    assert channel["events"].verify()
    normalized = channel["events"].read_events()[-1]
    assert all(field in normalized for field in ("event_id", "timestamp", "actor", "source_service",
                                                  "target_service", "action", "outcome", "session_id",
                                                  "message_id", "reason", "log_hash"))


def test_recipient_aad_tamper_rejected(channel):
    packet = channel["sender"].seal(b"private")
    changed = copy.deepcopy(packet)
    changed["header"]["recipient_identity"] = "mallory"
    assert changed["ciphertext"] == packet["ciphertext"]
    with pytest.raises(RecipientMismatch):
        channel["receiver"].open(changed)
    assert ("message_rejected", "recipient_mismatch") in event_reasons(channel)


def test_duplicate_message_rejected(channel):
    packet = channel["sender"].seal(b"once")
    assert channel["receiver"].open(packet) == b"once"
    with pytest.raises(ReplayRejected):
        channel["receiver"].open(packet)
    assert ("message_rejected", "replay_rejected") in event_reasons(channel)


def test_replay_cache_survives_restart(channel):
    packet = channel["sender"].seal(b"once")
    channel["receiver"].open(packet)
    restarted = ReplayCache(channel["path"] / "replay.db")
    receiver = EnvelopeCodec(channel["bob"], "bob", "laptop", restarted, channel["events"])
    with pytest.raises(ReplayRejected):
        receiver.open(packet)
    assert ("message_rejected", "replay_rejected") in event_reasons(channel)


def test_counter_out_of_window_rejected(channel):
    packet = channel["sender"].seal(b"first")
    packet["header"]["counter"] = 1000
    with pytest.raises(CounterOutOfWindow):
        channel["receiver"].open(packet)
    assert ("message_rejected", "counter_out_of_window") in event_reasons(channel)


def test_signature_and_aead_failures_logged(channel):
    packet = channel["sender"].seal(b"signed")
    original = unb64(channel["alice"].signatures["initiator"])
    bad_signature = bytes([original[0] ^ 1]) + original[1:]
    with pytest.raises(CryptoError):
        verify_handshake(channel["alice"].transcript, channel["alice_pk"], bad_signature, channel["events"])
    changed = copy.deepcopy(packet)
    changed["ciphertext"] = b64(b"tampered")
    with pytest.raises(AEADFailed):
        channel["receiver"].open(changed)
    reasons = event_reasons(channel)
    assert ("signature_invalid", "signature_invalid") in reasons
    assert ("message_rejected", "aead_failed") in reasons


def test_crypto_log_schema_and_secret_exclusion(channel):
    import base64
    import json
    secret = b"not-for-audit-plaintext"
    packet = channel["sender"].seal(secret)
    channel["receiver"].open(packet)
    raw = (channel["path"] / "crypto.log").read_bytes()
    db = (channel["path"] / "replay.db").read_bytes()
    assert secret not in raw + db
    assert channel["alice"].root not in raw + db
    assert base64.b64encode(channel["alice"].root) not in raw + db
    record = [json.loads(line) for line in raw.decode().splitlines() if line and not line.startswith("#")][-1]
    metadata = record["metadata"]
    assert record["event_id"] and record["entry_hash"] and record["action"] == "message_accepted"
    assert metadata["timestamp"].endswith("Z")
    assert all(field in metadata for field in ("actor", "source_service", "target_service",
                                                "outcome", "session_id", "message_id", "reason"))
    assert channel["events"].verify()


def test_crypto_log_tamper_detected_on_restart(channel):
    packet = channel["sender"].seal(b"audit")
    channel["receiver"].open(packet)
    path = channel["path"] / "crypto.log"
    path.write_text(path.read_text().replace("message_accepted", "message_rejected"))
    from src.crypto.events import CryptoEvents
    with pytest.raises(CryptoError, match="audit chain"):
        CryptoEvents(path)
