import copy
import hashlib
import pytest
from src.crypto.delivery import DeliveryReceiver, make_chunks
from src.crypto.primitives import CryptoError
from tests.conftest import event_reasons


def test_reordered_chunks_deliver(channel):
    data = b"ordered plaintext" * 10
    packets = make_chunks(channel["sender"], data, 17)
    receiver = DeliveryReceiver(channel["receiver"])
    result = None
    for packet in reversed(packets):
        result = receiver.ingest(packet)
    assert result["status"] == "delivered"
    assert result["data"] == data
    assert result["whole_hash"] == hashlib.sha256(data).hexdigest()
    assert ("message_accepted", "") in event_reasons(channel)


def test_missing_chunk_reports_incomplete(channel):
    packets = make_chunks(channel["sender"], b"abcdefghi", 3)
    receiver = DeliveryReceiver(channel["receiver"], timeout=0)
    receiver.ingest(packets[0]); receiver.ingest(packets[2])
    failures = receiver.expire()
    assert failures[0]["missing"] == [1]
    assert ("delivery_failed_incomplete", "missing_chunks:1") in event_reasons(channel)


def test_corrupt_chunk_discarded(channel):
    packets = make_chunks(channel["sender"], b"abcdef", 3)
    receiver = DeliveryReceiver(channel["receiver"])
    receiver.ingest(packets[0])
    bad = copy.deepcopy(packets[1]); bad["ciphertext"] = "AA=="
    assert receiver.ingest(bad)["status"] == "invalid"
    assert not receiver.pending
    assert ("delivery_failed_invalid", "aead_failed") in event_reasons(channel)


def test_duplicate_chunk_handled(channel):
    packets = make_chunks(channel["sender"], b"abcdef", 3)
    receiver = DeliveryReceiver(channel["receiver"])
    receiver.ingest(packets[0])
    assert receiver.ingest(packets[0])["status"] == "duplicate"
    assert receiver.ingest(packets[1])["status"] == "delivered"
    assert ("message_rejected", "replay_rejected") in event_reasons(channel)


def test_nonce_uniqueness(channel):
    packets = make_chunks(channel["sender"], b"abcdef", 2) + make_chunks(channel["sender"], b"ghijkl", 2)
    pairs = [channel["sender"]._materials(packet["header"]) for packet in packets]
    assert len(set(pairs)) == len(pairs)
    assert len({nonce for _, nonce in pairs}) == len(pairs)
    with pytest.raises(CryptoError):
        channel["sender"].seal(b"repeat", message_id=packets[0]["header"]["message_id"], chunk_index=0, chunk_count=3)
    from src.crypto.replay_cache import ReplayCache
    from src.crypto.envelope import EnvelopeCodec
    restarted = EnvelopeCodec(channel["alice"], "alice", "phone",
                              ReplayCache(channel["path"] / "replay.db"), channel["events"])
    with pytest.raises(CryptoError):
        restarted.seal(b"repeat after restart", message_id=packets[0]["header"]["message_id"],
                       chunk_index=0, chunk_count=3)
