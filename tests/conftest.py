"""Runtime-generated keys and isolated on-disk state for crypto acceptance tests."""
import pytest
from src.crypto.primitives import signing_keypair
from src.crypto.handshake import establish
from src.crypto.events import CryptoEvents
from src.crypto.replay_cache import ReplayCache
from src.crypto.envelope import EnvelopeCodec


@pytest.fixture
def channel(tmp_path):
    alice_pk, alice_sk = signing_keypair()
    bob_pk, bob_sk = signing_keypair()
    alice, bob = establish("alice", "phone", "bob", "laptop", alice_sk, alice_pk, bob_sk, bob_pk)
    events = CryptoEvents(tmp_path / "crypto.log")
    cache = ReplayCache(tmp_path / "replay.db")
    sender = EnvelopeCodec(alice, "alice", "phone", cache, events)
    receiver = EnvelopeCodec(bob, "bob", "laptop", cache, events)
    return {"alice": alice, "bob": bob, "alice_pk": alice_pk, "alice_sk": alice_sk,
            "bob_pk": bob_pk, "bob_sk": bob_sk, "events": events, "cache": cache,
            "sender": sender, "receiver": receiver, "path": tmp_path}


def event_reasons(channel):
    import json
    return [(e["action"], e["metadata"].get("reason")) for e in
            (json.loads(line) for line in (channel["path"] / "crypto.log").read_text().splitlines()
             if line and not line.startswith("#"))]
