import secrets
import sqlite3
import pytest
from src.crypto.resumption import TicketStore, ResumptionRejected
from tests.conftest import event_reasons


def make_ticket(channel):
    store = TicketStore(channel["path"] / "tickets.db", channel["events"])
    ticket, secret = store.issue(channel["alice"], "bob", "laptop")
    nonce = secrets.token_bytes(16)
    proof = store.proof(secret, ticket, nonce)
    return store, ticket, secret, nonce, proof


def test_same_peer_resumes(channel):
    store, ticket, _, nonce, proof = make_ticket(channel)
    new_id, new_root, _ = store.resume(ticket, "bob", "laptop", nonce, proof)
    assert new_id != channel["alice"].session_id
    assert new_root != channel["alice"].root
    assert ("resumption_accepted", "") in event_reasons(channel)


def test_different_identity_same_session_id_rejected(channel, monkeypatch):
    store, ticket, _, nonce, proof = make_ticket(channel)
    import src.crypto.resumption as resumption
    def forbidden_derive(*args, **kwargs):
        raise AssertionError("key derivation before peer check")
    monkeypatch.setattr(resumption, "derive", forbidden_derive)
    with pytest.raises(ResumptionRejected):
        store.resume(ticket, "mallory", "laptop", nonce, proof)
    reasons = event_reasons(channel)
    assert ("resumption_peer_mismatch", "resumption_peer_mismatch") in reasons
    assert not any(action == "resumption_accepted" for action, _ in reasons)


def test_expired_ticket_rejected(channel):
    store, ticket, _, nonce, proof = make_ticket(channel)
    with sqlite3.connect(store.path) as db:
        db.execute("UPDATE tickets SET expiry=0 WHERE session_id=?", (ticket["session_id"],))
    with pytest.raises(ResumptionRejected):
        store.resume(ticket, "bob", "laptop", nonce, proof)
    assert ("resumption_expired", "resumption_expired") in event_reasons(channel)


def test_replayed_ticket_rejected(channel):
    store, ticket, _, nonce, proof = make_ticket(channel)
    store.resume(ticket, "bob", "laptop", nonce, proof)
    restarted = TicketStore(channel["path"] / "tickets.db", channel["events"])
    with pytest.raises(ResumptionRejected):
        restarted.resume(ticket, "bob", "laptop", nonce, proof)
    assert ("resumption_replayed", "resumption_replayed") in event_reasons(channel)


def test_ticket_bound_to_transcript(channel):
    store, ticket, _, nonce, proof = make_ticket(channel)
    with pytest.raises(ResumptionRejected):
        store.resume(ticket, "bob", "laptop", nonce, proof, claimed_transcript_hash="0" * 64)
    assert ("resumption_peer_mismatch", "resumption_peer_mismatch") in event_reasons(channel)


def test_ticket_store_excludes_session_root(channel):
    import base64
    store, ticket, secret, nonce, proof = make_ticket(channel)
    raw = store.path.read_bytes()
    assert channel["alice"].root not in raw
    assert base64.b64encode(channel["alice"].root) not in raw
    assert secret not in (channel["path"] / "crypto.log").read_bytes()
