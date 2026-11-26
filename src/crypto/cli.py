"""Reproducible Track 4 crypto demonstrations and audit verification."""
import argparse
import copy
from pathlib import Path
import secrets
import sys
import tempfile

from src.audit.verifier import AuditLogVerifier
from .delivery import DeliveryReceiver, make_chunks
from .envelope import EnvelopeCodec, RecipientMismatch, ReplayRejected
from .events import CryptoEvents
from .handshake import attempt_identity_only_recovery, establish
from .primitives import signing_keypair
from .replay_cache import ReplayCache
from .resumption import TicketStore, ResumptionRejected


def context(directory):
    path = Path(directory)
    apk, ask = signing_keypair(); bpk, bsk = signing_keypair()
    alice, bob = establish("alice", "phone", "bob", "laptop", ask, apk, bsk, bpk)
    events = CryptoEvents(path / "crypto.log")
    cache = ReplayCache(path / "replay.db")
    sender = EnvelopeCodec(alice, "alice", "phone", cache, events)
    receiver = EnvelopeCodec(bob, "bob", "laptop", cache, events)
    return alice, bob, sender, receiver, events, ask


def show(events):
    import json
    for raw in events.path.read_text(encoding="utf-8").splitlines():
        if not raw or raw.startswith("#"):
            continue
        record = json.loads(raw)
        print("event=" + record["action"] + " reason=" + record["metadata"]["reason"])


def demo_replay(directory):
    _, _, sender, receiver, events, _ = context(directory)
    packet = sender.seal(b"demo message")
    assert receiver.open(packet) == b"demo message"
    try:
        receiver.open(packet)
    except ReplayRejected:
        pass
    else:
        raise AssertionError("duplicate accepted")
    changed = copy.deepcopy(packet); changed["header"]["recipient_identity"] = "mallory"
    try:
        receiver.open(changed)
    except RecipientMismatch:
        pass
    else:
        raise AssertionError("recipient substitution accepted")
    print("PASS replay and recipient binding")
    show(events)


def demo_forward_secrecy(directory):
    alice, _, sender, receiver, events, exposed_identity = context(directory)
    packet = sender.seal(b"historical content")
    assert receiver.open(packet) == b"historical content"
    assert attempt_identity_only_recovery(packet, exposed_identity, alice.transcript, events) is None
    print("PASS identity key alone cannot decrypt prior session")
    show(events)


def demo_chunked_loss(directory):
    _, _, sender, receiver, events, _ = context(directory)
    packets = make_chunks(sender, b"chunked delivery works", 7)
    delivery = DeliveryReceiver(receiver, timeout=0)
    delivery.ingest(packets[0]); delivery.ingest(packets[-1])
    failures = delivery.expire()
    assert failures and failures[0]["missing"]
    print("PASS missing chunks reported without partial delivery")
    show(events)


def demo_resumption_binding(directory):
    alice, _, _, _, events, _ = context(directory)
    store = TicketStore(Path(directory) / "tickets.db", events)
    ticket, secret = store.issue(alice, "bob", "laptop")
    nonce = secrets.token_bytes(16)
    proof = store.proof(secret, ticket, nonce)
    try:
        store.resume(ticket, "mallory", "laptop", nonce, proof)
    except ResumptionRejected:
        pass
    else:
        raise AssertionError("different peer resumed")
    _, new_root, _ = store.resume(ticket, "bob", "laptop", nonce, proof)
    assert new_root != alice.root
    print("PASS ticket bound to peer; legitimate peer resumed")
    show(events)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("demo-replay", "demo-forward-secrecy", "demo-chunked-loss",
                                            "demo-resumption-binding", "verify-logs"))
    parser.add_argument("--log", help="audit file for verify-logs")
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-logs" and args.log:
            result = AuditLogVerifier().verify_file(args.log)
            if not result.is_valid:
                raise ValueError(result.first_error)
            print(f"PASS audit chain: {result.total_records} records")
            return 0
        with tempfile.TemporaryDirectory(prefix="track4-demo-") as directory:
            if args.command == "verify-logs":
                events = CryptoEvents(Path(directory) / "crypto.log")
                events.emit("message_accepted", "allow", actor="demo")
                assert events.verify()
                print("PASS audit chain: 1 record")
            else:
                {"demo-replay": demo_replay, "demo-forward-secrecy": demo_forward_secrecy,
                 "demo-chunked-loss": demo_chunked_loss,
                 "demo-resumption-binding": demo_resumption_binding}[args.command](directory)
        return 0
    except Exception as exc:
        print("FAIL " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
