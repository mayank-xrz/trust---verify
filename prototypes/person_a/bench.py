"""Run local synthetic crypto benchmarks and print measured JSON."""
import json
import os
from pathlib import Path
import platform
import statistics
import tempfile
import time

from crypto import aead
from crypto.chunks import Reassembler, make_transfer
from crypto.primitives import decapsulate, encapsulate, kem_keypair, sign, signing_keypair, verify
from crypto.replay import ReplayLedger
from crypto.session import PrekeyStore, TrustRegistry, accept, finish, initiate


def measure(samples, operation):
    values = []
    for _ in range(samples):
        start = time.perf_counter_ns()
        operation()
        values.append((time.perf_counter_ns() - start) / 1e6)
    return {"samples": samples, "median_ms": round(statistics.median(values), 3),
            "min_ms": round(min(values), 3), "max_ms": round(max(values), 3)}


def main():
    public, private = kem_keypair()
    ciphertext, _ = encapsulate(public)
    sign_public, sign_private = signing_keypair()
    signature = sign(sign_private, "track4/v1/bench", {"x": 1})
    registry = TrustRegistry()
    alice_pk, alice_sk = signing_keypair()
    bob_pk, bob_sk = signing_keypair()
    registry.enroll("alice", "a", alice_pk)
    registry.enroll("bob", "b", bob_pk)

    def handshake():
        prekeys = PrekeyStore()
        offer = prekeys.offer("bob", "b", bob_sk)
        initiation, alice = initiate(offer, "alice", "a", alice_sk, registry)
        ack, bob = accept(offer, initiation, bob_sk, registry, prekeys)
        finish(ack, initiation, registry, alice)
        return alice, bob

    key = os.urandom(32)
    aad = b"track4/benchmark"
    encrypt_nonces = iter(range(20))
    decrypt_envelopes = [(index.to_bytes(12, "big"), *aead.encrypt(key, index.to_bytes(12, "big"), aad, b"benchmark"))
                         for index in range(20, 40)]
    decrypt_iterator = iter(decrypt_envelopes)
    def decrypt_one():
        nonce, ciphertext, tag = next(decrypt_iterator)
        return aead.decrypt(key, nonce, aad, ciphertext, tag)
    with tempfile.TemporaryDirectory() as directory:
        output = {
            "environment": {"os": platform.platform(), "python": platform.python_version(),
                            "node": os.popen("node --version").read().strip(), "pqcrypto": "0.4.0"},
            "kem_keygen": measure(30, kem_keypair),
            "kem_encapsulate": measure(30, lambda: encapsulate(public)),
            "kem_decapsulate": measure(30, lambda: decapsulate(private, ciphertext)),
            "dsa_sign": measure(30, lambda: sign(sign_private, "track4/v1/bench", {"x": 1})),
            "dsa_verify": measure(30, lambda: verify(sign_public, "track4/v1/bench", {"x": 1}, signature)),
            "handshake": measure(20, handshake),
            "aead_encrypt": measure(20, lambda: aead.encrypt(key, next(encrypt_nonces).to_bytes(12, "big"), aad, b"benchmark")),
            "aead_decrypt": measure(20, decrypt_one),
        }
        data = bytes([i % 251 for i in range(1024 * 1024)])
        def transfer(loss=False):
            local_alice, local_bob = handshake()
            packets = make_transfer(local_alice, data)
            local_ledger = ReplayLedger(Path(directory) / ("loss.db" if loss else "plain.db"))
            receiver = Reassembler(local_bob, local_ledger)
            order = [packets[0]] + list(reversed(packets[1:]))
            if loss:
                omitted = order.pop(2)
            for item in order:
                result = receiver.ingest(item)
            if loss:
                result = receiver.ingest(omitted)
            if result["status"] != "delivered" or result["data"] != data:
                raise RuntimeError("transfer failed")
        output["transfer_1mib"] = measure(3, transfer)
        output["transfer_1mib_one_loss_retransmit"] = measure(3, lambda: transfer(True))
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
