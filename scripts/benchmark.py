"""Performance Benchmark Script.

Measures:
- ML-KEM-768 Ephemeral Key Exchange Latency
- ML-DSA-65 Signing & Verification Latency
- Envelope Encryption & AEAD Throughput
- Explainable Detection Engine Event Evaluation Throughput
"""

from __future__ import annotations
import os
import sys
import time

# Ensure repo root is in python path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.crypto.pqc_kem import MLKEMKeyExchange
from src.crypto.pqc_sig import MLDSASignature
from src.crypto.messaging import SecureMessaging
from src.detector.rules import ContextRuleEngine
from src.audit.logger import AuditLogger


def benchmark_kem(iterations: int = 100):
    kem = MLKEMKeyExchange()
    t0 = time.perf_counter()
    for _ in range(iterations):
        pub, priv = kem.generate_keypair()
        ct, secret = kem.encapsulate(pub)
        dec_secret = kem.decapsulate(ct, priv)
    total_time = time.perf_counter() - t0
    avg_ms = (total_time / iterations) * 1000.0
    print(f"⚡ [PQC-KEM] {iterations} Key Exchanges: {total_time:.4f}s ({avg_ms:.2f} ms/op, {iterations/total_time:.1f} ops/sec)")


def benchmark_sig(iterations: int = 100):
    sig = MLDSASignature()
    pub, priv = sig.generate_keypair()
    msg = b"BENCHMARK_TRANSACTION_PAYLOAD_FOR_MEASUREMENT"
    t0 = time.perf_counter()
    for _ in range(iterations):
        signature = sig.sign(msg, priv)
        assert sig.verify(msg, signature, pub) is True
    total_time = time.perf_counter() - t0
    avg_ms = (total_time / iterations) * 1000.0
    print(f"⚡ [PQC-SIG] {iterations} Sign + Verifications: {total_time:.4f}s ({avg_ms:.2f} ms/op, {iterations/total_time:.1f} ops/sec)")


def benchmark_envelope(iterations: int = 500):
    alice = SecureMessaging("node-alice")
    bob = SecureMessaging("node-bob")
    signer = MLDSASignature()
    pub, priv = signer.generate_keypair()
    shared_key = b"BENCHMARK_SHARED_SECRET_32BYTES!"
    payload = b'{"operation": "SECURE_TRANSFER", "amount": 1000, "token": "USD"}'

    t0 = time.perf_counter()
    for _ in range(iterations):
        envelope = alice.pack_envelope("node-alice", "node-bob", payload, shared_key, signer)
        bob.unpack_envelope(envelope, shared_key, signer, pub)
    total_time = time.perf_counter() - t0
    avg_ms = (total_time / iterations) * 1000.0
    print(f"⚡ [Messaging] {iterations} Envelopes (Pack+Unpack+AAD): {total_time:.4f}s ({avg_ms:.2f} ms/op, {iterations/total_time:.1f} ops/sec)")


def benchmark_detector(iterations: int = 2000):
    engine = ContextRuleEngine()
    event = {
        "event_id": "bench-evt-001",
        "timestamp_ns": time.time_ns(),
        "subject": "service-worker",
        "service": "node-1",
        "resource": "/api/v1/message",
        "action": "PROCESS",
        "status": "SUCCESS",
        "metadata": {"role": "worker"},
    }

    t0 = time.perf_counter()
    for _ in range(iterations):
        engine.evaluate_event(event)
    total_time = time.perf_counter() - t0
    ops_sec = iterations / total_time
    print(f"⚡ [Detector Engine] {iterations} Rule Evaluations: {total_time:.4f}s ({ops_sec:.1f} events/sec)")


def main():
    print("=" * 60)
    print("🚀 TRUST-BUT-VERIFY PERFORMANCE BENCHMARK")
    print("=" * 60)
    benchmark_kem(100)
    benchmark_sig(100)
    benchmark_envelope(500)
    benchmark_detector(2000)
    print("=" * 60)


if __name__ == "__main__":
    main()
