"""Performance Benchmark Suite.

Measures:
- ML-KEM-768 Ephemeral Key Exchange Latency (p50, p95, throughput)
- ML-DSA-65 Signing & Verification Latency (p50, p95, throughput)
- Envelope Encryption & AEAD Throughput (p50, p95, throughput)
- Cross-Node Revocation Propagation Latency (p50, p95, mean)
- Explainable Detection Engine Event Evaluation Throughput
- Memory Overhead (baseline vs active cluster memory)
"""

from __future__ import annotations
import os
import sys
import time
import tracemalloc
from typing import List, Dict, Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.crypto.pqc_kem import MLKEMKeyExchange
from src.crypto.pqc_sig import MLDSASignature
from src.crypto.messaging import SecureMessaging
from src.identity.revocation import RevocationCoordinator
from src.detector.rules import ContextRuleEngine
from src.audit.logger import AuditLogger


def percentile(data: List[float], p: float) -> float:
    """Calculates the p-th percentile from a list of float values."""
    if not data:
        return 0.0
    sorted_data = sorted(data)
    k = (len(sorted_data) - 1) * (p / 100.0)
    f = int(k)
    c = f + 1
    if c < len(sorted_data):
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
    return sorted_data[f]


def benchmark_kem(iterations: int = 50) -> Dict[str, float]:
    kem = MLKEMKeyExchange()
    latencies: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        pub, priv = kem.generate_keypair()
        ct, secret = kem.encapsulate(pub)
        dec_secret = kem.decapsulate(ct, priv)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    total_time_s = sum(latencies) / 1000.0
    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    ops_sec = iterations / total_time_s if total_time_s > 0 else 0.0

    print(f"⚡ [PQC-KEM]   {iterations} ops | p50: {p50:.2f} ms | p95: {p95:.2f} ms | mean: {sum(latencies)/len(latencies):.2f} ms | {ops_sec:.1f} ops/sec")
    return {"p50": p50, "p95": p95, "ops_sec": ops_sec}


def benchmark_sig(iterations: int = 50) -> Dict[str, float]:
    sig = MLDSASignature()
    pub, priv = sig.generate_keypair()
    msg = b"BENCHMARK_TRANSACTION_PAYLOAD_FOR_MEASUREMENT"
    latencies: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        signature = sig.sign(msg, priv)
        valid = sig.verify(msg, signature, pub)
        latencies.append((time.perf_counter() - t0) * 1000.0)
        assert valid is True

    total_time_s = sum(latencies) / 1000.0
    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    ops_sec = iterations / total_time_s if total_time_s > 0 else 0.0

    print(f"⚡ [PQC-SIG]   {iterations} ops | p50: {p50:.2f} ms | p95: {p95:.2f} ms | mean: {sum(latencies)/len(latencies):.2f} ms | {ops_sec:.1f} ops/sec")
    return {"p50": p50, "p95": p95, "ops_sec": ops_sec}


def benchmark_envelope(iterations: int = 100) -> Dict[str, float]:
    alice = SecureMessaging("node-alice")
    bob = SecureMessaging("node-bob")
    signer = MLDSASignature()
    pub, priv = signer.generate_keypair()
    shared_key = b"BENCHMARK_SHARED_SECRET_32BYTES!"
    payload = b'{"operation": "SECURE_TRANSFER", "amount": 1000, "token": "USD"}'
    latencies: List[float] = []

    for _ in range(iterations):
        t0 = time.perf_counter()
        envelope = alice.pack_envelope("node-alice", "node-bob", payload, shared_key, signer)
        bob.unpack_envelope(envelope, shared_key, signer, pub)
        latencies.append((time.perf_counter() - t0) * 1000.0)

    total_time_s = sum(latencies) / 1000.0
    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    ops_sec = iterations / total_time_s if total_time_s > 0 else 0.0

    print(f"⚡ [Messaging] {iterations} ops | p50: {p50:.2f} ms | p95: {p95:.2f} ms | mean: {sum(latencies)/len(latencies):.2f} ms | {ops_sec:.1f} envelopes/sec")
    return {"p50": p50, "p95": p95, "ops_sec": ops_sec}


def benchmark_revocation_propagation(iterations: int = 50) -> Dict[str, float]:
    signer = MLDSASignature()
    pub, priv = signer.generate_keypair()
    cluster_nodes = ["node-a", "node-b", "node-c"]
    latencies: List[float] = []

    for i in range(iterations):
        authority = RevocationCoordinator("key-authority")
        nodes = [RevocationCoordinator(nid) for nid in cluster_nodes]
        for coord in [authority] + nodes:
            coord.register_cluster_nodes(["key-authority"] + cluster_nodes)

        t0 = time.perf_counter()
        rev_event = authority.create_revocation(
            key_id=f"key-rev-{i}",
            target_node_id="node-b",
            reason="COMPROMISED",
            signer=signer,
        )
        # Broadcast and process on all cluster nodes
        for node in nodes:
            node.receive_revocation(rev_event, from_node_id="key-authority")
            authority.acknowledge_revocation(rev_event.revocation_id, node.node_id)

        latencies.append((time.perf_counter() - t0) * 1000.0)

    p50 = percentile(latencies, 50)
    p95 = percentile(latencies, 95)
    mean_val = sum(latencies) / len(latencies)

    print(f"⚡ [Revocation] {iterations} broadcasts | p50: {p50:.2f} ms | p95: {p95:.2f} ms | mean: {mean_val:.2f} ms cross-node propagation")
    return {"p50": p50, "p95": p95, "mean": mean_val}


def benchmark_detector(iterations: int = 2000) -> Dict[str, float]:
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
    ops_sec = iterations / total_time if total_time > 0 else 0.0

    print(f"⚡ [Detector Engine] {iterations} evaluations: {total_time:.4f}s ({ops_sec:.1f} events/sec, {(total_time/iterations)*1e6:.2f} µs/eval)")
    return {"ops_sec": ops_sec}


def measure_memory_overhead() -> Dict[str, float]:
    tracemalloc.start()
    snap_before = tracemalloc.take_snapshot()

    # Instantiate full cryptographic multi-node cluster
    kem = MLKEMKeyExchange()
    sig = MLDSASignature()
    kem.generate_keypair()
    sig.generate_keypair()

    alice = SecureMessaging("node-a")
    bob = SecureMessaging("node-b")
    engine = ContextRuleEngine()
    coords = [RevocationCoordinator(nid) for nid in ["node-a", "node-b", "node-c"]]

    # Run sample operations
    envelope = alice.pack_envelope("node-a", "node-b", b"TEST_PAYLOAD", b"K"*32, sig)
    bob.unpack_envelope(envelope, b"K"*32, sig, sig._public_key)

    current_b, peak_b = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    current_kb = current_b / 1024.0
    peak_kb = peak_b / 1024.0
    print(f"⚡ [Memory Overhead] Cluster In-Memory Footprint: {current_kb:.1f} KB current | {peak_kb:.1f} KB peak")
    return {"current_kb": current_kb, "peak_kb": peak_kb}


def main():
    print("=" * 70)
    print("🚀 TRUST-BUT-VERIFY PERFORMANCE BENCHMARK SUITE")
    print("=" * 70)
    benchmark_kem(50)
    benchmark_sig(50)
    benchmark_envelope(100)
    benchmark_revocation_propagation(50)
    benchmark_detector(2000)
    measure_memory_overhead()
    print("=" * 70)


if __name__ == "__main__":
    main()
