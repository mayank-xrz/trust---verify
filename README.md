# 🛡️ Trust-But-Verify

**Post-Quantum Zero-Trust Defense, Tamper-Evident Audit Logging, and Explainable Lateral Attack Detection for Multi-Node Microservices.**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![NIST FIPS 203](https://img.shields.io/badge/NIST-ML--KEM--768-success)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-ML--DSA--65-success)](https://csrc.nist.gov/pubs/fips/204/final)
[![Zero AI/ML](https://img.shields.io/badge/AI%2FML%20Deps-ZERO-success)]()

---

## 🌟 Overview & Unique Selling Proposition (USP)

**Trust-But-Verify** is an enterprise-grade, clean-machine reproducible zero-trust security framework defending distributed microservices against both modern network adversaries and future quantum attacks (Harvest-Now-Decrypt-Later / HNDL).

### What Sets Us Apart
1. **ZERO Black-Box AI/ML Dependencies:** Zero PyTorch, zero TensorFlow, zero scikit-learn, zero LLM hallucinations. All attack detection and anomaly flagging use deterministic graph-theoretic topology policies (DAG) and formal context-aware state rules ($< 2\,\mu\text{s}$ evaluation).
2. **Vetted NIST Post-Quantum Cryptography:** Native support for NIST FIPS 203 (**ML-KEM-768**) for forward-secret ephemeral key encapsulation and NIST FIPS 204 (**ML-DSA-65**) for quantum-resistant digital signatures.
3. **Cryptographically Bound Messaging:** Envelopes enforce explicit **Recipient Binding** within Authenticated Associated Data (AAD), completely eliminating recipient-swapping and relay attacks.
4. **Resilient Key Lifecycle:** Atomic key rotation with configurable grace periods and hard cutoff enforcement, paired with an append-only Write-Ahead Log (WAL) for seamless crash recovery and HMAC-SHA3-512 tamper-proof backups.
5. **Tamper-Evident Forensic Audit:** Continuous cryptographic hash chaining ($H_i = \text{SHA256}(H_{i-1} \parallel \text{canonical}(E_i))$) with newline injection sanitization and instant 1-byte mutation detection via `/logs/verify`.

---

## 🏛️ System Architecture

```mermaid
flowchart TD
    subgraph ControlPlane ["Control Plane (Identity & Key Authority)"]
        KA["Key Authority Service\n(:8000)"]
        KM["Atomic Key Manager\n(WAL + 5.0s Grace Cutoff)"]
        REV["Revocation Coordinator\n(Signed Broadcast & Latency Tracking)"]
        BKP["Backup Manager\n(HMAC-SHA3-512 Authenticated Snapshots)"]
        KA --> KM
        KA --> REV
        KA --> BKP
    end

    subgraph DataPlane ["Data Plane (Zero-Trust Messaging)"]
        NODE_A["Service node-a\n(:8001)"]
        NODE_B["Service node-b\n(:8002)"]
        NODE_C["Service node-c\n(:8003)"]
        
        ENV["PQC Message Envelope\n(ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1)\nAAD: sender/device | recipient/device | session_id | message_id | counter | epoch"]
        
        NODE_A -->|Dispatches Envelope| ENV
        ENV -->|Recipient Binding & Decryption| NODE_B
        ENV -->|Replay Cache Check| NODE_C
    end

    subgraph AuditPipeline ["Audit Pipeline (Tamper-Evident Logging)"]
        LOGGER["Audit Logger\n(Injection-Safe Serializer)"]
        CHAIN["Continuous Hash Chain\nHi = SHA256(Hi-1 || canonical(Ei))"]
        VERIFIER["Audit Log Verifier\n(/logs/verify + CLI)"]
        
        NODE_B -->|Structured Events| LOGGER
        LOGGER --> CHAIN
        CHAIN --> VERIFIER
    end

    subgraph ExplainableDetector ["Explainable Detection Engine (Zero AI/ML)"]
        CLOCK["Clock-Skew Buffer\n(±2000 ms Window + Uncertainty Flag)"]
        RULES["Context Rule Engine\n(Privilege Escalation & Routine vs Suspicious)"]
        DAG["Lateral Movement Graph\n(Strict Microservice Access Boundary DAG)"]
        ALERTS["Explainable Security Alerts\n(/metrics + operator_cli alerts)"]
        
        NODE_B -->|Telemetry| CLOCK
        CLOCK --> RULES
        RULES --> DAG
        DAG --> ALERTS
    end

    ControlPlane -.->|Signed Revocation Broadcast| DataPlane
    DataPlane --> AuditPipeline
    DataPlane --> ExplainableDetector
```

---

## ⚙️ Documented Operational Parameters

### 1. Key Rotation Grace Period & Hard Cutoff Policy
* **Atomic Two-Phase Rotation:** Triggered via `/keys/rotate`. A new keypair ($K_{\text{new}}$) is generated and committed to the WAL as `active`.
* **Grace Period Window ($T_{\text{grace}} = 5.0\text{ s}$ default, configurable via `GRACE_PERIOD_SECONDS`):** The retiring key ($K_{\text{old}}$) transitions to state `grace`. Messages in flight encrypted prior to the rotation are accepted, preventing dropped messages in distributed clusters.
* **Hard Cutoff Enforcement:** Once $t \ge T_{\text{cutoff}} = T_{\text{rotation}} + T_{\text{grace}}$, `enforce_cutoffs()` purges secret material and marks $K_{\text{old}}$ as `expired`. All service nodes (`node-a`, `node-b`, `node-c`) immediately reject messages using $K_{\text{old}}$ with `HTTP 400 Bad Request`.

### 2. Supported Clock-Skew Tolerance Range
* **Arrival Skew Tolerance ($\pm 2000\text{ ms}$):** Distributed cloud nodes experience physical clock drift. The detector’s `ClockSyncBuffer` tolerates up to $\pm 2000\text{ ms}$ of arrival skew without dropping records.
* **Sequence Ordering Buffer:** Inbound events are ordered deterministically by monotonic sequence and timestamp.
* **Uncertainty Flagging:** Events arriving with skew exceeding $\pm 2000\text{ ms}$ are processed with `uncertainty_flag = True`, warning forensic operators of clock manipulation or network delay without discarding audit evidence.

### 3. Pinned Post-Quantum Cryptographic Algorithms
* **Canonical Suite String:** `ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1` (`src/crypto/primitives.py`)
* **Key Encapsulation Mechanism (KEM):** NIST FIPS 203 **ML-KEM-768** via `pqcrypto==1.0.0`, hybridized with ephemeral **X25519** (`node:crypto`) in session handshakes.
* **Digital Signatures (DSA):** NIST FIPS 204 **ML-DSA-65** via `pqcrypto==1.0.0` with domain-separated canonical transcripts.
* **Key Derivation:** **HKDF-SHA256** (`node:crypto`) for session root, chain keys, and message keys.
* **Symmetric AEAD Cipher:** **AES-256-GCM** (`node:crypto`) with 96-bit counter nonces and explicit Authenticated Associated Data (AAD).
* **Judging Adapter (`track4_service.py`):** Uses stdlib + `pqcrypto==1.0.0` and Node.js built-ins. Its `protected_read` operation uses ML-KEM-768 and HMAC-SHA256.

### Offline Track 4 verification

Run `python3 -m compileall src track4_service.py` and `python3 -m unittest tests.test_crypto` with Python 3.9+ (verified on 3.15.2), `pqcrypto==1.0.0`, and Node.js 24.11.1 on `PATH` after `pip install -r requirements.txt`. The suite is `ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1`.

Session state, trust enrollments and revocations, prekeys, challenge hashes, and the adapter audit chain are persisted with restrictive permissions. Session sending uses an OS file lock and reserves counters before encryption. Default session files and adapter state live under the system temporary directory's `track4-local` subdirectory and can be moved with `TRACK4_STATE_DIR`. Set `TRACK4_STATE_DIR` to a durable private directory in production: temporary directories may be cleared. State files contain private key material and must be backed up and protected as secrets. The adapter state lock and session lock use `fcntl`, so this implementation requires a POSIX filesystem; it does not provide distributed locking across hosts. The audit hash chain detects accidental or untrusted edits when checked against a trusted head, but an attacker able to replace the whole state file and chain can forge a new chain.

---

## 🚀 Clean-Machine Quickstart Guide

The Track 4 crypto path requires Python 3.9+, `pqcrypto==1.0.0`, and Node.js on PATH.

### Prerequisites
* Python 3.9+ (`python3 --version`)
* Optional: Docker & Docker Compose (`docker compose version`)

### One-Command Make Targets
```bash
# 1. Install pinned requirements & pre-push hooks
make setup

# 2. Run the full test suite (crypto, audit, detector, lifecycle, identity/key management)
make test

# 3. Run performance & cryptographic overhead benchmarks
make bench

# 4. Run the 5-minute deterministic walkthrough demo for judges
make demo

# 5. Boot the multi-node container sandbox (Docker)
make up

# 6. Shut down containers and clean temporary artifacts
make clean
```

### Manual Execution (No Make Required)

#### Run the Full Test Suite
```bash
python3 -m pytest tests/ -v
```

#### Run Benchmarks
```bash
python3 scripts/benchmark.py
```

#### Run Judge Walkthrough Demo
```bash
./scripts/run_demo.sh
```

#### Demo Video
The 5-minute recording is a human-supplied artifact. The shot list, narration
points, and upload checklist are in [`docs/DEMO_VIDEO.md`](docs/DEMO_VIDEO.md).
Set `DEMO_VIDEO_URL` to the final URL once it exists. While the variable is
unset, the README and brief must say **video pending** and must not link to a
placeholder domain.

---

## 📊 Performance & Detection Benchmarks

Measured on a standard developer workstation (Apple Silicon / Linux x86_64) using `scripts/benchmark.py` and `tests/test_detector_eval.py`:

### Cryptographic & Operational Metrics

| Component / Layer | Metric | p50 Latency | p95 Latency | p99 Latency | Throughput | Overhead |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Envelope Sign + Encrypt** | ML-DSA sign + AES-256-GCM | 21.05 ms | 21.32 ms | 21.48 ms | — | — |
| **Envelope Verify + Decrypt**| ML-DSA verify + AES-256-GCM | 21.14 ms | 21.38 ms | 21.52 ms | — | — |
| **Envelope Full Roundtrip**  | Sign, Encrypt, Deliver, Verify, Decrypt | 42.19 ms | 42.70 ms | 43.00 ms | **23.7 ops/sec** | — |
| **ML-KEM-768 Exchange**      | Ephemeral Key Agreement | 59.70 ms | 59.96 ms | 60.10 ms | 16.7 ops/sec | NIST FIPS 203 |
| **ML-DSA-65 Sign & Verify**  | Post-Quantum Digital Signature | 42.09 ms | 42.33 ms | 42.50 ms | 23.7 ops/sec | NIST FIPS 204 |
| **Revocation Propagation**   | Broadcast from Authority to 3 Nodes | 26.78 ms | 27.56 ms | 28.10 ms | (Mean: 27.06 ms) | 100% Cluster Ack |
| **Detection Rule Engine**    | Context-Aware Policy Evaluation | — | — | — | **591,986 events/sec** | 1.69 $\mu$s/eval |
| **Cluster Memory Footprint** | Active Multi-Node RAM Overhead | — | — | — | — | **0.018 MB (18.9 KB)** |

### Explainable Detector Accuracy Metrics

| Metric | Target | Measured Result | Evaluation Condition |
| :--- | :--- | :--- | :--- |
| **F1 Score** | $\ge 0.90$ | **0.96** | Tested against 500 ground-truth attack/benign scenarios |
| **Precision** | $\ge 0.90$ | **0.95** | Replay, privilege escalation, lateral movement, swap attacks |
| **Recall** | $\ge 0.90$ | **0.97** | Zero missed high-severity policy violations |
| **Mean Time to Alert (MTTA)**| $< 50\text{ ms}$ | **0.002 ms ($1.69\,\mu\text{s}$)** | Deterministic in-memory evaluation |
| **False Positive Rate** | $< 1 / 1,000$ | **0.4 per 1,000 events** | Routine worker activity with legitimate privileges |

---

## 🖥️ Operator CLI Reference

The CLI (`src/node/operator_cli.py`) provides operators and judges direct visibility into running nodes:

```bash
# Check multi-node health, active key versions, and uptime
python3 -m src.node.operator_cli status

# Trigger atomic key rotation on node-a
python3 -m src.node.operator_cli rotate --identity node-a --role admin

# Revoke a compromised key and measure propagation latency across nodes
python3 -m src.node.operator_cli revoke --key-id <KEY_ID> --reason "Suspicious activity detected"

# Verify cryptographic audit log hash chains across all nodes
python3 -m src.node.operator_cli verify-logs

# Display explainable security alerts and evidence
python3 -m src.node.operator_cli alerts
```

---

## 📑 Frozen Shared JSON Schemas (`schemas/`)

* [`schemas/envelope.schema.json`](file:///Users/zuri/Hackathons/Devforge/trust-but-verify/schemas/envelope.schema.json): Cryptographically bound envelope (`version`, `sender_id`, `recipient_id`, `seq_num`, `session_id`, `kem_ciphertext`, `nonce`, `ciphertext`, `associated_data`, `signature`, `sig_alg`, `kem_alg`) with `"additionalProperties": false`.
* [`schemas/key_state.schema.json`](file:///Users/zuri/Hackathons/Devforge/trust-but-verify/schemas/key_state.schema.json): Key lifecycle schema tracking rotation state, grace periods, cutoffs, and authority signatures.
* [`schemas/audit_event.schema.json`](file:///Users/zuri/Hackathons/Devforge/trust-but-verify/schemas/audit_event.schema.json): Injection-safe audit record schema with continuous hash chain pointers (`entry_hash`, `previous_hash`).

---

## 🔐 PQC & Crypto Engineer — Scope

| Objective | Code Path | Acceptance Test File | Demo Command |
| :--- | :--- | :--- | :--- |
| **1. Replay & Recipient Binding** | [`src/crypto/envelope.py`](src/crypto/envelope.py), [`src/crypto/replay_cache.py`](src/crypto/replay_cache.py) | [`tests/test_replay_binding.py`](tests/test_replay_binding.py) | `python -m src.cli demo-replay` |
| **2. Forward Secrecy** | [`src/crypto/handshake.py`](src/crypto/handshake.py) | [`tests/test_forward_secrecy.py`](tests/test_forward_secrecy.py) | `python -m src.cli demo-forward-secrecy` |
| **3. Delivery Under Loss / Reordering** | [`src/crypto/delivery.py`](src/crypto/delivery.py) | [`tests/test_delivery.py`](tests/test_delivery.py) | `python -m src.cli demo-chunked-loss` |
| **4. Peer-Bound Session Resumption** | [`src/crypto/resumption.py`](src/crypto/resumption.py) | [`tests/test_resumption.py`](tests/test_resumption.py) | `python -m src.cli demo-resumption-binding` |

> **Standards precision:** ML-DSA (FIPS 204) relies on **both Module-LWE and Module-SIS** (not Module-SIS alone). FIPS 206 (FN-DSA / Falcon) is **draft / expected** and not yet finalized.

---

## 📚 Course Provenance and Documentation

The educational and protocol-risk documentation in `docs/` is derived from **Prof. Alfred Menezes's Cryptography 101** curriculum at the University of Waterloo (<https://cryptography101.ca/>), with attribution; any errors are the repository authors' own.

* [01 — Course Provenance & Attribution](docs/01-course-provenance.md)
* [02 — Protocol-Level Quantum Risk & HNDL Prioritization](docs/02-protocol-risk.md)
* [03 — 16-Module PQC Syllabus & Resource Index](docs/03-syllabus.md)
* [04 — NIST PQC Standards Reference (FIPS 203–206)](docs/04-nist-standards.md)
* [05 — PQC Migration Engineering](docs/05-migration-engineering.md)
* [06 — Mathematical Foundations (LLL, SIS/M-SIS, LWE/M-LWE)](docs/06-math-foundations.md)
* [07 — Corrections & Part B Scope Checklist](docs/07-corrections-and-scope.md)

---

## 💻 Clean-Machine Setup

* **OS & Python:** macOS or Linux, Python 3.9+ (verified on macOS arm64 with Python 3.15.2).
* **System dependencies:** None required beyond Python 3.9+ and `pip` (`pqcrypto==1.0.0` ships prebuilt wheels for ML-KEM-768 and ML-DSA-65).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# Run full pytest suite (including the 4 crypto acceptance test files)
pytest tests/ -v

# Run all 6 reproducible demo & verification CLI commands
python -m src.cli demo-replay
python -m src.cli demo-forward-secrecy
python -m src.cli demo-chunked-loss
python -m src.cli demo-resumption-binding
python -m src.cli verify-logs
python -m src.cli doc-check

# Run the Track-4-Toolkit lost-device validator (no regression)
python ../Track-4-Toolkit/validate.py --entry ./track4_service.py
```

---

## 📦 Dependency List (Pinned Versions & Licenses)

See [`requirements.txt`](requirements.txt) for exact pins:
* `cryptography==42.0.8` (Apache-2.0 / BSD-3-Clause) — X25519, HKDF-SHA256, AES-256-GCM, SHA-256
* `pqcrypto==1.0.0` (MIT / Apache-2.0 / Public-domain PQClean bindings) — ML-KEM-768 (FIPS 203), ML-DSA-65 (FIPS 204)
* `fastapi==0.111.0`, `uvicorn==0.30.0`, `pydantic==2.14.4`, `jsonschema==4.22.0`, `pytest==9.2.0`, `httpx==0.27.2`, `click==8.5.1`, `requests==2.32.3`, `sqlalchemy==2.0.58`, `alembic==1.14.0`, `psycopg[binary]==3.3.9`

---

## 🧪 Negative-Test Output Snippet

```text
$ ../.venv/bin/pytest -q tests/test_replay_binding.py tests/test_forward_secrecy.py tests/test_delivery.py tests/test_resumption.py -s
20 passed in 0.18s

$ ../.venv/bin/python -m src.cli demo-replay
{
  "demo": "demo-replay",
  "valid_accepted": true,
  "replay_rejected": true,
  "recipient_mismatch_rejected": true,
  "log_valid": true
}
```

---

## ⏱️ Timing and Ordering Assumptions

* **Chunk-delivery timeout:** `DEFAULT_DELIVERY_TIMEOUT_SECONDS = 30.0` seconds (configurable in `ChunkReceiver`); incomplete messages past timeout are discarded and logged as `delivery_failed_incomplete`.
* **Replay counter window:** Sliding window of `256` counters per `(sender_identity, recipient_identity, session_id)` in `PersistentReplayCache` (configurable).
* **Clock-skew buffer:** ±2000 ms clock-skew buffer unchanged (`ClockSyncBuffer` in `src/detector/clock_sync.py` was not modified).

---

## ⚠️ Limitations and Honest Non-Goals

* **Python memory zeroization:** Python `bytes` objects are immutable and garbage-collected; zeroization in `src/crypto/handshake.py` (`_best_effort_zeroize`) overwrites `bytearray` buffers and drops references, which is best-effort (brief residual copies may exist in the CPython heap until overwritten or freed).
* **Session resumption edge cases:** `PersistentResumptionStore` is single-node SQLite-backed and assumes the responder holds the ticket database; cross-node distributed ticket replication without shared storage is not implemented here.
* **Out-of-scope subsystems:** Backup-key management, key-rotation grace/cutoff internals, revocation broadcast, WAL recovery, and the detector rule engine are out of this role's scope and were left untouched.
* **Timeline verification flag:** full exclusive PQC by 2035 — needs verification against agency-specific updates (see [docs/05-migration-engineering.md](docs/05-migration-engineering.md)).

---

## 🛡️ Threat Model Delta

These controls protect against **message replay across restarts**, **recipient/device substitution**, **retroactive decryption of past sessions upon long-term ML-DSA identity-key compromise**, **corrupt or out-of-order chunked delivery**, and **session-ID hijacking during resumption**. They do **not** protect against a **compromised endpoint** (active malware reading live memory/keys), **compromise of a long-term ML-DSA key for future impersonation**, or **volumetric denial-of-service (DoS)** attacks.
