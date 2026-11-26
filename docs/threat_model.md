# 1-Page Threat Model: Trust-But-Verify

**System:** Multi-Node Distributed Microservice Cluster with Post-Quantum Cryptography & Tamper-Evident Audit Logging  
**Evaluation Standard:** STRIDE + Quantum Adversary Capabilities (Shor's & Grover's Algorithms)

> **Scope Disclaimer:** This is a hackathon sandbox prototype running against mock services and synthetic identities. It makes **no claim** of production-grade security.

---

## 1. Protected Assets & Security Objectives

| Asset | Sensitivity | Objective | Primary Mitigation |
| :--- | :--- | :--- | :--- |
| **Node Private Keys (DSA/KEM)** | High (Identity) | Confidentiality & Non-Repudiation | Kept in volatile memory; zero-secret persistence; NIST FIPS 204 signatures. |
| **Ephemeral Session Secrets** | High (Payload) | Forward Secrecy | ML-KEM-768 ephemeral key exchange; session keys purged immediately after use. |
| **Message Payloads & Commands** | High (Business Data) | Confidentiality & Integrity | AEAD encryption (AES-256-GCM) with Recipient Binding inside Associated Data (AAD). |
| **Audit Logs & Event History** | High (Forensics) | Tamper-Evidence & Integrity | Continuous SHA-256 hash chaining ($H_i = \text{SHA256}(H_{i-1} \parallel E_i)$) with periodic signatures. |
| **Cluster Topology & Authorization** | Medium (Access) | Policy Enforcement | Directed Acyclic Graph (DAG) lateral movement policy engine + deterministic rules. |

---

## 2. Threat Actors & Adversary Capabilities

* **HNDL Nation-State / Quantum Adversary:** Records encrypted network traffic today; possesses fault-tolerant quantum computer tomorrow running Shor’s algorithm to factor integers or compute discrete logarithms.
* **Network Man-in-the-Middle (MITM):** Controls packet routing between nodes; can delay, replay, redirect, or alter unauthenticated metadata.
* **Compromised Worker / Malicious Insider:** Possesses valid local credentials on one worker node; attempts lateral hops to restricted admin sinks.
* **Byzantine Node / Crash Faults:** Crashes mid-rotation; attempts out-of-order sequence insertion or corrupts local backup images.

---

## 3. STRIDE Analysis & Cryptographic Mitigations

| Threat (STRIDE) | Attack Vector | Security Control in Trust-But-Verify | Residual Risk / Assumption |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged node messages or impersonation. | **ML-DSA-65 (NIST FIPS 204)** quantum-resistant digital signatures on all envelopes and revocation broadcasts. | Node signing key secrecy maintained in RAM. |
| **Tampering** | In-flight payload mutation or log alteration. | **AEAD (AES-256-GCM)** with recipient binding; **SHA-256 continuous hash chains** for audit logs. | Unsigned historical logs prior to checkpoint verification could be truncated if whole node is lost. |
| **Repudiation** | Node denies having dispatched an instruction or rotation. | **Signed audit checkpoints** and sender-bound signatures verified against immutable key states. | Clock sync skew within $\pm 2000$ ms window. |
| **Information Disclosure** | Passive wiretap / Harvest-Now-Decrypt-Later (HNDL). | **ML-KEM-768 (NIST FIPS 203)** ephemeral key exchange with strict **Forward Secrecy**. | Quantum computers cannot break ML-KEM module lattice problems (MLWE). |
| **Denial of Service** | Packet floods, replay bursts, or stale sequence spam. | **Sliding-window replay cache (256 msg)** with timestamp TTL and rate-limiting burst detection rules. | Physical link saturation requires upstream scrubbing. |
| **Elevation of Privilege** | Lateral traversal from worker node to restricted admin service. | **Recipient Binding (AAD check)**, **Lateral Movement Graph Enforcement (DAG)**, and deterministic privilege rules. | Initial DAG policy topology must be correctly defined. |

### Concrete Attack Vector Hardening

| Threat | Attacker Capability | System Behavior | Residual Risk |
| :--- | :--- | :--- | :--- |
| **Stolen device** | Possesses device Ed25519 private key | `revoke_device` sets `revoked` + gapless `commit_seq`; DB trigger prevents un-revoke; all nodes deny. | Window before loss is reported; bounded by `STALE_AFTER_MS` on disconnected nodes. |
| **Stolen recovery code** | Possesses 1 of 10 codes | Single-use salted `scrypt`; requires enrollment nonce + new PoP; rate-limited (5/hr user, 20/hr source, lockout at 10). | Valid code can re-enroll if stolen before owner revokes/uses it. |
| **Stale / partitioned node** | Network partition blocks DB/sync | `NodeSyncManager.is_stale()` fails closed with `STALE_STATE`. | Availability loss for partitioned node until reconnected. |
| **Replayed requests** | Re-sends enrollment nonce or auth challenge | Nonces and challenges are single-use (`used_at`) and short-lived. | Bearer token valid until `exp` (300s) unless device is revoked. |
| **Revoked key re-registration** | Submits revoked public key under new user | `public_key_fingerprint` `UNIQUE` + `status == 'revoked'` permanently rejects. | None for identical key; attacker could generate a new key if authorized. |
| **Backup tampering** | Modifies header, ciphertext, manifest, or tar | 11-step restore verifies pinned Ed25519 sig, SHA-256, AES-256-GCM tag, Merkle root, and semantic invariants. | None without backup-signing private key + passphrase. |
| **Backup rollback** | Restores older valid signed backup | Refused by default (`STEP9_ROLLBACK_REFUSED`) via `trust_anchor`; `--allow-rollback` union-merges live revocations. | Fresh wiped host with `--accept-unanchored` relies on operator-supplied anchor. |
| **Wrap-key compromise** | Reads `WRAP_MASTER_KEY_B64` | Can unwrap `key_versions` private material if DB is also read. | Env var instead of HSM/KMS in sandbox. |
| **DB compromise** | Direct SQL write access | Triggers block `devices` un-revoke & `revocations` mutation; private keys are AES-256-GCM wrapped. | Superuser DB role can drop triggers in single-DB topology. |
| **Admin compromise** | Possesses admin token | Can rotate/revoke/approve re-enroll; actions are immutably audited in `audit_outbox`. | Single-admin approval without M-of-N quorum. |
| **Clock manipulation** | Skewed wall clock vs monotonic | Latency uses `time.monotonic_ns()`; grace uses strict `now < grace_until`. | Wall-clock skew on host affects `grace_until` / `exp`. |
| **Enrollment spam DoS** | Floods `/reenroll/complete` | DB-backed rate limits + exponential backoff + `ALERT` audit events. | Unauthenticated `/reenroll/begin` still writes DB rows if unthrottled at ingress. |

---

## 4. Trust Boundaries & Assumptions

1. **Intra-Node Boundary:** Memory inside a single node process is trusted; disk storage uses Write-Ahead Logging (WAL) and HMAC-SHA3-512 backup verification to protect against restart corruption.
2. **Inter-Node Boundary:** Completely untrusted network. Zero-trust principles apply: every single message requires mutual quantum-resistant authentication, recipient binding, and freshness validation.
3. **Log Storage Boundary:** Audit log files are append-only. Any attempt to alter historical lines breaks the mathematical hash chain.

---

## 5. Honest System Limits & Out-of-Scope Risks

* **Physical & Hardware Side-Channels:** Timing, power, or electromagnetic emissions at the physical CPU level are outside the scope of software microservices.
* **Upstream Network Saturation (DDoS):** Wire-speed volumetric packet flooding that exhausts physical bandwidth cannot be resolved at the application layer and requires upstream ISP scrubbing.
* **Host OS & Hypervisor Compromise:** If an adversary achieves root execution or hypervisor memory dump access on the physical host, volatile RAM containing active session keys is compromised. Defense-in-depth requires kernel hardening and confidential computing enclaves (AMD SEV / Intel TDX).
