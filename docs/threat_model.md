# 1-Page Threat Model: Trust-But-Verify

**System:** Multi-Node Distributed Microservice Cluster with Post-Quantum Cryptography & Tamper-Evident Audit Logging  
**Evaluation Standard:** STRIDE + Quantum Adversary Capabilities (Shor's & Grover's Algorithms)

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

---

## 4. Trust Boundaries & Assumptions

1. **Intra-Node Boundary:** Memory inside a single node process is trusted; disk storage uses Write-Ahead Logging (WAL) and HMAC-SHA3-512 backup verification to protect against restart corruption.
2. **Inter-Node Boundary:** Completely untrusted network. Zero-trust principles apply: every single message requires mutual quantum-resistant authentication, recipient binding, and freshness validation.
3. **Log Storage Boundary:** Audit log files are append-only. Any attempt to alter historical lines breaks the mathematical hash chain.

---

## 5. Honest System Limits & Out-of-Scope Risks

* **Physical & Hardware Side-Channels:** Timing, power, or electromagnetic emissions at the physical CPU level are outside the scope of software microservices.
* **Upstream Network Saturation (DDoS):** Wire-speed volumetric volumetric packet flooding that exhausts physical bandwidth cannot be resolved at the application layer and requires upstream ISP scrubbing.
* **Host OS & Hypervisor Compromise:** If an adversary achieves root execution or hypervisor memory dump access on the physical host, volatile RAM containing active session keys is compromised. Defense-in-depth requires kernel hardening and confidential computing enclaves (AMD SEV / Intel TDX).
