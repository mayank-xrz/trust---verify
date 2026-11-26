# 1-Page Threat Model: Trust-But-Verify

**System:** Multi-Node Distributed Microservice Cluster with Post-Quantum Cryptography & Tamper-Evident Audit Logging  
**Evaluation Standard:** STRIDE + Quantum Adversary Capabilities (Shor's & Grover's Algorithms)

---

## 1. Threat Actors & Adversary Capabilities

| Adversary Profile | Capabilities | Goal |
| :--- | :--- | :--- |
| **HNDL Nation-State / Quantum Adversary** | Records encrypted network traffic today; possesses fault-tolerant quantum computer tomorrow running Shor’s algorithm. | Decrypt historical communication retroactively; forge legacy RSA/ECC digital signatures. |
| **Network Man-in-the-Middle (MITM)** | Intercepts, delays, replays, or redirects packets between nodes; can alter unauthenticated metadata. | Replay high-value transactions; execute recipient swapping attacks to misroute credentials or assets. |
| **Compromised Node / Malicious Insider** | Has local execution rights on one worker node; attempts lateral movement and privilege elevation. | Access restricted admin resources, forge audit records, conceal unauthorized activity. |
| **Byzantine Node / Crash Faults** | Drops connections mid-handshake; terminates during atomic key rotation; tampers with backup images. | Induce state desynchronization, key inconsistency, or denial of service across the cluster. |

---

## 2. STRIDE Analysis & Cryptographic Mitigations

| Threat (STRIDE) | Attack Vector | Security Control in Trust-But-Verify | Residual Risk / Assumption |
| :--- | :--- | :--- | :--- |
| **Spoofing** | Forged node messages or impersonation. | **ML-DSA-65 (NIST FIPS 204)** quantum-resistant digital signatures on all envelopes and revocation broadcasts. | Node signing key secrecy must be maintained in memory. |
| **Tampering** | In-flight payload mutation or log alteration. | **AEAD (AES-256-GCM / ChaCha20-Poly1305)** for envelopes; **SHA-256 continuous cryptographic hash chains** for audit logs. | Unsigned historical logs prior to checkpoint verification could be truncated if whole node is lost. |
| **Repudiation** | Node denies having dispatched an instruction or rotation. | **Signed audit checkpoints** and sender-bound signatures verified against immutable public key records. | Clock sync skew within $\pm 2000$ ms window. |
| **Information Disclosure** | Passive wiretap / Harvest-Now-Decrypt-Later (HNDL). | **ML-KEM-768 (NIST FIPS 203)** ephemeral key exchange with strict **Forward Secrecy** (session keys destroyed after use). | Quantum computers with millions of physical qubits cannot break ML-KEM lattice security. |
| **Denial of Service** | Packet floods, replay bursts, or stale sequence spam. | **Sliding-window replay cache** with timestamp TTL and rate-limiting burst detection rules. | Physical link saturation requires upstream scrubbing. |
| **Elevation of Privilege** | Lateral traversal from worker node to restricted admin service. | **Recipient Binding (AAD check)**, **Lateral Movement Graph Enforcement (DAG)**, and deterministic privilege rules. | Relies on accurate initial service-to-service policy definition. |

---

## 3. Trust Boundaries & Assumptions

1. **Intra-Node Boundary:** Memory inside a single node process is trusted; disk storage uses Write-Ahead Logging (WAL) and HMAC-SHA3-512 backup verification to protect against restart corruption.
2. **Inter-Node Boundary:** Completely untrusted network. Zero-trust principles apply: every single message requires mutual quantum-resistant authentication, recipient binding, and freshness validation.
3. **Log Storage Boundary:** Audit log files are append-only. Any attempt to alter historical lines breaks the mathematical hash chain $H_i = \text{SHA256}(H_{i-1} \parallel \text{canonical}(E_i))$.
