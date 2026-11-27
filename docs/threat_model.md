# 1-Page Threat Model: Trust-But-Verify

**System:** Multi-Node Distributed Microservice Cluster with Post-Quantum Cryptography & Tamper-Evident Audit Logging  
**Evaluation Standard:** STRIDE + NIST Post-Quantum Cryptographic Standards (FIPS 203, FIPS 204)  
**Document Purpose:** Ready-to-export Page 2 briefing for project evaluation and security review.

> **Scope & Disclaimer:** This repository is a sandbox prototype that composes vetted implementations of standardized primitives. Its automated tests demonstrate specific properties—such as recipient binding, replay rejection, rotation cutoffs, and tamper detection—under documented test conditions. They are not a formal proof, certification, or evidence that the full system resists every implementation, deployment, side-channel, or operational failure.

---

## 1. Protected Assets & Security Objectives

| Asset | Sensitivity | Objective | Primary Cryptographic / System Mitigation |
| :--- | :--- | :--- | :--- |
| **In-Flight Message Payloads & Files** | High | Confidentiality & Integrity | AEAD (**AES-256-GCM**) with Recipient Binding inside Authenticated Associated Data (AAD). |
| **Long-Term Node Identity Keys** | Critical | Authentication and message integrity | NIST FIPS 204 **ML-DSA-65** signatures and restricted state-file permissions. Production use requires an HSM/TPM or equivalent key boundary. |
| **Ephemeral Session Secrets** | Critical | Forward secrecy for completed sessions within the documented handshake model | Hybrid ML-KEM-768 + ephemeral X25519 derivation, per-session keys, and best-effort removal of references. CPython does not guarantee physical zeroisation. |
| **Key Lifecycle State & Backups** | High | Availability & State Integrity | Atomic Write-Ahead Log (**WAL**) with checksums; signed & **HMAC-SHA3-512** authenticated backups. |
| **Audit Logs & Forensic History** | High | Tamper-Evidence & Verifiability | Continuous SHA-256 cryptographic hash chaining ($H_i = \text{SHA256}(H_{i-1} \parallel E_i)$) with instant CLI verification. |

---

## 2. Adversary Model & Attack Vectors

1. **Harvest-Now-Decrypt-Later (HNDL) Quantum Adversary:**
   - *Capability:* Wiretaps and stores encrypted microservice payloads across public/cloud networks today; will possess cryptanalytically relevant quantum computers (CRQC) running Shor's algorithm to break RSA/ECC tomorrow.
   - *Mitigation:* Session establishment includes **ML-KEM-768**, reducing exposure to known classical public-key breaks. This assumes correct libraries, uncompromised endpoints and keys, secure randomness, and the continuing validity of the standardized security assumptions.

2. **Network Man-in-the-Middle (MITM):**
   - *Capability:* Intercepts, delays, drops, replays, or redirects envelopes; attempts recipient-swapping (forwarding Node-B's confidential payload to Node-C).
   - *Mitigation:* Sliding-window replay cache (256 sequence numbers) rejects duplicates; **Recipient Binding** cryptographically binds the target identity inside signed AAD; Node-C hard-rejects Node-B's packets with `RecipientMismatchError`.

3. **Compromised Service Node / Byzantine Node:**
   - *Capability:* Malicious code execution or node compromise; crashes mid-rotation; attempts out-of-order sequence injections or emits corrupted WAL entries.
   - *Mitigation:* Two-phase atomic WAL rotation cleanly rolls back uncommitted rotation intents; corrupted trailing records are safely discarded without state contamination.

4. **Malicious Insider / Credential Abuse (Lateral Movement):**
   - *Capability:* Possesses valid credentials on one worker node (e.g., `audit-service`); attempts unauthorized RPC calls or lateral traversal to sensitive sinks.
   - *Mitigation:* Strict **Lateral Movement Graph (DAG)** topology policy; unauthorized hop combinations are blocked at the perimeter and emit high-severity explainable detector alerts.

5. **Log-Injection & Log-Tampering Attacker:**
   - *Capability:* Crafts payloads containing newline characters (`\n`) and escaped JSON structures to forge fake audit records or alters disk records after an intrusion.
   - *Mitigation:* Injection-safe JSON serializer with strict control character sanitization; continuous SHA-256 hash chaining detects any 1-byte mutation on disk via `/logs/verify`.

---

## 3. Security Controls & Trust Assumptions

* **Deterministic detector:** Detection uses explicit graph and context rules rather than an ML model. This removes model-specific behavior, but the rules still produce false positives and false negatives; the labelled evaluations report both.
* **Trust Anchor & Enrollment:** Key authority is trusted during initial device enrollment; subsequent rotations are verified peer-to-peer using cryptographic authority signatures.
* **Intra-Node Boundary:** Memory inside an active node process and the host account controlling its files are trusted. Fsynced WAL and atomic-write tests reduce crash-consistency risk, but do not protect against a malicious host, storage firmware failure, or every filesystem behavior.

---

## 4. Explicit Limits & Honest Trade-offs

1. **Clock-Skew Boundary Limits ($\pm 2000\text{ ms}$):**
   - The arrival reordering buffer tolerates up to $\pm 2000\text{ ms}$ of network arrival skew.
   - *Trade-off:* Events arriving with skew exceeding $\pm 2000\text{ ms}$ are accepted for forensic completeness but explicitly marked with `uncertainty_flag = True`, warning operators of potential timing manipulation.

2. **Network Partitions during Revocation:**
   - Revocation broadcast relies on gossip/fanout across registered peer nodes.
   - *Trade-off:* A partitioned node may retain stale authorization or peer-key state. Configured authorization replicas deny when their synchronization watermark is stale, and configured demo senders fail closed when a required revocation snapshot cannot be fetched. Deployments that disable those checks do not receive that guarantee.

3. **Metadata & Traffic Analysis Visibility:**
   - Envelope headers contain cleartext routing fields (`sender_id`, `recipient_id`, `session_id`) required for standard L7 routing and recipient binding checks.
   - *Trade-off:* While payload confidentiality and integrity are quantum-safe, traffic volume and communication graph metadata remain visible to passive network observers unless layered under network-level WireGuard/IPsec tunnels.

4. **Sandbox Prototype Scope:**
   - Nodes operate with ephemeral runtime key generation and simulated hardware security modules (HSMs).
   - *Trade-off:* Production hardening requires physical HSM/TPM key sealing and confidential computing enclaves (AMD SEV-SNP / Intel TDX) to protect private keys against hypervisor root compromises.

The machine-readable companion [`../threat-model.json`](../threat-model.json) maps assets,
actors, trust boundaries, threats, controls, assumptions, residual risks, and verification
evidence. Its identifiers are stable so automated assessment can check coverage without
scraping this prose.
