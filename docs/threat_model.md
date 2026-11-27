# Threat Model: Trust-But-Verify

## Judge adapter

The protected asset is the content seeded by `setup`. The trust boundary is the ownership and revocation check before `read` or `protected_read` releases a result. `read` returns plaintext to the authorized owner. `protected_read` encapsulates to the supplied ML-KEM-768 public key and returns a ciphertext and a proof over the challenge and stored body. An audit query returns the recorded decision for a request ID.

The runner is trusted to initialize state, perform revocations and supply the authenticated actor. The adapter accepts the actor as a JSON field and does not authenticate a person from that field. It denies unknown assets, wrong owners and disabled actors. A protected read also requires a well-formed key and a fresh challenge in the request context.

The local service user and its state directory are trusted. The directory holds both the storage key and the encrypted resources. A process that can read or replace the whole directory can recover resources or replace the audit chain and its local anchor. Revocation applies to future requests and cannot recall content already returned. Each adapter state directory is independent.

`threat-model.json` carries the two declaration fields recognized by the organizer. The HTTP demo has a separate boundary and runs on synthetic sandbox state.

## HTTP cluster demonstration

**System:** Multi-Node Distributed Microservice Cluster with Post-Quantum Cryptography & Tamper-Evident Audit Logging  
**Evaluation Standard:** STRIDE + NIST Post-Quantum Cryptographic Standards (FIPS 203, FIPS 204)  
Demonstration nodes use synthetic data. The audit-tamper demonstration verifies a temporary copy of the node's audit log. Public demo deployments should use disposable state and test credentials.

---

## 1. Protected Assets & Security Objectives

| Asset | Sensitivity | Objective | Primary Cryptographic / System Mitigation |
| :--- | :--- | :--- | :--- |
| **In-Flight Message Payloads & Files** | High | Confidentiality & Integrity | AEAD (**AES-256-GCM**) with Recipient Binding inside Authenticated Associated Data (AAD). |
| **Long-Term Node Identity Keys** | Critical | Authentication | NIST FIPS 204 **ML-DSA-65** signatures and restricted access to node key state. |
| **Ephemeral Session Secrets** | Critical | Forward Secrecy | Hybrid session key derivation with ML-KEM-768 and X25519. Python secret cleanup is best effort. |
| **Key Lifecycle State & Backups** | High | Availability & State Integrity | Atomic Write-Ahead Log (**WAL**) with checksums; signed & **HMAC-SHA3-512** authenticated backups. |
| **Audit Logs & Forensic History** | High | Tamper-Evidence & Verifiability | Continuous SHA-256 cryptographic hash chaining ($H_i = \text{SHA256}(H_{i-1} \parallel E_i)$) with instant CLI verification. |

---

## 2. Adversary Model & Attack Vectors

1. **Harvest-Now-Decrypt-Later (HNDL) Quantum Adversary:**
   - *Capability:* Wiretaps and stores encrypted microservice payloads across public/cloud networks today; will possess cryptanalytically relevant quantum computers (CRQC) running Shor's algorithm to break RSA/ECC tomorrow.
   - *Mitigation:* The hybrid session protocol combines ML-KEM-768 and X25519. Its post-quantum protection depends on ML-KEM-768 and protection of endpoint state.

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

* **Detector coverage:** Deterministic access policies and context rules respond to configured behaviours. Synthetic traces exercise those rules. Field accuracy is unmeasured.
* **Trust Anchor & Enrollment:** Key authority is trusted during initial device enrollment; subsequent rotations are verified peer-to-peer using cryptographic authority signatures.
* **Intra-Node Boundary:** Memory inside an active node process is trusted; disk persistence uses fsynced WAL logging to guarantee crash consistency.

---

## 4. Explicit Limits & Honest Trade-offs

1. **Clock-Skew Boundary Limits ($\pm 2000\text{ ms}$):**
   - The arrival reordering buffer tolerates up to $\pm 2000\text{ ms}$ of network arrival skew.
   - *Trade-off:* Events arriving with skew exceeding $\pm 2000\text{ ms}$ are accepted for forensic completeness but explicitly marked with `uncertainty_flag = True`, warning operators of potential timing manipulation.

2. **Network Partitions during Revocation:**
   - Revocation broadcast relies on gossip/fanout across registered peer nodes.
   - *Trade-off:* A completely partitioned node that cannot receive revocation packets continues accepting grace-period keys until its local cutoff expires. Partitioned nodes fail closed upon reconnect.

3. **Metadata & Traffic Analysis Visibility:**
   - Envelope headers contain cleartext routing fields (`sender_id`, `recipient_id`, `session_id`) required for standard L7 routing and recipient binding checks.
   - *Trade-off:* While payload confidentiality and integrity are quantum-safe, traffic volume and communication graph metadata remain visible to passive network observers unless layered under network-level WireGuard/IPsec tunnels.

4. **Sandbox Prototype Scope:**
   - Nodes operate with ephemeral runtime key generation and simulated hardware security modules (HSMs).
   - *Trade-off:* Production hardening requires physical HSM/TPM key sealing and confidential computing enclaves (AMD SEV-SNP / Intel TDX) to protect private keys against hypervisor root compromises.
