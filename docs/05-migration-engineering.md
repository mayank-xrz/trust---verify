# PQC Migration Engineering

## 1. Cryptographic Inventory Discovery (First Gate)
Before migrating protocols or rotating keys, an organization must build a complete cryptographic inventory:
- **What to inventory:** Symmetric/asymmetric algorithms, key sizes, key lifetimes, TLS/SSH/VPN/API protocols, PKI certificate chains (root/intermediate/leaf), firmware & software signing keys, and long-lived encrypted archives.
- **How to inventory it:** Automated static/binary analysis (scanning dependencies and TLS configurations), **Cryptographic Bill of Materials (CBOM)** generation, runtime traffic inspection, and vendor security questionnaires.
- **Why it gates the rest of the migration:** You cannot prioritize HNDL-exposed assets, estimate bandwidth/fragmentation budgets, or schedule vendor upgrades without knowing where RSA, ECDH, and legacy hashes are deployed.

## 2. TLS ClientHello Amplification & Packet Fragmentation
- **Mechanism:** Replacing a 32-byte X25519 key share with an ML-KEM-768 public key (1,184 bytes) or hybrid X25519+ML-KEM-768 key share (1,216 bytes) pushes the TLS 1.3 `ClientHello` past a typical ~1,400–1,500 byte Ethernet MTU.
- **Operational impact:** Single-packet `ClientHello` messages fragment across multiple TCP segments (or UDP datagrams in QUIC/DTLS), triggering middlebox drops, firewall inspection timeouts, or extra round trips via `HelloRetryRequest` (HRR) when the server's preferred group is not in the initial key share.
- **Practical mitigations:**
  - Send only the primary hybrid group (`X25519MLKEM768`) in the initial `ClientHello` key_share extension to avoid sending multiple large PQC shares.
  - Tune initial congestion window (IW10) and Path MTU Discovery (PMTUD) / TCP MSS clamping.
  - Update DPI/middleboxes to tolerate multi-packet `ClientHello`s.

## 3. SUPERCOP Cycle-Count Benchmarking
- **What SUPERCOP measures:** SUPERCOP (*System for Unified Performance Evaluation Related to Cryptographic Operations and Primitives*, eBACS) benchmarks **CPU cycle counts** (plus memory footprint and code size) for key generation (`keygen`), encapsulation (`encaps`), decapsulation (`decaps`), signing, and verification across standardized x86_64, ARM64, and embedded architectures.
- **How to cite it:** Always cite the specific SUPERCOP benchmark run date, target microarchitecture (e.g., Intel Skylake / Apple M-series / Cortex-A72), compiler version, and whether AVX2/NEON assembly optimizations were enabled.

## 4. Open-Source Ecosystem: OpenSSH Forks & Linux Foundation PQC Alliance (PQCA)
- **OpenSSH PQC support & forks:** Upstream OpenSSH added `sntrup761x25519-sha512@openssh.com` and `mlkem768x25519-sha256` hybrid key exchange; Open Quantum Safe maintains `openssh-portable` PQC forks for broader ML-KEM / ML-DSA / hybrid experimentation.
- **Linux Foundation Post-Quantum Cryptography Alliance (PQCA):** Coordinates open-source PQC tooling and interoperability across **Open Quantum Safe (`liboqs`)**, **PQClean**, **ML-KEM/ML-DSA** reference integrations, and **OpenSSL / BoringSSL / wolfSSL** ecosystem providers.

## 5. AWS KMS Hybrid Post-Quantum TLS Options
- AWS KMS and AWS Certificate Manager / Private CA support hybrid post-quantum TLS endpoints (e.g., `X25519MLKEM768` / `SecP256r1MLKEM768` hybrid key agreement in AWS TLS termination and SDKs, alongside ML-DSA signing capabilities in AWS KMS / Private CA).
- **Operational implications:** Hybrid groups preserve classical ECDHE security while adding ML-KEM-768 HNDL resistance, at the cost of larger TLS handshake payloads and updated client/SDK cipher-group negotiation.

## 6. LMS / HSS Stateful Hash-Based Signatures for Firmware Updates
- **Use case:** **LMS/HSS** (RFC 8554, NIST SP 800-208) is well-suited for **firmware and software update signing** because signing happens infrequently in a controlled build/HSM environment, verification is fast and tiny, and security relies solely on cryptographic hash functions (minimal mathematical assumptions).
- **Statefulness & state-exhaustion risk:** Every LMS/HSS private key is a finite Merkle tree of one-time signatures (OTS). **Reusing a one-time leaf index catastrophically breaks security**, and exhausting all leaves permanently retires the key.
- **Why not general-purpose TLS:** High-concurrency stateless TLS servers cannot safely synchronize one-time signature state across horizontal replicas or survive VM snapshots/rollbacks without risking state reuse.

## 7. CNSA 2.0 Migration Timelines
According to NSA **CNSA 2.0** (*Commercial National Security Algorithm Suite 2.0*, Cybersecurity Advisory, Sept 2022; <https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF>):
- **Software & firmware signing:** Begin transitioning immediately; exclusively CNSA 2.0 supported by **2025** (prefer LMS/XMSS, transition complete by **2030**).
- **Web browsers/servers & cloud services:** Support CNSA 2.0 by **2025**; exclusively CNSA 2.0 by **2033**.
- **Traditional networking equipment (VPNs, routers):** Support CNSA 2.0 by **2026**; exclusively CNSA 2.0 by **2030**.
- **Operating systems & custom/legacy applications:** Support by **2027**; exclusively CNSA 2.0 by **2030–2033**.
- **Verification Flag:** Any claim of **"full exclusive PQC by 2035"** is **flagged as needing verification** against agency-specific updates (CNSA 2.0 targets 2030–2033 for NSS systems, while NIST IR 8547 / OMB M-23-02 set 2035 as a broader federal/non-NSS planning horizon — do not treat "full exclusive PQC by 2035" as a single authoritative CNSA 2.0 date without explicit citation).
