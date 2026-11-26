# Protocol-Level Quantum Risk & HNDL Prioritization

## 1. Impact of a CRQC on Classical Protocols
A Cryptographically Relevant Quantum Computer (CRQC) running Shor's algorithm breaks integer factorization (RSA) and discrete logarithms over finite fields and elliptic curves (DH, ECDH, ECDSA, EdDSA) in polynomial time.

### TLS (Transport Layer Security)
- **Primitives relied on:** RSA / ECDSA / Ed25519 for server/client authentication; (EC)DHE for ephemeral key agreement (or RSA key transport in legacy TLS 1.2).
- **Failure mode under a CRQC:** Recorded TLS 1.2 RSA-key-transport or static-DH traffic is decrypted retroactively; live TLS 1.3 sessions are vulnerable to active man-in-the-middle impersonation if signatures are forged, and recorded (EC)DHE handshakes are decrypted once the ephemeral public key is solved.

### SSH (Secure Shell)
- **Primitives relied on:** Curve25519 / ECDH / DH for key exchange; RSA / ECDSA / Ed25519 for host and user authentication.
- **Failure mode under a CRQC:** Passive eavesdroppers can decrypt captured SSH sessions via Shor's algorithm on the key-exchange public values; active attackers can forge host keys or user certificates.

### VPNs (IPsec / IKEv2 & WireGuard)
- **Primitives relied on:** IKEv2 uses DH/ECDH + RSA/ECDSA; WireGuard uses Curve25519 (Noise_IKpsk2) with static and ephemeral ECDH.
- **Failure mode under a CRQC:** Long-lived tunnel captures can be decrypted retroactively. Even WireGuard's optional pre-shared key (PSK) mitigates only symmetric confidentiality if deployed; without a PSK or PQC KEM, all captured tunnel traffic falls to Shor's algorithm.

### Signal Protocol (E2EE Messaging)
- **Primitives relied on:** X3DH (Curve25519 identity, signed prekey, one-time prekey) and Double Ratchet (Curve25519 DH ratchet + symmetric KDF ratchet).
- **Failure mode under a CRQC:** Without a post-quantum KEM (such as Signal's PQXDH / ML-KEM-1024 addition), a CRQC can recover the initial X3DH shared secret and subsequent DH ratchet outputs from recorded ciphertext transcripts.

### PKI Certificate Chains
- **Primitives relied on:** RSA, ECDSA, or EdDSA signatures across Root CA, Intermediate CA, and leaf certificates.
- **Failure mode under a CRQC:** Forging any CA's signing key allows arbitrary certificate issuance for any domain or service identity, collapsing trust across all relying protocols.

## 2. Harvest-Now, Decrypt-Later (HNDL) & Migration Priority
**Harvest-Now, Decrypt-Later (HNDL)** is the threat model in which an adversary records encrypted network traffic or stored ciphertext today and waits until a CRQC is available to break the key-establishment exchange and recover the plaintext.

**Why key-establishment migration is more urgent than signature migration:**
- **Confidentiality is retroactive; authentication is not.** Forging a signature in 2035 does not reveal what was encrypted in 2026, nor does it retroactively invalidate a past handshake that was genuinely verified at the time.
- By contrast, breaking a classical key-establishment exchange (RSA key transport, DH, or ECDH) in the future immediately exposes **all historical traffic** captured under that exchange.
- Therefore, hybrid post-quantum key establishment (e.g., X25519 + ML-KEM-768, implemented in [handshake.py](../src/crypto/handshake.py)) must be deployed first to protect long-lived confidential data against HNDL.

## 3. Primitive-Level Risk vs. Protocol-Level Risk
- **Primitive-level risk** is the mathematical break of a standalone algorithm (e.g., Shor's algorithm factoring RSA-2048 or solving ECDLP on P-256).
- **Protocol-level risk** arises from how a protocol composes primitives, handles downgrade negotiation, binds identities, or relies on certificate chains.

**Concrete example (TLS 1.2 RSA Key Transport vs. TLS 1.3 Ephemeral Key Agreement):**
In TLS 1.2 with `TLS_RSA_WITH_AES_256_GCM_SHA384`, the server's long-term RSA key is used directly for key transport: compromising that single long-term key (via theft or a CRQC) decrypts *every* recorded session ever sent to that server. In TLS 1.3 (or our [handshake.py](../src/crypto/handshake.py)), ephemeral key agreement (X25519 + ML-KEM-768) is used for session keys while the long-term identity key (ML-DSA-65) only signs the transcript—so long-term key compromise alone does not decrypt past sessions.

## 4. Quantum Impact on Symmetric Cryptography & Hash Collisions (Grover Nuance)
- Grover's quantum search algorithm provides a **quadratic** speedup for unstructured preimage search, reducing $n$-bit preimage security to roughly $2^{n/2}$ quantum work (hence AES-256 and SHA-256/SHA-384 are preferred over AES-128).
- **Important nuance for hash collisions:** Grover's quadratic speedup does **not** reduce hash collision-finding security to $2^{n/2}$ in the same way it affects preimage search. Under quantum collision algorithms (e.g., Brassard–Høyer–Tapp), collision finding is roughly **$2^{n/3}$** query/time (with significant quantum memory/parallelism trade-offs). Consequently, 256-bit hashes (SHA-256) remain strong in practice for collision resistance (~$2^{85}$+ quantum operations with large memory), and hash-based signatures (SLH-DSA, LMS/HSS) rely primarily on preimage/second-preimage resistance rather than collision resistance.
