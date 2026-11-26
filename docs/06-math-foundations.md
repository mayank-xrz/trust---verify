# Mathematical Foundations: Lattice Reduction, SIS/Module-SIS, and LWE/Module-LWE

## 1. LLL and Lattice Basis Reduction as Cryptanalysis Tools
- **What LLL does:** The **Lenstra–Lenstra–Lovász (LLL)** algorithm takes an arbitrary basis of a lattice $\mathcal{L} \subset \mathbb{R}^n$ and produces a *reduced* basis of shorter, nearly orthogonal vectors in polynomial time.
- **Complexity:** Polynomial in dimension $n$ and bit-length of entries ($\mathcal{O}(n^5 d \log^3 B)$ classically, faster with floating-point variants), but the approximation factor grows **exponentially** in $n$ ($2^{(n-1)/2}$).
- **Role in PQC:** Because of its exponential approximation factor in high dimensions ($n \ge 512$), LLL (and stronger BKZ blockwise reduction) **cannot break** deployed ML-KEM or ML-DSA parameters. Instead, LLL/BKZ cost models (e.g., Core-SVP methodology) are used as **security-assessment tools** to estimate the concrete bit-security of parameter sets.

## 2. SIS vs. Module-SIS
- **SIS (Short Integer Solution):** Given a uniformly random matrix $A \in \mathbb{Z}_q^{n \times m}$, find a non-zero short integer vector $z \in \mathbb{Z}^m$ such that $Az \equiv 0 \pmod q$ and $\|z\| \le \beta$.
- **Module-SIS (M-SIS):** Replaces unstructured integer matrices over $\mathbb{Z}_q$ with matrices of polynomials over the cyclotomic ring $R_q = \mathbb{Z}_q[X]/(X^n + 1)$: given $A \in R_q^{k \times \ell}$, find a short vector $z \in R_q^\ell$ such that $Az \equiv 0 \pmod q$.
- **Why Module-SIS is used:** Ring/module structure reduces public-key and signature sizes by roughly a factor of $n$ (typically $n=256$) and enables fast NTT (Number Theoretic Transform) multiplication, while module rank $(k, \ell)$ allows fine-grained security scaling.

## 3. LWE vs. Module-LWE
- **LWE (Learning With Errors):** Given $(A, b = As + e \bmod q)$ where $A \in \mathbb{Z}_q^{m \times n}$, secret $s \in \mathbb{Z}_q^n$, and small error $e$, distinguish $(A, b)$ from uniform (or recover $s$). Used directly by conservative schemes such as **FrodoKEM** (unstructured matrices, larger keys/ciphertexts).
- **Module-LWE (M-LWE):** Replaces $\mathbb{Z}_q^n$ with $R_q^k$ where $R_q = \mathbb{Z}_q[X]/(X^n + 1)$. Used by **ML-KEM (FIPS 203)** and **ML-DSA (FIPS 204)**.
- **Trade-offs:**
  - *Unstructured LWE (FrodoKEM):* No algebraic ring structure; larger keys and ciphertexts (~10–20 KB), slower, conservative security assumption.
  - *Module-LWE (ML-KEM / ML-DSA):* Compact keys (~1–2.5 KB), fast NTT arithmetic, tunable security via module rank $k$.
  - **Note on ML-DSA (FIPS 204):** ML-DSA relies on **BOTH Module-LWE and Module-SIS** (not Module-SIS alone).
  - **Note on FN-DSA (FIPS 206 / Falcon):** Uses NTRU lattices; FIPS 206 is **draft / expected** and not yet finalized.

## 4. Cross-Links to Implementation & Walkthroughs
- Hybrid Ephemeral ML-KEM-768 + X25519 Handshake: [src/crypto/handshake.py](../src/crypto/handshake.py) and [tests/test_forward_secrecy.py](../tests/test_forward_secrecy.py)
- ML-DSA-65 Authenticated Envelopes: [src/crypto/envelope.py](../src/crypto/envelope.py) and [tests/test_replay_binding.py](../tests/test_replay_binding.py)
- Unified PQC System & Primitives: [src/crypto/system.py](../src/crypto/system.py) and [src/crypto/primitives.py](../src/crypto/primitives.py)
- Standards Status Table: [docs/04-nist-standards.md](04-nist-standards.md)
