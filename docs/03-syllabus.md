# Post-Quantum Cryptography 16-Module Syllabus & Mapping

Source curriculum: Prof. Alfred Menezes, University of Waterloo — [Cryptography 101](https://cryptography101.ca/).

## 1. 16-Module Syllabus
1. Overview
2. Quantum Computers
3. The Quantum Threat: Primitives
4. The Quantum Threat: Protocols
5. Quantum-Safe Cryptography
6. PQC Standards
7. PQC Migration Timelines
8. PQC Software
9. PQC Deployments
10. Lattice-Based Cryptography
11. Learning With Errors (LWE)
12. Kyber (ML-KEM)
13. Short Integer Solution (SIS)
14. Dilithium Signatures (ML-DSA)
15. Falcon Signatures (FN-DSA)
16. FrodoKEM

## 2. Supplementary Resource Index
| Topic | Title | Author / Source | Link | Description |
| :--- | :--- | :--- | :--- | :--- |
| Kyber / Dilithium deep dives | Cryptography 101: PQC Modules | Alfred Menezes (UWaterloo) | <https://cryptography101.ca/> | Detailed lecture notes and videos covering ML-KEM (Kyber) and ML-DSA (Dilithium) algebraic structures and security reductions. |
| Hash-based signatures | NIST FIPS 205 (SLH-DSA) & NIST SP 800-208 (LMS/XMSS) | NIST CSRC | <https://csrc.nist.gov/pubs/fips/205/final> | Authoritative specifications for stateless (SLH-DSA / SPHINCS+) and stateful (LMS/HSS, XMSS) hash-based signature schemes. |
| Mathematics of lattice-based cryptography | A Decade of Lattice Cryptography | Chris Peikert (IACR ePrint 2015/939) | <https://eprint.iacr.org/2015/939> | Comprehensive survey of LWE, Ring-LWE, Module-LWE, SIS, and worst-case to average-case reductions. |
| Lattice basis reduction / LLL | Factoring Polynomials with Rational Coefficients | Lenstra, Lenstra, Lovász (1982) / Cryptography 101 | <https://cryptography101.ca/> | Foundational polynomial-time lattice basis reduction algorithm used as a baseline in lattice cryptanalysis. |
| Applied Cryptography 101 | Cryptography 101 Core Portal | Alfred Menezes (UWaterloo) | <https://cryptography101.ca/> | Practical applied cryptography curriculum bridging primitives, protocols, and standards. |
| Error-correcting codes | Classic McEliece & NIST Round 4 KEMs | NIST PQC Project | <https://csrc.nist.gov/projects/post-quantum-cryptography> | Overview of code-based KEMs (e.g., Classic McEliece, HQC) as conservative non-lattice alternatives. |

## 3. Module-to-Repository Mapping
| Module | Topic | Repository Artifact / Walkthrough | Test or Demo Command |
| :--- | :--- | :--- | :--- |
| 1–4 | Overview, Quantum Computers, Primitives, Protocols | [docs/02-protocol-risk.md](02-protocol-risk.md) | `python -m src.cli doc-check` |
| 5–6 | Quantum-Safe Cryptography, PQC Standards | [docs/04-nist-standards.md](04-nist-standards.md) | `python -m src.cli doc-check` |
| 7–9 | Migration Timelines, PQC Software, PQC Deployments | [docs/05-migration-engineering.md](05-migration-engineering.md) | `python -m src.cli doc-check` |
| 10–11 | Lattice-Based Cryptography, LWE | [docs/06-math-foundations.md](06-math-foundations.md) | `python -m src.cli doc-check` |
| 12 | Kyber (ML-KEM) | [src/crypto/handshake.py](../src/crypto/handshake.py), [src/crypto/system.py](../src/crypto/system.py) | `python -m src.cli demo-forward-secrecy` / `pytest tests/test_forward_secrecy.py` |
| 13–14 | SIS, Dilithium Signatures (ML-DSA) | [src/crypto/envelope.py](../src/crypto/envelope.py), [src/crypto/primitives.py](../src/crypto/primitives.py) | `python -m src.cli demo-replay` / `pytest tests/test_replay_binding.py` |
| 15 | Falcon Signatures (FN-DSA) | [docs/04-nist-standards.md](04-nist-standards.md), [docs/06-math-foundations.md](06-math-foundations.md) | `python -m src.cli doc-check` |
| 16 | FrodoKEM | [docs/06-math-foundations.md](06-math-foundations.md) | `python -m src.cli doc-check` |
