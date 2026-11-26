# NIST Post-Quantum Cryptography Standards Reference

| standard | algorithm | underlying mathematics | primary purpose | status |
| :--- | :--- | :--- | :--- | :--- |
| FIPS 203 | ML-KEM (Kyber) | Module-LWE | Key encapsulation / key establishment | Final |
| FIPS 204 | ML-DSA (Dilithium) | Module-LWE AND Module-SIS | Digital signatures | Final |
| FIPS 205 | SLH-DSA (SPHINCS+) | Hash-based (stateless) | Digital signatures | Final |
| FIPS 206 | FN-DSA (Falcon) | NTRU lattice (NTRU-LWE variant) | Digital signatures | Draft / expected — NOT fully ratified |

> **Important Precision Note:** **ML-DSA (FIPS 204) relies on BOTH Module-LWE and Module-SIS** (not Module-SIS alone): Module-SIS underpins unforgeability while Module-LWE underpins key-recovery / zero-knowledge masking hardness. Additionally, **FIPS 206 (FN-DSA / Falcon) is draft / expected and must NOT be presented as finalized or ratified**; only FIPS 203, FIPS 204, and FIPS 205 are finalized NIST standards (published August 2024).

## Sources
- NIST FIPS 203 (ML-KEM): <https://csrc.nist.gov/pubs/fips/203/final>
- NIST FIPS 204 (ML-DSA): <https://csrc.nist.gov/pubs/fips/204/final>
- NIST FIPS 205 (SLH-DSA): <https://csrc.nist.gov/pubs/fips/205/final>
- NIST PQC Standardization (FN-DSA / FIPS 206 draft status): <https://csrc.nist.gov/projects/post-quantum-cryptography>
