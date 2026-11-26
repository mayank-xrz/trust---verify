# Corrections & Part B Scope Checklist

## 1. Mandatory Corrections ("Do Not Reintroduce" Notes)
1. **ML-DSA hardness assumptions (7.1):** Do **NOT** say ML-DSA is based only on M-SIS. ML-DSA (FIPS 204) relies on **BOTH Module-LWE and Module-SIS**. See [docs/04-nist-standards.md](04-nist-standards.md) and [docs/06-math-foundations.md](06-math-foundations.md).
2. **FIPS 206 status (7.2):** Do **NOT** present FIPS 206 (FN-DSA / Falcon) as finalized. It is **draft / expected** and not yet ratified. See [docs/04-nist-standards.md](04-nist-standards.md).
3. **Grover / hash-collision nuance (7.3):** Grover's quadratic speedup does **not** reduce hash collision security to $2^{n/2}$ in the same way it affects preimage search; quantum collision finding is roughly $2^{n/3}$. See [docs/02-protocol-risk.md](02-protocol-risk.md).
4. **CNSA 2.0 dates & 2035 verification flag (7.4):** Use precise CNSA 2.0 dates (2025–2033) with citation, and explicitly flag any claim of "full exclusive PQC by 2035" as **needing verification**. See [docs/05-migration-engineering.md](05-migration-engineering.md).
5. **Detailed walkthroughs retained (7.5):** Retain existing PQC implementation walkthroughs and links; do not replace them with syllabus-only summaries. See [docs/03-syllabus.md](03-syllabus.md) and [docs/06-math-foundations.md](06-math-foundations.md).

## 2. Part B Coverage Checklist
- [x] course provenance and target audience — [docs/01-course-provenance.md](01-course-provenance.md)
- [x] protocol-level risks and HNDL prioritization — [docs/02-protocol-risk.md](02-protocol-risk.md)
- [x] 16-module syllabus — [docs/03-syllabus.md](03-syllabus.md)
- [x] supplementary resource index — [docs/03-syllabus.md](03-syllabus.md)
- [x] FIPS 203–206 table with status — [docs/04-nist-standards.md](04-nist-standards.md)
- [x] TLS ClientHello amplification / packet fragmentation — [docs/05-migration-engineering.md](05-migration-engineering.md)
- [x] SUPERCOP cycle-count benchmarking — [docs/05-migration-engineering.md](05-migration-engineering.md)
- [x] OpenSSH forks and Linux Foundation PQC Alliance — [docs/05-migration-engineering.md](05-migration-engineering.md)
- [x] AWS KMS hybrid TLS — [docs/05-migration-engineering.md](05-migration-engineering.md)
- [x] LMS/HSS firmware-signing use case — [docs/05-migration-engineering.md](05-migration-engineering.md)
- [x] LLL / lattice basis reduction — [docs/06-math-foundations.md](06-math-foundations.md)
- [x] SIS vs Module-SIS and LWE vs Module-LWE distinctions — [docs/06-math-foundations.md](06-math-foundations.md)
