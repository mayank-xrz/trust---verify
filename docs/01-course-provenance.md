# Course Provenance & Attribution

## Source Curriculum
- **Instructor:** Prof. Alfred Menezes, Department of Combinatorics & Optimization, University of Waterloo
- **Portal:** Cryptography 101 — <https://cryptography101.ca/>
- **Portal Description:** An open-access online cryptography education portal covering modern applied cryptography, post-quantum cryptography (PQC), lattice-based schemes, and standards migration.

## Target Audience
This curriculum and the corresponding engineering documentation in this repository are designed for:
- **Security engineers** evaluating cryptographic primitives, protocol bindings, and migration risk.
- **System architects** designing hybrid key establishment, forward-secret sessions, and tamper-evident audit pipelines.
- **Software developers** integrating vetted PQC libraries (`liboqs` / `pqcrypto`) into production services without writing custom primitives.
- **Technical decision-makers** planning PQC inventory discovery, compliance timelines, and operational rollouts.

## Pedagogical Strategy
1. **Practical and operational focus:** Connects mathematical hardness assumptions directly to wire formats, key sizes, fragmentation, and deployment constraints.
2. **Mathematically sound but accessible:** Introduces LWE, Module-LWE, SIS, Module-SIS, and lattice reduction with rigorous definitions while avoiding unnecessary formalism.
3. **Continuously updated:** Tracked against finalized and draft NIST FIPS standards (FIPS 203, FIPS 204, FIPS 205, draft FIPS 206), recent cryptanalysis, and real-world deployment telemetry.

## Repository Attribution & Disclaimer
The PQC educational walkthroughs and protocol-risk analyses in this repository are derived from Prof. Alfred Menezes's Cryptography 101 curriculum at the University of Waterloo, with explicit attribution. Any errors, omissions, or implementation bugs in this repository are the repository authors' own.
