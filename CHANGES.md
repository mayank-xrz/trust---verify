# Changes (PQC & Crypto Engineer)

| File | Purpose | Acceptance Test / Doc-Check Item |
| :--- | :--- | :--- |
| `src/crypto/events.py` | Hash-chained audit event helper (`AuditLogger`) | All crypto negative tests + `verify-logs` |
| `src/crypto/replay_cache.py` | Persistent SQLite replay cache + sliding window | `tests/test_replay_binding.py` |
| `src/crypto/envelope.py` | Canonical AAD, recipient/device check, AES-256-GCM + ML-DSA-65 | `tests/test_replay_binding.py`, `demo-replay` |
| `src/crypto/handshake.py` | Ephemeral X25519 + ML-KEM-768, HKDF-SHA256, transcript signing | `tests/test_forward_secrecy.py`, `demo-forward-secrecy` |
| `src/crypto/delivery.py` | Chunked delivery, deterministic nonce, loss/corrupt/dup handling | `tests/test_delivery.py`, `demo-chunked-loss` |
| `src/crypto/resumption.py` | Peer-bound single-use resumption tickets (SQLite) | `tests/test_resumption.py`, `demo-resumption-binding` |
| `src/cli.py` | 6 reproducible CLI subcommands (`demo-*`, `verify-logs`, `doc-check`) | All 6 CLI commands exit 0 |
| `tests/conftest.py` | Runtime keypair fixtures & audit log reader | All 4 `tests/test_*.py` suites |
| `tests/test_replay_binding.py` | Objective 1 acceptance tests (5 tests) | `pytest tests/test_replay_binding.py` |
| `tests/test_forward_secrecy.py` | Objective 2 acceptance tests (3 tests) | `pytest tests/test_forward_secrecy.py` |
| `tests/test_delivery.py` | Objective 3 acceptance tests (5 tests) | `pytest tests/test_delivery.py` |
| `tests/test_resumption.py` | Objective 4 acceptance tests (5 tests) | `pytest tests/test_resumption.py` |
| `docs/01-course-provenance.md` | Course provenance & attribution (Prof. Menezes) | `python -m src.cli doc-check` |
| `docs/02-protocol-risk.md` | Protocol-level risks, HNDL, Grover $2^{n/3}$ nuance | `python -m src.cli doc-check` |
| `docs/03-syllabus.md` | 16-module syllabus, resource index, repo mapping | `python -m src.cli doc-check` |
| `docs/04-nist-standards.md` | FIPS 203–206 table (ML-DSA M-LWE+M-SIS, FIPS 206 draft) | `python -m src.cli doc-check` |
| `docs/05-migration-engineering.md` | Inventory, ClientHello frag, SUPERCOP, PQCA, AWS, LMS/HSS, CNSA 2.0 | `python -m src.cli doc-check` |
| `docs/06-math-foundations.md` | LLL, SIS vs Module-SIS, LWE vs Module-LWE, cross-links | `python -m src.cli doc-check` |
| `docs/07-corrections-and-scope.md` | Corrections 7.1–7.5 & Part B checklist | `python -m src.cli doc-check` |
| `requirements.txt` | Pin `pqcrypto==1.0.0` (matches `.venv`) | Clean-machine setup |
| `README.md` | Scope, provenance, setup, pinned deps, snippet, timing, limits, delta | `python -m src.cli doc-check` |
