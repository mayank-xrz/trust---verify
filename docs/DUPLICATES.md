# Track 4 implementation inventory

Run the submission from the repository root. Use the root
[`track4_service.py`](../track4_service.py) for organizer adapter operations,
[`src/`](../src/) for the integrated implementation, and
[`tests/`](../tests/) for the submission gate.

| Path | What it does | Integrated coverage | Imports and proposed disposition |
| --- | --- | --- | --- |
| [`src/`](../src/) | Crypto sessions, identity and key lifecycle, detector, and audit chain | The root test suite exercises these components and the adapter | Imported by the root adapter, demo, tests, and operator tools. Keep as the official implementation. |
| [`verify_log.py`](../verify_log.py) | Command-line entry point for operators and judges | The strict verification regression tests exercise it | Delegates to `src.audit.verifier.main`. Keep the wrapper for compatibility. |
| [`src/audit/verifier.py`](../src/audit/verifier.py) | Official chain and pinned ML-DSA checkpoint verifier | Covered by root audit remediation and signed-log tests | Used by `verify_log.py`, the crypto CLI, and the HTTP demo. Keep as the verifier implementation. |

The standalone crypto adapter and Role 3 detector were removed from the working tree. Their standalone material remains available in Git history.
