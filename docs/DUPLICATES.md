# Track 4 implementation inventory

Run the submission from the repository root. Use the root
[`track4_service.py`](../track4_service.py) for organizer adapter operations,
[`src/`](../src/) for the integrated implementation, and
[`tests/`](../tests/) for the submission gate.

| Path | What it does | Integrated coverage | Imports and proposed disposition |
| --- | --- | --- | --- |
| [`src/`](../src/) | Crypto sessions, identity and key lifecycle, detector, and audit chain | The root test suite exercises these components and the adapter | Imported by the root adapter, demo, tests, and operator tools. Keep as the official implementation. |
| [`prototypes/person_a/`](../prototypes/person_a/) | Earlier standalone crypto adapter, benchmark, and session package | Root crypto and protected-read tests cover the corresponding integrated features. The standalone demo and reference benchmark have a different dependency and execution context. | Its adapter, benchmark, and tests import its local `crypto/` package. No integrated runtime imports it. Keep the standalone tree intact. |
| [`role3_logging_detector/`](../role3_logging_detector/) | Earlier logger, verifier, detector, metrics, and optional XERJ integration | Root audit and detector tests cover the submission's chain, classification, and timing. They do not cover this standalone XERJ workflow. | Its CLI and tests import its own `src/` modules. No integrated runtime imports it. Keep the standalone tree intact. |
| [`verify_log.py`](../verify_log.py) | Command-line entry point for operators and judges | The strict verification regression tests exercise it | Delegates to `src.audit.verifier.main`. Keep the wrapper for compatibility. |
| [`src/audit/verifier.py`](../src/audit/verifier.py) | Official chain and pinned ML-DSA checkpoint verifier | Covered by root audit remediation and signed-log tests | Used by `verify_log.py`, the crypto CLI, and the HTTP demo. Keep as the verifier implementation. |

No candidate meets both conditions for moving to the archive. The earlier
trees have internal consumers and retain standalone workflows or evidence.
