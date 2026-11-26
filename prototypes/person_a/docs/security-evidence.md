# Security evidence and integration status

## Organizer contract

The official toolkit at commit `8901dfbdbfe048853e0bfa25b60583d1e6617a63` requires one root adapter, a new process for each request, persistent state before acknowledgment, and exact `protected_read` ML-KEM-768/Base64/HMAC-SHA256 behavior. The public validator checks the lost-device authorization scenario only. The offline worker supplies Python 3.12, `pqcrypto==0.4.0`, and Node 24.11.1.

## Current checks

| Control | Result | Evidence |
| --- | --- | --- |
| Authorized and unauthorized protected read | Passed locally | `tests/test_crypto.py`; independent decapsulation and exact HMAC comparison |
| Public lost-device scenario | Passed locally | Official `validate.py --entry outputs/track4_service.py` |
| ML-KEM key agreement and malformed lengths | Passed locally | `test_kem_and_bad_input` |
| Ephemeral X25519 key agreement and malformed length | Passed locally | `test_x25519_ephemeral_agreement_and_bad_key` |
| ML-DSA transcript and domain binding | Passed locally | `test_signature_and_tamper` |
| Signed handshake and one-time prekey | Passed locally | `test_handshake_identity_binding_and_prekey_once` |
| AEAD, recipient binding, replay after restart | Passed locally | `test_aead_replay_restart_and_binding` |
| Reordered, duplicate, and tampered chunks; completed transfer replay after restart | Passed locally | `test_chunks_reorder_duplicate_missing_and_cross_session`, `test_chunk_tamper_and_expiration` |
| Secure resumption | Unsupported | Disabled; no resume API |
| Strong forward secrecy after endpoint compromise | Unsupported | Python byte zeroization and endpoint memory not controlled |
| Distributed revocation, access logs, anomaly detection | Not integrated | Other engineer-owned components unavailable in this local project |

Final local verification used macOS arm64, Python 3.12.16, `pqcrypto==0.4.0`, and Node 24.11.1. `python -m unittest discover -s tests -q` passed 12 tests. The official public validator printed `Local scenario passed.` Benchmark values and sample counts are in `benchmark-results.json`; they are local measurements, not judging-container performance claims.

## Audit matrix

| Area | Local project before work | Current status | This prototype |
| --- | --- | --- | --- |
| Team application | No repository files supplied | Partially implemented | Isolated local adapter and crypto package; no team repository to integrate |
| Access policy | Missing | Partially implemented | Synthetic owner/disabled policy for validator; team policy integration remains |
| Protected read | Missing | Implemented | Exact interoperability operation and negative authorization test |
| Identity enrollment | Missing | Partially implemented | In-memory explicit registry; production enrollment remains |
| Messaging and chunks | Missing | Partially implemented | Local APIs and tests; no network service integration or crash-safe partial transfer recovery |
| Resumption | Missing | Missing | Explicitly unsupported |
| Incompatible behavior | No prior implementation to assess | None observed | Public validator and local Python/Node versions passed |

## XERJ research record

XERJ `v1.0.0-rc.105` and its Query-1 bundle were installed locally. The bundle archive SHA-256 matched the published digest `74f7b7abf8f4a120fd8c2d4d6121df025af9b66cb63186709ce75ebd04ab3c77`; `bundle.json` declares `xerj-model-bundle-v1`, and `GET /_facts` reported `model.state=loaded`. The data directory is outside all indexed roots.

Indexed roots and corpus prefixes:

| Root | Prefix | Result |
| --- | --- | --- |
| This local submission root (`outputs/`) | `t4project` | 17 files, 94 records, no junk |
| Official `Track-4-Toolkit` checkout | `t4toolkit` | 19 files, 99 records, no junk |
| Named `post-quantum-messaging-app` reference | `t4ref` | 493 files, 7,212 records; 2 junk files including one nested archive, no code files junked |

The first search found `docs/adapter-v1.md:45` for the exact protected-read HMAC transcript and `docs/adapter-v1.md:21` for process/state rules. Reference searches and `xerj def` found `conversation_associated_data` at `crates/pqmsg-core/src/ad.rs:9`, `MlKem768` at `crates/pqmsg-core/src/kem.rs:50`, and `mix_root_with_pq` at `crates/pqmsg-core/src/ratchet/pq.rs:109`. The reference-coding lookup of the exact `MlKem768` symbol led to `kem.rs:208–253`: its provider validates key and ciphertext representations and wraps shared secrets in a zeroizing container. That informed strict length checks locally while highlighting that Python cannot promise the same zeroization. Source inspection also confirmed that the reference binds sender and recipient in AEAD associated data, explicitly checks suites and versions in its handshake, derives a hybrid session key from X25519 and ML-KEM material, and bounds skipped keys. Its own `docs/SPEC.md` and `docs/THREAT_MODEL.md` state endpoint and snapshot limitations. The local implementation follows these principles but uses its own code and the organizer-supported runtime. No source code was copied; the reference checkout had no root license file.

The first facts batch contained three evidence-backed records in namespace `track4`:

| Fact ID | Subject / relation | Value | Source offset |
| --- | --- | --- | --- |
| `t4-f1` | runtime / Python version | `3.12` | `t4-toolkit-contract` chars 28–32 |
| `t4-f2` | runtime / pqcrypto version | `0.4.0` | `t4-toolkit-contract` chars 68–73 |
| `t4-f3` | protected_read / proof algorithm | `HMAC-SHA-256` | `t4-toolkit-contract` chars 105–117 |

Query-1 question: **“What is the pqcrypto version in the runtime?”** Its `final_status` was `ANSWER`, `final_answer` was `0.4.0`, and its program was `[["LOOKUP",0,null],["RETURN",null,null]]`. The resolved evidence was fact `t4-f2`, quote `0.4.0`, document `t4-toolkit-contract` version `v1`, character offsets `68:73`. This derived document paraphrases the official adapter contract; the actual contract was also read directly. Four more design facts (`t4-f4` to `t4-f7`) record the ephemeral prekey, AEAD schedule, unsupported resumption, and hybrid key material. Codex registered a global `xerj` MCP server, and `xerj_memory_store` saved note `crypto-suite-v1` in namespace `track4-engineering`; a recall confirmed the updated X25519 design.
