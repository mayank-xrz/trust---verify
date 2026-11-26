# Trust, but verify — Track 4 crypto evidence

This repository contains a lost-device judging adapter and a separate crypto demonstration path. The four objectives below are implemented in `src/crypto/`. The public toolkit validator checks the adapter's lost-device scenario, while the named tests and demos exercise messaging, forward secrecy, delivery, and resumption.

## PQC & Crypto Engineer — Scope

| Objective | Code path | Acceptance tests | Demo |
| --- | --- | --- | --- |
| Replay and recipient binding | `src/crypto/envelope.py`, `src/crypto/replay_cache.py`, `src/crypto/events.py` | `tests/test_replay_binding.py` | `python -m src.crypto.cli demo-replay` |
| Forward secrecy | `src/crypto/handshake.py` | `tests/test_forward_secrecy.py` | `python -m src.crypto.cli demo-forward-secrecy` |
| Loss and reordering | `src/crypto/delivery.py` | `tests/test_delivery.py` | `python -m src.crypto.cli demo-chunked-loss` |
| Peer-bound resumption | `src/crypto/resumption.py` | `tests/test_resumption.py` | `python -m src.crypto.cli demo-resumption-binding` |

The new handshake uses ephemeral ML-KEM-768 and X25519, an ML-DSA-65 signature on the public transcript, and HKDF-SHA256 to derive a session root. Message envelopes use AES-256-GCM authentication; the long-term signing key signs only the handshake transcript. The root does not use that signing key. See `test_each_session_uses_fresh_ephemerals`, `test_identity_key_exposure_does_not_decrypt_past_session`, and `test_signature_and_aead_failures_logged`.

## Clean-machine setup

Assumptions: macOS or Linux with Python 3.12+, Node.js on PATH, and internet access for initial package installation. Node is needed by the legacy adapter and core session path. The new four-objective path uses `cryptography` directly. This work was exercised on macOS with Python 3.15.2 and Node 26.13.1; the organizer toolkit documents Python 3.12 and optional Node 24.11.1. No system crypto package or `liboqs` installation is required for these pinned wheels.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt -r requirements-test.txt
python -m pytest -q
python -m src.crypto.cli demo-replay
python -m src.crypto.cli demo-forward-secrecy
python -m src.crypto.cli demo-chunked-loss
python -m src.crypto.cli demo-resumption-binding
python -m src.crypto.cli verify-logs
```

To run the public validator, clone [Track-4-Toolkit](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit) beside this repository and run:

```bash
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git ../Track-4-Toolkit
python ../Track-4-Toolkit/validate.py --entry track4_service.py
```

The toolkit's [README](https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit) describes the validator's narrow lost-device coverage. A fresh run uses temporary state. For a persistent private adapter directory, set `TRACK4_STATE_DIR`.

## Pinned dependencies and licenses

| Package | Pin | Purpose | License |
| --- | --- | --- | --- |
| [pqcrypto](https://pypi.org/project/pqcrypto/1.0.0/) | `1.0.0` | ML-KEM-768 and ML-DSA-65 | Apache-2.0 |
| [cryptography](https://pypi.org/project/cryptography/50.0.2/) | `50.0.2` | X25519, HKDF-SHA256, AES-256-GCM | Apache-2.0 OR BSD-3-Clause |
| [pytest](https://pypi.org/project/pytest/9.2.0/) | `9.2.0` (test only) | Acceptance tests | MIT |

Runtime pins are in `requirements.txt`; the test pin is in `requirements-test.txt`. Dependency transitive packages are resolved by pip. The legacy demo has separate dependencies in `requirements-demo.txt` and is outside these four objectives.

## Negative-test output

Observed with the command above on the stated macOS host:

```text
.........................................................                [100%]
57 passed
```

The demos print deterministic outcomes and event reasons; IDs and key material are random per run. Examples:

```text
PASS replay and recipient binding
event=message_rejected reason=replay_rejected
event=message_rejected reason=recipient_mismatch
PASS missing chunks reported without partial delivery
event=delivery_failed_incomplete reason=missing_chunks:1,2
PASS ticket bound to peer; legitimate peer resumed
event=resumption_peer_mismatch reason=resumption_peer_mismatch
```

## Timing and ordering assumptions

`ReplayCache` defaults to a 256-counter per-session sliding window; it persists seen keys and outbound reservations in SQLite. The cache rejects counters beyond the window in either direction. `DeliveryReceiver` defaults to a 300-second timeout and accepts at most 8 MiB and 256 chunks per message. A duplicate chunk is ignored for delivery and logged as `message_rejected` with `replay_rejected`. Each chunk hash is SHA-256 of plaintext; the whole hash is SHA-256 of reassembled plaintext. The receiver authenticates and decrypts each chunk before checking its plaintext hash, and delivers only after the whole hash matches. AEAD nonces are derived by HKDF-SHA256 from the session root, sender/recipient identities, message ID, and chunk index with a distinct nonce label. A durable uniqueness table prevents resealing the same message ID and index under one session. The existing ±2000 ms detector clock-skew buffer is unchanged.

## Audit events

The crypto path appends via `src/audit/logger.py`; `python -m src.crypto.cli verify-logs --log PATH` checks an existing file using the existing verifier. The canonical hash-chain record remains unchanged. `event_id`, action, and `entry_hash` are top-level fields; UTC millisecond timestamp, actor, source and target service, outcome, session ID, message ID, and reason live in `metadata`. `CryptoEvents.read_events()` verifies the chain and exposes the requested flat event schema with `log_hash` mapped from `entry_hash`. `tests/test_replay_binding.py::test_crypto_log_schema_and_secret_exclusion` checks the fields and scans the log and replay DB for plaintext and root material.

## Limitations and honest non-goals

Python cannot guarantee immediate zeroization of immutable bytes. Ephemeral X25519 and ML-KEM private material and shared secrets briefly reside in process memory during `establish`; the returned new-path session holds a root until `close()` drops its reference. A compromised endpoint can still read live plaintext and keys. The legacy `Session` class persists its root and chain state in restricted files for crash-safe counters; that older path does not meet the new path's no-session-key-on-disk property. The new `HybridSession` is not serializable, so resumption after restart requires the peer to retain its ticket proof secret; the server keeps a distinct resumption secret in a mode-0600 SQLite ticket store. Tickets are one-use and tied to one original session, peer device, and transcript; there is no multi-host ticket replication or rotation chain. A stolen ticket database and peer proof secret can enable impersonation. The current `establish` helper runs both handshake roles locally for reproducible tests; it is not a transport protocol. Full production deployment needs a network exchange and independently held peer credentials.

The default `pytest` discovery is scoped in `pyproject.toml` to these acceptance and core regression tests. Legacy demo, migration, and Role 3 tests remain runnable by explicit path with their separate dependencies; unrestricted repository-wide collection is not part of this gate. The hash chain is tamper-evident only against a trusted previous head; an attacker who can replace the entire log can forge a new chain. We do not claim protection against denial of service, compromised future identity keys, or a compromised live endpoint. Backup-key management, detector rules, revocation broadcast, key-rotation internals, and WAL crash recovery are unchanged by this work.

## Threat model delta

The new path rejects replay and recipient substitution, keeps past session roots independent of a later long-term signing-key leak, reports missing or corrupt chunks without partial delivery, and rejects a different identity reusing a session ID. Tests cover those properties in the four named acceptance files. A compromised endpoint, a future signing-key compromise, a stolen resumption secret, and denial of service remain outside these controls.
