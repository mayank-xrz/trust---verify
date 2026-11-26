# Track 4 local crypto prototype

> **Archived sub-project.** This directory is retained for provenance and is
> excluded from the root pytest run. See [../../docs/ARCHIVED.md](../../docs/ARCHIVED.md).
> The canonical implementation lives in `src/`.

This directory is a self-contained local submission root. `track4_service.py` is its only root-level adapter. It implements the organizer's `setup`, `read`, `revoke`, `audit`, and `protected_read` operations. The separate `crypto/` package provides an experimental authenticated messaging API; it is not exposed as an organizer adapter operation.

## Requirements

- Python 3.12 and the organizer-provided `pqcrypto==0.4.0`
- Node.js 24.11.1 in the judging container, used for standard X25519, AES-256-GCM, and HKDF-SHA256 through `node:crypto`
- No network access during judging

Clean local setup:

```sh
python3.12 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python bench.py > benchmark-results.json
```

From the official toolkit checkout:

```sh
python validate.py --entry /absolute/path/to/this/directory/track4_service.py
```

The adapter reads one UTF-8 JSON object from stdin and writes one JSON object to stdout. It starts from an empty state in a fresh `TRACK4_STATE_DIR`, or the OS temporary directory when unset. State is saved before a mutation is acknowledged. Standard error contains only a generic failure message.

## Teammate interfaces

- `crypto.protected_read.protected_read(challenge, stored_body, public_key_b64)` returns only `ciphertext` and `proof`. Call it **after** the application's authorization check.
- `crypto.session.TrustRegistry.enroll(identity, device, public_key)` is an explicit trust enrollment boundary. The registry must be populated from an approved identity service, never directly from a peer packet.
- `PrekeyStore.offer`, `initiate`, `accept`, and `finish` establish a signed ML-KEM + X25519 session. `finish` activates the initiator session after verifying the responder acknowledgment.
- `Session.encrypt` produces an authenticated packet. `Session.decrypt(packet, ReplayLedger, epoch)` verifies protocol, peer, device, session, epoch, AEAD tag, and persistent replay state before returning bytes.
- `make_transfer` and `Reassembler.ingest` provide authenticated, bounded chunk transfer. `ingest` returns `incomplete`, `duplicate`, or `delivered`; only `delivered` contains plaintext.
- Authentication, replay, recipient, epoch, and transfer errors raise `CryptoError`. The caller may emit event **labels and trusted actor/session context**; never include key material or plaintext in event fields.

## Scope and limits

Session resumption is disabled. Sender session counters are memory only; sessions must not be cloned, serialized, or restarted. The replay ledger survives receiver process restarts if its database remains intact. Incomplete transfer buffers are memory only; a receiver crash requires a new transfer ID and fresh session. The prekey store is memory only, so an interrupted handshake must start again. A session is not a policy token: the caller must recheck authorization and revocation on each sensitive operation, and pass the current key epoch. The local adapter's JSON state is a practice implementation of the organizer's synthetic ownership policy, not a production identity store.

See [crypto architecture](docs/crypto-architecture.md) and [security evidence](docs/security-evidence.md).
