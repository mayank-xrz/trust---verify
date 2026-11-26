# Crypto architecture and threat model

## Protocol

All protocol objects use UTF-8 JSON with sorted keys, no insignificant spaces, and explicit version and suite fields. Signatures prefix that encoding with `track4/v1/<purpose>\0`. Base64 is standard padded Base64. Unknown versions and suites fail closed.

Cipher suite: `ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1`.

1. An enrolled responder creates ephemeral ML-KEM-768 and X25519 key pairs and signs a short-lived offer containing its identity, device, suite, both public keys, expiration, and one-time prekey ID with ML-DSA-65.
2. The initiator checks that signature using the trusted registry, encapsulates to the ephemeral ML-KEM key, generates its own ephemeral X25519 key, computes the X25519 shared secret, and signs an initiation carrying both identities and devices, session ID, offer hash, KEM ciphertext, initiator X25519 public key, version, and suite.
3. The responder verifies the initiator's enrolled key, consumes both prekeys once, decapsulates ML-KEM, computes X25519, derives the root, and signs an acknowledgment. The initiator verifies that acknowledgment before its session can encrypt.
4. HKDF-SHA256 derives a 32-byte root from a domain-separated concatenation of the 32-byte ML-KEM and 32-byte X25519 shared secrets and transcript hash. Independent message keys are derived from the root, sender device, and counter. AES-256-GCM authenticates canonical metadata including both identities/devices, session ID, message ID, counter, key epoch, version, and suite. A 96-bit nonce is the message counter; each message key is independent.
5. A SQLite primary key over session, sender, recipient, and counter rejects a second successful message delivery, including after a receiver restart. A second persistent key rejects completed transfer IDs even if an attacker generates fresh encrypted frames. The replay row is inserted only after AEAD authentication. Application delivery must be coupled to that insertion by the integrating service if exactly-once side effects are needed.
6. A transfer manifest and each chunk are separately AEAD-authenticated packets. The manifest carries transfer ID, count, chunk size, total size, and SHA-256 of complete plaintext. The reassembler supports reordered chunks, duplicates of the exact authenticated packet, and retransmission of missing chunks. It releases bytes only after full length and hash checks.

## Bounds and trust

- Session send limit: 100,000 messages. Replay and completed-transfer tables each cap at 1,000,000 rows; capacity exhaustion fails closed and needs operational cleanup. Transfer size: 8 MiB. Chunk count: 256. Active transfers: 8. Transfer timeout: 300 seconds by default.
- The trusted identity registry is an external enrollment boundary. Revocation and authorization decisions belong to the identity and access service. The messaging API expects a current key epoch from that service.
- The `protected_read` adapter intentionally uses the organizer's exact `challenge + stored_body` HMAC transcript, separate from this messaging protocol.
- X25519, HKDF, and AES-GCM use the guaranteed Node.js runtime's standard crypto implementation. The signed transcript prevents an X25519 key from being substituted independently of the ML-KEM key.

## Threat model and guarantee limits

The attacker may control packet order, loss, duplication, and modification and may supply arbitrary public packets. Signed offers and initiation messages prevent an unauthenticated network key from becoming an identity. AEAD protects packet contents and header metadata. The ledger blocks repeat delivery while its persistent database is intact.

Disclosure of a long-term **signing** key alone does not reveal a completed session's ML-KEM or X25519 shared secrets, provided the responder's ephemeral private keys and initiator's ephemeral X25519 private key were not retained or copied. This is a design-level claim under those assumptions, not a formal forward-secrecy proof. CPython does not guarantee prompt zeroization of immutable byte strings. A compromise of the endpoint, retained prekeys, or replay database, or an attacker who recorded traffic and later gets the matching ephemeral prekeys, is outside that claim. A stolen signing key can impersonate future sessions until revoked. No session resumption or multi-device state synchronization is implemented.

The SQLite replay record and application side effect are not one transaction, so exactly-once application side effects are not guaranteed across a crash. Incomplete transfer buffers are not persisted; after a receiver crash, restart with a fresh transfer ID and session. The integrating service should use one transactional store for replay insertion, transfer state, and delivery if crash-safe transfer continuity is required.
