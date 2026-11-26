# Threat Model (`docs/THREAT_MODEL.md`)

> **Scope Disclaimer:** This is a hackathon sandbox prototype running against mock services and synthetic identities. It makes **no claim** of production-grade security.

| Threat | Attacker Capability | System Behavior | Residual Risk |
| --- | --- | --- | --- |
| **Stolen device** | Possesses device Ed25519 private key | `revoke_device` sets `revoked` + gapless `commit_seq`; DB trigger prevents un-revoke; all nodes deny. | Window before loss is reported; bounded by `STALE_AFTER_MS` on disconnected nodes. |
| **Stolen recovery code** | Possesses 1 of 10 codes | Single-use salted `scrypt`; requires enrollment nonce + new PoP; rate-limited (5/hr user, 20/hr source, lockout at 10). | Valid code can re-enroll if stolen before owner revokes/uses it. |
| **Stale / partitioned node** | Network partition blocks DB/sync | `NodeSyncManager.is_stale()` fails closed with `STALE_STATE`. | Availability loss for partitioned node until reconnected. |
| **Replayed requests** | Re-sends enrollment nonce or auth challenge | Nonces and challenges are single-use (`used_at`) and short-lived. | Bearer token valid until `exp` (300s) unless device is revoked. |
| **Revoked key re-registration** | Submits revoked public key under new user | `public_key_fingerprint` `UNIQUE` + `status == 'revoked'` permanently rejects. | None for identical key; attacker could generate a new key if authorized. |
| **Backup tampering** | Modifies header, ciphertext, manifest, or tar | 11-step restore verifies pinned Ed25519 sig, SHA-256, AES-256-GCM tag, Merkle root, and semantic invariants. | None without backup-signing private key + passphrase. |
| **Backup rollback** | Restores older valid signed backup | Refused by default (`STEP9_ROLLBACK_REFUSED`) via `trust_anchor`; `--allow-rollback` union-merges live revocations. | Fresh wiped host with `--accept-unanchored` relies on operator-supplied anchor. |
| **Wrap-key compromise** | Reads `WRAP_MASTER_KEY_B64` | Can unwrap `key_versions` private material if DB is also read. | Env var instead of HSM/KMS in sandbox. |
| **DB compromise** | Direct SQL write access | Triggers block `devices` un-revoke & `revocations` mutation; private keys are AES-256-GCM wrapped. | Superuser DB role can drop triggers in single-DB topology. |
| **Admin compromise** | Possesses admin token | Can rotate/revoke/approve re-enroll; actions are immutably audited in `audit_outbox`. | Single-admin approval without M-of-N quorum. |
| **Clock manipulation** | Skewed wall clock vs monotonic | Latency uses `time.monotonic_ns()`; grace uses strict `now < grace_until`. | Wall-clock skew on host affects `grace_until` / `exp`. |
| **Enrollment spam DoS** | Floods `/reenroll/complete` | DB-backed rate limits + exponential backoff + `ALERT` audit events. | Unauthenticated `/reenroll/begin` still writes DB rows if unthrottled at ingress. |
