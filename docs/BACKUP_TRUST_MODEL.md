# Backup Trust Model (`docs/BACKUP_TRUST_MODEL.md`)

## 1. Out-of-Band Trusted Roots
1. **Pinned Backup-Signing Public Key (Ed25519):**
   - Separate from every operational `auth` or `data` key.
   - The **public key** is pinned in node configuration / environment (`BACKUP_SIGNING_PUBKEY_B64`) or passed out-of-band to `restore_backup()`. It is **never** read from the backup manifest or payload.
2. **Trusted Recovery-State Anchor (`trust_anchor`):**
   - Tracks the live node's high-water `revocation_commit_seq` and `revocation_head_hash` in the `trust_anchor` table.
   - During restore, the procedure reads the anchor from the live DB (or from an operator-supplied signed anchor when restoring onto an empty/fresh machine).

## 2. Fail-Closed Anchor & Rollback Rules
- If neither a live DB anchor nor an operator-supplied anchor can be established, **restore is refused** (`StateUnavailable` / `BACKUP_UNANCHORED`).
- If the backup's `revocation_head.commit_seq` is behind the live anchor, **restore is refused** (`Conflict` / `BACKUP_ROLLBACK_REFUSED`) unless `--allow-rollback` (`allow_rollback=True`) is explicitly passed, in which case all live revocations are **union-merged forward** so a revoked device or key can never be reactivated.
- **Residual Risk (Wiped System):** On a completely wiped host with no live DB and no out-of-band anchor file, an operator passing `--accept-unanchored` accepts the risk of restoring an older valid signed backup; this override is loudly audited (`backup.unanchored_override`) and still merges any supplied revocations.
