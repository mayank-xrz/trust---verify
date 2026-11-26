# Part 2 Handoff (`docs/HANDOFF_2.md`) — Key Rotation, Envelope Encryption & Crash Recovery

## 1. New Schema & Columns (`alembic/versions/0002_part2_key_lifecycle.py`)
- **`key_sets`**: `key_set_id` (PK), `scope` (`auth|data`), `active_key_version_id`, `current_version`, `updated_at`.
- **`key_versions`**: added `destroyed_at` (nullable UTC timestamp).
- **`resources`**: added `wrapped_dek`, `dek_nonce`, `dek_aad` (envelope encryption).

## 2. Rotation & Envelope API (`src/identity_keys/api.py`)
- `POST /rotations` (`InitiateRotationRequest`: `key_set_id`, `grace_seconds`, `idempotency_key`) -> `{"rotation_id"}` (requires `key:rotate`).
- `GET /rotations/{rotation_id}` -> rotation status (`STARTED | PENDING_PERSISTED | VERIFIED | COMMITTED | SYNCED | ABORTED`).
- `GET /keys/{key_set_id}/metadata` -> public metadata, states, `grace_until`, `destroyed_at` (never private material).
- `POST /resources/{resource_id}/rewrap` -> re-wraps DEK under active `data` key version.
- `POST /internal/sync` -> HMAC-SHA-256 (`CLUSTER_SYNC_SECRET`) authenticated peer sync; node re-reads authoritative DB.
- `POST /internal/test/arm-crash` -> arms `crash_point()` (guarded by `SANDBOX_MODE=1`).

## 3. Crash Points & Observed Recovery Outcome Table (`tests/test_part2_rotation.py`)

| Crash Point | Process Exit | Recovery Action (`recover_rotations()`) | Active Version After Recovery | Data Decryptable? |
| --- | --- | --- | --- | --- |
| `rotate.before_start` | `os._exit(1)` | None needed (no rotation row) | `v1` | Yes |
| `rotate.after_pending_persisted` | `os._exit(1)` | `aborted` (pending key -> `RETIRED`, wiped) | `v1` | Yes |
| `rotate.before_commit` | `os._exit(1)` | `aborted` (pending key -> `RETIRED`, wiped) | `v1` | Yes |
| `rotate.after_commit` | `os._exit(1)` | `rolled_forward` (outbox dispatched -> `SYNCED`) | `v2` | Yes |
| `rotate.during_sync` | `os._exit(1)` | Outbox/node sync converged | `v2` | Yes |

## 4. Authorization Contract Changes (for Person A)
- `AuthzService.authorize(actor_context, resource_id, permission, *, key_version_id=None, correlation_id=None)` and `IdentityService.verify_identity(..., key_version_id=None)` now validate `key_version_id` via `is_key_acceptable(kv, now, purpose="auth")`.
- Using a `GRACE` key before `grace_until` is allowed and emits `key.grace_used`; using it at/after `grace_until` is denied with `KEY_RETIRED` and emits `key.rejected_after_cutoff`.

## 5. Real Verification Output (Observed)
- `pytest -v tests/`: `36 passed, 103 warnings in 2.24s` (14 existing + 9 Part 1 + 9 Part 2 + 4 multi-node/migration tests).
- `validate.py --entry .../track4_service.py`: `Local scenario passed.` (exit code `0`).
- `ruff check src/identity_keys track4_service.py scripts/seed_sandbox.py scripts/fault.py`: `All checks passed!`
- `mypy`: `Success: no issues found in 15 source files`

## 6. Open Issues / Simulation Limits
- Local tests executed against SQLite (Docker daemon / `psql` not running on host); PostgreSQL 16 + `docker-compose.yml` remain ready for container execution.
- Shared DB (`SELECT ... FOR UPDATE`), env-supplied `WRAP_MASTER_KEY_B64`, and HMAC `CLUSTER_SYNC_SECRET` simulate consensus, KMS/HSM, and mTLS respectively.
