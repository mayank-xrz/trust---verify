# Part 3 Handoff (`docs/HANDOFF_3.md`) — Revocation, Latency & Secure Re-Enrollment

## 1. Revocation & Re-Enrollment API Reference (`src/identity_keys/api.py`)
- `POST /revocations/device` (`device_id`, `reason_code`) -> `{revocation_id, target_type, target_id, commit_seq, idempotent_replay}`
- `POST /revocations/key-version` (`key_version_id`, `reason_code`) -> revokes key version (`REVOKED`)
- `POST /revocations/permission` (`user_id`, `grant_id_or_perm`, `reason_code`) -> revokes `ResourceGrant`
- `POST /rotations/emergency` (`key_set_id`, `idempotency_key`) -> zero-grace rotation transitioning old `ACTIVE` directly to `REVOKED`
- `GET /node/sync-status` -> `{node_id, watermark, db_reachable, stale, last_sync_at, lag_commit_seq}`
- `POST /reenroll/recovery-codes` -> generates 10 128-bit one-time recovery codes (salted `scrypt` verifiers stored)
- `POST /reenroll/approve` -> admin with `device:approve_reenroll` signs bound approval
- `POST /reenroll/begin` / `POST /reenroll/complete` -> 10-min nonce + atomic device replacement + `replaced_by_device_id`

## 2. Sync Protocol, Watermark & Stale-Node Semantics
- Gapless `commit_seq` assigned inside the revoking transaction via `commit_seq_counter` (`SELECT ... FOR UPDATE`).
- Nodes maintain `revocation_watermark` and advance it strictly over contiguous `commit_seq` via `POST /internal/sync` (HMAC-signed hint -> DB pull) and periodic pull.
- Any node whose `last_sync_at` exceeds `STALE_AFTER_MS` (default 2000 ms) or cannot reach the DB fails closed on `/api/v1/authorize` with `reason_code="STALE_STATE"`.

## 3. Observed Latency Headline Numbers (`reports/revocation_latency.md`, M=20, seed=42)
- **`push_plus_pull` (250 ms pull):** min `7.732 ms`, median `10.801 ms`, p95 `16.675 ms`, p99 `16.811 ms`, max `16.845 ms`.
- **`pull_only_250ms` (push off):** min `6.631 ms`, median `8.796 ms`, p95 `14.506 ms`, p99 `23.48 ms`, max `25.724 ms`.

## 4. Real Verification Output (Observed)
- `pytest -v tests/`: `43 passed` (all Part 1, Part 2, Part 3, and existing repo tests).
- `validate.py --entry .../track4_service.py`: `Local scenario passed.` (exit code `0`).
- `ruff check` & `mypy`: clean across all `src/identity_keys` and `scripts/` targets.

## 5. Open Issues / Simulation Limits
- Single-host `TestClient` + SQLite used for local latency benchmark (`scripts/measure_revocation.py --ci`); container network latency and PostgreSQL 16 `docker-compose.yml` execution remain for Part 4/integration.
