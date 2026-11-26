# Part 1 Handoff (`docs/HANDOFF_1.md`) — Person B: Identity, Key Lifecycle & Storage

## 1. Schema Summary (`alembic/versions/0001_initial_schema.py`)
- **Core Tables:** `users`, `devices`, `roles`, `permissions`, `role_permissions`, `user_roles`, `resources`, `resource_grants`, `key_versions`, `revocations`, `auth_challenges`.
- **Reserved Tables (for Prompts 2–4):** `rotations`, `outbox`, `node_sync_state`, `audit_outbox`, `enrollments`, `recovery_credentials`, `backups`.
- **DB-Enforced Constraints & Triggers:**
  - `devices`: `CHECK (status != 'revoked' OR revoked_at IS NOT NULL)`, `UNIQUE (public_key_fingerprint)`, trigger `trg_devices_no_unrevoke` raising on any `status` transition away from `revoked`.
  - `key_versions`: `UNIQUE (key_set_id, version)`, partial unique index `uq_key_versions_one_active_per_set` (`WHERE state = 'ACTIVE'`).
  - `revocations`: `commit_seq` monotonic sequence, triggers `trg_revocations_no_update` / `trg_revocations_no_delete` (or `trg_revocations_append_only` on PostgreSQL) rejecting `UPDATE`/`DELETE`.

## 2. Public Service Methods & FastAPI Endpoints
- `IdentityService` (`src/identity_keys/services.py`):
  - `start_enrollment(user_id: str, kind: str = "first", ttl_seconds: int = 300) -> dict[str, str]`
  - `enroll_device(*, enrollment_id, nonce, label, public_key_b64, proof_of_possession_b64, public_key_alg="Ed25519") -> dict[str, Any]`
  - `issue_challenge(device_id: str, ttl_seconds: int = 120) -> dict[str, str]`
  - `verify_identity(*, device_id, challenge, signature_b64) -> dict[str, Any]`
- `AuthzService` (`src/identity_keys/services.py`):
  - `authorize(actor_context: ActorContext, resource_id: str, permission: str, *, correlation_id: str | None = None) -> AuthzDecision`
- `KeyMetadataService` (`src/identity_keys/services.py`):
  - `get_public_key_metadata(requester: ActorContext, target_user_id: str) -> list[dict[str, Any]]`
- **FastAPI Endpoints (`src/identity_keys/api.py`):**
  - `GET /healthz` (liveness), `GET /readyz` (database + wrap-key readiness), `GET /node/status`
  - `POST /api/v1/enroll/start`, `POST /api/v1/enroll`
  - `POST /api/v1/auth/challenge`, `POST /api/v1/auth/verify` (per-device rate limited)
  - `POST /api/v1/authorize` (Bearer token required), `GET /api/v1/keys/metadata/{target_user_id}` (Bearer token required)
  - `POST /internal/test/arm-crash` (admin token + `SANDBOX_MODE=1` only)

## 3. Authentication & Fail-Closed Rules
- **Auth Scheme:** Device proves possession of its Ed25519 private key over a server-issued single-use expiring challenge (`verify_identity`), receiving an Ed25519-signed bearer token (`user_id`, `device_id`, `iat`, `exp`, `jti`).
- **Actor Binding:** `authorize()` derives the actor strictly from `ActorContext` (verified bearer token), ignoring any `actor_id` or `label` in request bodies.
- **Fail-Closed:** Any database error or unreachable state inside `AuthzService.authorize()` returns `AuthzDecision(allowed=False, reason_code="STATE_UNAVAILABLE", ...)`.

## 4. Audit Event Contract (`src/identity_keys/audit_outbox.py`)
- `AuditEmitter.emit(session, ...)` writes structured JSON events (`event_id`, `actor_id`, `device_id`, `node_id`, `action`, `target`, `timestamp`, `timestamp_ns`, `correlation_id`, `outcome`, `reason_code`, `metadata`) to `audit_outbox` in the **same DB transaction** as the state change.
- All string fields are sanitized via `AuditLogger.sanitize_field()` (stripping `\r`, `\n`, `\x00-\x1f`, `\x7f-\x9f`).
- `AuditDispatcher.dispatch_pending()` delivers outbox rows to `src/audit/logger.py` (`AuditLogger`), preserving the `SHA-256` hash chain.

## 5. Toolkit Adapter Status (`track4_service.py`)
- **Done:** `setup`, `read`, `revoke`, `audit`, `protected_read` (raw `ML-KEM-768` encapsulation + `HMAC-SHA-256` over `challenge + body`), `threat-model.json`.
- **Also implemented in later parts:** multi-node key rotation state machine, cross-node revocation sync + propagation latency measurement, device re-enrollment & recovery credentials, and cryptographic backup/restore.
- **Adapter hardening:** challenges are single-use per `(actor, asset)` across request ids, audit entries carry UTC timestamps, and every mutation advances the out-of-band audit anchor.

## 6. Test & Validator Output (Historical Snapshot)

The pass counts below were captured when this handoff was written. Current,
reproducible results live in `docs/FIX_LEDGER.md` and `docs/MEASUREMENTS.md`.

- `validate.py --entry .../track4_service.py`: `Local scenario passed.` (exit code `0`)
- `ruff check src/identity_keys track4_service.py scripts/seed_sandbox.py scripts/fault.py`: `All checks passed!`

## 7. Known Limitations
- Local verification ran against SQLite (with equivalent CHECK, UNIQUE, partial unique index, and triggers) because the Docker daemon and `psql` were not running on this host; PostgreSQL 16 + `docker-compose.yml` (`postgres`, `node-a`, `node-b`, `node-c`) are configured and ready for container execution.
