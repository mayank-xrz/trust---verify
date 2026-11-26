# Security Review (`docs/SECURITY_REVIEW.md`)

## 1. Automated Static & CI Grep Checks (in `src/identity_keys/`)
- **No direct wall-clock calls outside `Clock`:** All timestamps use injectable `Clock.now()` / `Clock.monotonic_ns()`.
- **No secret logging:** `private_key`, `wrapped_private_material`, `passphrase`, `recovery_code`, and `key_material` are never passed to loggers, API responses, or `AuditEmitter`.
- **Constant-time MAC/verifier comparisons:** All digest, HMAC, and scrypt verifier checks use `hmac.compare_digest()`.
- **Single-writer state transitions:** `key_versions.state` is written only by `transition_key()`; `devices.status` by `transition_device_status()`, backed by DB triggers.
- **SQL injection:** All queries use SQLAlchemy 2.x parameterized ORM/Core expressions.
- **API authentication:** Every non-health endpoint verifies the Ed25519-signed bearer token via `require_actor`, except the two enrollment endpoints, which use the dedicated enrollment gate described in the next bullet.
- **Enrollment authorization (P0-1):** `POST /api/v1/enroll/start` and `POST /api/v1/enroll` require either a valid bearer token whose `user_id` equals the enrollment target, or `X-Admin-Enroll-Token` equal to `ADMIN_ENROLL_TOKEN` (constant-time compare). The admin path fails closed (401) when the environment variable is unset or the header is wrong/empty; unauthenticated calls are 401 and cross-user bearer calls are 403. `kind=recovery` (persisted as `re_enroll`) is admin-only. Enrollment start/completion audit events record the authenticated actor (`admin-enroll-token` for admin actions) and the target user.
- **Sandbox-only crash endpoints:** `POST /internal/test/arm-crash` requires a valid `X-Admin-Enroll-Token` (constant-time compare against `ADMIN_ENROLL_TOKEN`, failing closed when unset) **and** `SANDBOX_MODE=1`; `arm_crash_point()` re-checks the sandbox flag. Unknown crash points are rejected.
- **Readiness:** `GET /readyz` returns 503 unless a live database query succeeds and the wrap master key is configured; `GET /healthz` remains a liveness-only probe.
- **Authentication rate limits (P1-7):** `/api/v1/auth/challenge` and `/api/v1/auth/verify` use a per-device fixed-window counter in `rate_limits`; exceeding it locks the scope and emits `ALERT.auth_rate_limit`. Expired auth challenges are swept after a one-hour retention window.
- **Signing-key configuration (P1-5):** `TOKEN_SIGNING_SEED_B64` is required and must decode to 32 bytes; `TokenAuthority` and `ReenrollmentService` fail closed (`STATE_UNAVAILABLE`) instead of minting ephemeral keys. `CLUSTER_SYNC_SECRET` and `WRAP_MASTER_KEY_B64` are likewise required for their operations.

## 2. Dependency Pinning
- All dependencies are pinned in `requirements.txt` (including `pqcrypto==1.0.0`, `cryptography==42.0.8`, `sqlalchemy==2.0.58`, `alembic==1.14.0`, `fastapi==0.111.0`).
