# Security Review (`docs/SECURITY_REVIEW.md`)

## 1. Automated Static & CI Grep Checks (in `src/identity_keys/`)
- **No direct wall-clock calls outside `Clock`:** All timestamps use injectable `Clock.now()` / `Clock.monotonic_ns()`.
- **No secret logging:** `private_key`, `wrapped_private_material`, `passphrase`, `recovery_code`, and `key_material` are never passed to loggers, API responses, or `AuditEmitter`.
- **Constant-time MAC/verifier comparisons:** All digest, HMAC, and scrypt verifier checks use `hmac.compare_digest()`.
- **Single-writer state transitions:** `key_versions.state` is written only by `transition_key()`; `devices.status` by `transition_device_status()`, backed by DB triggers.
- **SQL injection:** All queries use SQLAlchemy 2.x parameterized ORM/Core expressions.
- **API authentication:** Every non-health endpoint verifies the Ed25519-signed bearer token via `require_actor`, except the two enrollment endpoints, which use the dedicated enrollment gate described in the next bullet.
- **Enrollment authorization (P0-1):** `POST /api/v1/enroll/start` and `POST /api/v1/enroll` require either a valid bearer token whose `user_id` equals the enrollment target, or `X-Admin-Enroll-Token` equal to `ADMIN_ENROLL_TOKEN` (constant-time compare). The admin path fails closed (401) when the environment variable is unset or the header is wrong/empty; unauthenticated calls are 401 and cross-user bearer calls are 403. `kind=recovery` (persisted as `re_enroll`) is admin-only. Enrollment start/completion audit events record the authenticated actor (`admin-enroll-token` for admin actions) and the target user.
- **Sandbox-only crash endpoints:** `POST /internal/test/arm-crash` fails closed unless `SANDBOX_MODE=1`.

## 2. Dependency Pinning
- All dependencies are pinned in `requirements.txt`; `pqcrypto==0.4.0` matches the official Track 4 Python 3.12 judging runtime.
