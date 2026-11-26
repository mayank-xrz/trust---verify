# Security Review (`docs/SECURITY_REVIEW.md`)

## 1. Automated Static & CI Grep Checks (in `src/identity_keys/`)
- **No direct wall-clock calls outside `Clock`:** All timestamps use injectable `Clock.now()` / `Clock.monotonic_ns()`.
- **No secret logging:** `private_key`, `wrapped_private_material`, `passphrase`, `recovery_code`, and `key_material` are never passed to loggers, API responses, or `AuditEmitter`.
- **Constant-time MAC/verifier comparisons:** All digest, HMAC, and scrypt verifier checks use `hmac.compare_digest()`.
- **Single-writer state transitions:** `key_versions.state` is written only by `transition_key()`; `devices.status` by `transition_device_status()`, backed by DB triggers.
- **SQL injection:** All queries use SQLAlchemy 2.x parameterized ORM/Core expressions.
- **API authentication:** Every non-health endpoint (`/api/v1/authorize`, `/rotations`, `/revocations/*`, `/keys/*`, `/resources/*/rewrap`) verifies the Ed25519-signed bearer token via `require_actor`.
- **Sandbox-only crash endpoints:** `POST /internal/test/arm-crash` fails closed unless `SANDBOX_MODE=1`.

## 2. Dependency Pinning
- All dependencies are pinned in `requirements.txt` (including `pqcrypto==1.0.0`, `cryptography==42.0.8`, `sqlalchemy==2.0.58`, `alembic==1.14.0`, `fastapi==0.111.0`).
