# Phase 0 Inspection — Trust, But Verify (Person B)

## 1. Existing Repository Findings (`mayank-xrz/trust---verify`)
- **Language & Existing Stack:** Python 3.11+ (`fastapi==0.111.0`, `uvicorn==0.30.0`, `cryptography==42.0.8`, `jsonschema==4.22.0`, `pytest==8.2.1`, `liboqs-python==0.10.0`).
- **Existing Modules (Preserved Untouched):**
  - Person A (`src/crypto/`): `pqc_kem.py`, `pqc_sig.py`, `session.py`, `messaging.py`.
  - Person C (`src/audit/`, `src/detector/`): `logger.py`, `verifier.py`, `rules.py`, `graph_lateral.py`, `clock_sync.py`, `metrics.py`.
  - Person D (`src/node/`, `scripts/`, `docker-compose.yml`, `docs/`): `server.py`, `operator_cli.py`, `benchmark.py`, `run_demo.sh`.
  - Existing `tests/`: 14 `unittest` tests pass (`Ran 14 tests in 0.162s OK`).
- **Missing for Person B & Toolkit:** No `identity_keys` package, no SQLAlchemy/Alembic DB schema, no `track4_service.py` at repo root.

## 2. Track 4 Adapter Contract v1 (`Track-4-Toolkit/docs/adapter-v1.md`)

| Operation | Request Fields | Response & Behavior | Person B Implementation |
| --- | --- | --- | --- |
| `setup` | `owners`, `contents`, `disabled`, `key_material` | Init state, return `{"ready": true}`, never log `key_material` | `identity_keys` adapter -> DB seed/reset |
| `read` | `actor`, `asset`, `request_id` | `{"decision": "allow", "body": ...}` or `{"decision": "deny"}` | `AuthzService.authorize()` + audit outbox |
| `revoke` | `actor` | Revoke actor/devices across nodes, persist, return `{}` | `RevocationService` (append-only) |
| `audit` | `request_id` | Return `{"request_id", "decision"}` | Query `audit_outbox` / decision record |
| `protected_read` | `actor`, `asset`, `challenge`, `public_key` | ML-KEM-768 encaps + HMAC-SHA256(`ss`, `challenge + body`) | `pqc_compat` + `AuthzService` |

**Validator Command & Baseline Failure:**
- Command: `python3 ../Track-4-Toolkit/validate.py --entry ./track4_service.py`
- Baseline on empty starter: `FAIL [setup] validation stopped: Adapter exited unsuccessfully. Check dependencies and local state handling.`

## 3. Audit Event & Peer Interfaces
- **Audit Contract (`schemas/audit_event.schema.json` & `src/audit/logger.py`):** Structured single-line JSON with `sequence`, `event_id` (UUID), `timestamp_ns`, `node_id`, `service`, `action`, `subject`, `resource`, `status` (`SUCCESS|DENIED|SUSPICIOUS|ERROR`), `metadata`, `prev_hash`, `entry_hash` (`SHA-256(prev_hash || canonical_json)`), optional `signature` (Base64). Control chars/newlines stripped.
- **Person A Interface:** Calls `AuthzService.authorize(actor_ctx, resource_id, permission)` and `KeyService.get_public_key_metadata(requester, target)`.
- **Person C Interface:** `AuditDispatcher` delivers `audit_outbox` events into `AuditLogger` / `audit_event.schema.json` format.

## 4. Open Questions & 15-Line Implementation Plan
- *Open Question:* Local machine lacks `psql`/running Docker daemon; SQLite dialect fallback with identical constraints/triggers will run local tests while PostgreSQL 16 + Alembic migrations target `docker-compose.yml`.
1. Add `pyproject.toml`, `.env.example`, and pin dependencies (`sqlalchemy`, `alembic`, `cryptography`, `pqcrypto`, `fastapi`, `uvicorn`, `ruff`, `mypy`).
2. Implement `identity_keys/` package (`clock.py`, `errors.py`, `crypto.py`, `db.py`, `models.py`).
3. Create Alembic migration `0001_initial_schema.py` with all tables, CHECK/UNIQUE/FK, partial unique index, and immutability triggers.
4. Test Alembic `upgrade`/`downgrade` and DB constraint enforcement.
5. Implement `enrollment.py`, `auth.py` (signed bearer tokens), `authz.py` (fail-closed), and `key_metadata.py`.
6. Implement FastAPI routes (`api.py`) and `scripts/seed_sandbox.py`.
7. Implement `audit_outbox.py` (`AuditEmitter` + `AuditDispatcher` matching `src/audit/logger.py`).
8. Implement `track4_service.py` at repo root for Adapter v1 (`setup`, `read`, `revoke`, `audit`, `protected_read`).
9. Update `docker-compose.yml` (`postgres` + `node-a`, `node-b`, `node-c`) and add `scripts/fault.py`.
10. Run full `pytest`, `validate.py`, `ruff`, `mypy`, write `docs/HANDOFF_1.md`, and push each phase to GitHub.
