# Clean-build and database evidence

The authoritative evidence is produced on every push and pull request by
`.github/workflows/ci.yml`; this document describes the gates and does not claim
that an unobserved run passed.

## Clean Python validation

`make validate` creates `.venv`, installs the pinned `requirements.txt`, and runs
Ruff, the full pytest suite, documentation checks, and the offline two-page
submission check. The command does not depend on a pre-existing environment.

## PostgreSQL 16

The `postgresql` CI job starts an official `postgres:16-alpine` service, applies
the complete Alembic migration chain, then runs
`tests/integration/test_postgres_runtime.py`. The smoke test confirms the
PostgreSQL dialect, exercises the PostgreSQL `ON CONFLICT` authentication-rate
counter, and verifies that the audit outbox uses `JSONB`.

## Docker

The `docker` CI job performs a `--no-cache` BuildKit build, runs the test suite
inside the image, exercises the organizer adapter with a read-only root
filesystem, and checks that the image contains no `.env`, PEM, or key files.
It uploads BuildKit metadata and `docker image inspect` output as the
`docker-build-evidence` artifact. A successful workflow run—not this prose—is
the evidence that these gates passed for a particular commit.
