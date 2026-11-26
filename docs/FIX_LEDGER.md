# Audit Fix Ledger

Autonomous remediation loop for the Track #4 audit. One logical change per
commit. Every number below must be reproducible from the command recorded in
`docs/MEASUREMENTS.md`.

Environment: Darwin 25.6.0 arm64 (Apple M-series), Python 3.11.16, Node
v26.13.1, git 2.55.0. Baseline `origin/main` at clone time: `fa1f243` (the
prompt's `f3e38a5` plus one prior detector fix); baseline suite: **218 passed**.

| ID | Status | Commit | Evidence | Notes |
|---|---|---|---|---|
| P0-1 | DONE | `1c2678d` | `pytest tests -q` -> 222 passed; 4 new authz tests; takeover PoC 401; `doc-check` PASS; `run_demo.sh` PASS | ruff/mypy and `verify-logs` fail identically on the untouched baseline (see Gate notes); no new findings from this change |
| P0-2 | DONE | `9f4f06a` | `tests/test_docs_drift.py`; `README.md` and brief render "video pending" when `DEMO_VIDEO_URL` is unset | Demo video recording/upload is BLOCKED-HUMAN; see `docs/DEMO_VIDEO.md` |
| P0-3 | DONE | `bcc5b69` + `6a1fb83` | `scripts/benchmark.py`, `scripts/eval_detector.py`, `reports/measurements.json`; detector eval labelled synthetic-only | Provenance recorded in `docs/MEASUREMENTS.md` |
| P0-4 | DONE | `c7d436d` | `make gates` -> 233 passed at commit; `make demo` PASS; `tests/test_clean_machine_setup.py` | `make setup` creates `.venv` with `python3.11` and enables hooks |
| P0-5 | DONE | `364bfa0` | `make brief`; PDF exactly 2 pages; dead URL removed | Brief generated from `reports/measurements.json` |
| P0-6 | DONE | `9b25323` | `pytest .` -> 230 passed at commit | Archived sub-projects quarantined; see `docs/ARCHIVED.md` |
| P1-1 | DONE | `73ae6fc` | 5 new tests in `tests/test_demo_identity.py`; suite 242 passed at commit; `make demo` PASS | Demo node fails closed on unknown senders; no default keys |
| P1-2 | DONE | `fdbcfd8` | 5 new tests in `tests/test_track4_service_hardening.py`; suite 246 passed at commit | Single-use challenge per actor/asset; anchor on every mutation; UTC timestamps |
| P1-3 | DONE | `d82cedb` | 5 new tests in `tests/test_arm_crash_gate.py`; covered by the 257-pass run after P1-4 | Requires admin token and `SANDBOX_MODE=1` |
| P1-4 | DONE | `b84b290` | 6 static compose tests; suite 257 passed at commit | Runtime `docker compose up` BLOCKED on this host (no Docker) |
| P1-5 | DONE | `0cb3aa5` | 6 new tests in `tests/test_env_token_hardening.py`; suite 262 passed at commit | Missing/malformed signing seeds fail closed |
| P1-6 | DONE | `27c46fa` | 4 new tests in `tests/test_alert_contract.py`; suite 267 passed at commit; `make demo` PASS | Alerts carry `event_id` and `services[]` |
| P1-7 | DONE | `c143757` | 4 new tests in `tests/test_readyz_and_rate_limits.py`; suite 271 passed at commit | `/readyz`, per-device auth limits, challenge sweeper |
| P1-8 | DONE | `f0d27b0` | 5 new tests in `tests/test_docs_drift.py`; `make gates` -> 277 passed | Handoff/security docs match current endpoints and gates |
| P2-1 | TODO | — | — | CI matrix + gates |
| P2-2 | TODO | — | — | Missing negative/fuzz tests |
| P2-3 | TODO | — | — | Benchmark methodology |
| P2-4 | TODO | — | — | `docs/VALIDATION.md` |
| P3 | TODO | — | — | Polish batch |

## P0-1 evidence (2026-11-27)

Commit: `1c2678d693452e1a50760a29e3bcf8dfa9122057`.

Reproduction before the fix (new regression tests, pre-fix code):

```
$ .venv/bin/python -m pytest tests/test_phase2_authz.py -q \
    -k "enroll_start_requires or enroll_completion or takeover or admin_token_fails"
4 failed
# unauthenticated /api/v1/enroll/start returned 200; forged /api/v1/enroll returned 200
```

After the fix:

```
$ .venv/bin/python -m pytest tests/test_phase2_authz.py -q \
    -k "enroll_start_requires or enroll_completion or takeover or admin_token_fails"
4 passed

$ .venv/bin/python -m pytest tests -q
222 passed, 274 warnings in 11.64s

$ .venv/bin/python -m unittest tests.test_crypto -q
Ran 24 tests ... OK

$ .venv/bin/python -m compileall -q src track4_service.py demo scripts
(exit 0)

$ .venv/bin/python -m src.cli doc-check
{"doc_check": "PASS", ...}   # exit 0

$ .venv/bin/python scripts/benchmark.py
(exit 0)

$ PATH="$PWD/.venv/bin:$PATH" ./scripts/run_demo.sh
🎉 WALKTHROUGH DEMO COMPLETED SUCCESSFULLY   # exit 0
```

Regression coverage added in `tests/test_phase2_authz.py`:

- `test_enroll_start_requires_owner_bearer_or_admin`: unauth 401, cross-user 403,
  owner 200, admin 200, recovery 403 for non-admin, recovery 200 for admin, and
  the admin actor is present in `enrollment.started` audit metadata.
- `test_enroll_start_admin_token_fails_closed`: wrong token 401; env unset 401.
- `test_enroll_completion_requires_owner_bearer_or_admin`: unauth 401,
  cross-user 403, owner 200, admin 200, recovery completion 403 for non-admin.
- `test_unauthenticated_enrollment_takeover_is_blocked`: the audit PoC
  (`/enroll/start` for a victim, then `/enroll` with an attacker key) now fails
  at step 1 with 401 and creates no device.

`tests/test_phase3_multinode.py` was updated to use the admin enrollment path.
The old assertion exercised unauthenticated enrollment, which is the behavior
P0-1 removes; the test's multi-node purpose is unchanged.

## Gate notes (baseline vs. this commit)

`ruff` and `mypy` fail on the untouched baseline with exactly the same output
(15 ruff findings, 15 mypy errors in `src/crypto`, `src/audit`, and unrelated
tests). `git stash` + rerun + `diff` showed zero new findings from P0-1.
`python -m src.cli verify-logs` also exits 1 on the untouched baseline
(`No signed checkpoint found`); the CLI self-check writes an unsigned log while
the verifier requires signatures. These are tracked under P2-1/P2-4 and were
not fixed here to keep this commit scoped to P0-1.

`./scripts/run_demo.sh` invokes bare `python3`; on this machine that resolves to
Python 3.15 without project dependencies. With `.venv/bin` on `PATH` the demo
passes end-to-end. P0-4 will make the clean-machine invocation explicit.

## P0-2 through P1-8 evidence (2026-11-27)

Environment: Darwin 25.6.0 arm64 (Apple M-series), Python 3.11.16,
Node v26.13.1, git 2.55.0. All commands run in a fresh clone at `/tmp/tv-fix`.

Authoritative gate run at `f0d27b0` (after P1-8):

```
$ make gates
ruff check .                     -> All checks passed!
mypy                             -> Success: no issues found in 20 source files
python -m src.cli verify-logs    -> exit 0
pytest . -q                      -> 277 passed, 302 warnings in 11.76s
```

Item-specific regression files (all included in the 277-pass run):

| ID | Test file | Tests |
|---|---|---|
| P0-4 | `tests/test_clean_machine_setup.py` | clean-machine setup contract |
| P1-1 | `tests/test_demo_identity.py` | 5 |
| P1-2 | `tests/test_track4_service_hardening.py` | 5 |
| P1-3 | `tests/test_arm_crash_gate.py` | 5 |
| P1-4 | `tests/test_compose_hardening.py` | 7 |
| P1-5 | `tests/test_env_token_hardening.py` | 6 |
| P1-6 | `tests/test_alert_contract.py` | 4 |
| P1-7 | `tests/test_readyz_and_rate_limits.py` | 4 |
| P1-8 | `tests/test_docs_drift.py` | 5 |

Demo and measurement commands:

```
$ make demo
WALKTHROUGH DEMO COMPLETED SUCCESSFULLY   (exit 0; alerts include Event ID + Services)

$ .venv/bin/python scripts/eval_detector.py
synthetic set: TP=25 FP=0 TN=100 FN=0 F1=1.00 FP/1k=0  (labelled synthetic-only)

$ make brief
docs/project_brief.pdf                   (2 pages; no dead demo URL)
```

Known environment limitation: Docker is not installed on this host, so
`docker compose up` was not executed. `docker compose config` and the compose
contract are covered statically by `tests/test_compose_hardening.py`; runtime
container validation remains a CI/manual step.

P0-2 remains BLOCKED-HUMAN only for recording/uploading the 5-minute video.
The code and published artifacts render "video pending" until
`DEMO_VIDEO_URL` is supplied.
