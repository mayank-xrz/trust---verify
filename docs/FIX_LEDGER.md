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
| P0-2 | TODO | — | — | Remove dead demo URL; add shot list + `DEMO_VIDEO_URL`; BLOCKED-HUMAN for the video itself |
| P0-3 | TODO | — | — | One source of measured truth; rewrite benchmark/eval; purge stale numbers |
| P0-4 | TODO | — | — | README + Makefile clean-machine setup |
| P0-5 | TODO | — | — | Regenerate 2-page brief with only defensible claims |
| P0-6 | TODO | — | — | Make `pytest .` exit 0 |
| P1-1 | TODO | — | — | Demo node fail-closed identity |
| P1-2 | TODO | — | — | `track4_service.py` replay/timezone/audit-chain hardening |
| P1-3 | TODO | — | — | Admin + sandbox gate on `/internal/test/arm-crash` |
| P1-4 | TODO | — | — | Compose/Docker hardening |
| P1-5 | TODO | — | — | Env + token hardening |
| P1-6 | TODO | — | — | Alert contract (`event_id`, `services[]`) |
| P1-7 | TODO | — | — | `/readyz`, rate limits, challenge sweeper |
| P1-8 | TODO | — | — | Documentation drift |
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
