# Archived sub-projects

Two standalone sub-projects are retained in this repository as provenance for
the Track #4 work, but they are **not** part of the root submission and are
excluded from the root pytest run:

- `role3_logging_detector/` — the Role 3 logging/detector module. Its tests
  import from its own `src/` package (`src.audit_logger`), which collides with
  the root `src/` package when collected from the repository root.
- `prototypes/person_a/` — the original Person A local crypto prototype. It has
  its own `crypto/` package and its own `track4_service.py` adapter.

Both directories are configured out of the root suite in `pyproject.toml`
(`norecursedirs` plus explicit `--ignore`). Run them from inside their own
directories if you need to inspect them:

```sh
cd role3_logging_detector && python3 -m unittest discover -s tests -v
cd prototypes/person_a && python3 -m unittest discover -s tests -v
```

The canonical, shipped implementation lives in `src/` and is exercised by
`tests/`. Nothing in this note changes the shipped behavior.
