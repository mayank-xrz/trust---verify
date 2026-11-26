# Revocation Propagation Latency Report

- **Measurement method:** Single-coordinator `time.monotonic_ns()` (`t_enforced[node] - t_commit`) with 5 ms parallel probe loop across `node-a`, `node-b`, `node-c`.
- **Seed:** `42` | **M:** `20` per scenario | **Limits:** Single-host `TestClient` + SQLite, includes 5 ms probe granularity.

| Scenario | Push | Pull Interval (ms) | Overall Min (ms) | Median (ms) | P95 (ms) | P99 (ms) | Max (ms) |
| --- | --- | --- | --- | --- | --- | --- | --- |
| push_plus_pull | True | 250 | 7.732 | 10.801 | 16.675 | 16.811 | 16.845 |
| pull_only_250ms | False | 250 | 6.631 | 8.796 | 14.506 | 23.48 | 25.724 |
