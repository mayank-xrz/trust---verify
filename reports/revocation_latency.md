# Revocation Propagation Latency Report

Measured from SQLAlchemy's successful commit callback to the last of three nodes returning
`DEVICE_REVOKED` or reporting a converged watermark. Each node must allow the same device
and resource before the measured revocation. Each node waits 5 ms between probe cycles.

Seed **42**, **20** trials per scenario. Single-host TestClient with shared SQLite
in WAL mode. In push mode, node-a sends signed HTTP hints in-process to node-b and node-c.
All nodes run a 250 ms heartbeat in both scenarios. Authorization reads the shared
database, so a node can deny a revoked device before its sync watermark catches up.
Timings include request handling and probe delay.

| Scenario | Last denial p50 | Last denial p95 | Last denial max | Last sync p50 | Last sync p95 | Excluded denials |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| push_plus_pull | 10.158 ms | 11.905 ms | 13.219 ms | 234.657 ms | 244.836 ms | 0 |
| pull_only_250ms | 6.232 ms | 8.558 ms | 8.996 ms | 241.092 ms | 244.899 ms | 0 |
