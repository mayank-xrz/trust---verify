# Track 4 evidence from measured runs

Measured on macOS arm64 with Python 3.11.18. See the [raw observations](judge-evidence.json).

## Revocation across independent processes

Three separately running Uvicorn identity nodes share a SQLite database in WAL mode.
Each node accepted the same device and resource before revocation. After the authority
acknowledged the request, parallel HTTP probes counted only explicit `DEVICE_REVOKED`
decisions. No manual sync was used. All nodes had a 250 ms heartbeat.

Times are milliseconds from sending the revocation request. They include the request
and probe delays and bound the time to observed enforcement from above. Database
authorization can see the revocation before the node's local watermark catches up.

| Trial | A first denial | B first denial | C first denial | Last denial | Last watermark |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 4.922 | 6.821 | 6.451 | 6.821 | 252.718 |
| 2 | 5.254 | 5.564 | 6.795 | 6.795 | 238.169 |
| 3 | 5.957 | 7.620 | 6.316 | 7.620 | 258.086 |
| 4 | 6.460 | 6.803 | 8.167 | 8.167 | 230.933 |
| 5 | 5.182 | 6.767 | 5.524 | 6.767 | 243.592 |

## Detector evidence

| Measurement | Result | Scope |
| --- | --- | --- |
| Classification | F1 1.000, 0 false escalations per 1,000 benign events | Shipped synthetic fixture with 1,024 benign and 30 suspicious events |
| Median in-memory evaluation | 0.0025 ms | Time spent evaluating detected suspicious fixture events |
| Median HTTP request to alert response | 0.7012 ms | 21 requests to the localhost demo endpoint for a synthetic event |

The HTTP measurement includes request handling, audit logging, rule evaluation and the
response carrying the alert. It does not measure external log transport or dashboard
polling. No independent labelled dataset or multi-host deployment was available for this run.

## Reproduce

```sh
python -m scripts.measure_live_revocation --runs 5
python -m scripts.measure_detector_http
python -m scripts.evaluate_detector
```

To score independent labels, run `python -m scripts.evaluate_detector --dataset path/to/labels.jsonl`.
Use one event per JSONL row in the [fixture format](../tests/fixtures/track4_detector.jsonl),
with `expected_suspicious` set to a boolean. Include benign and suspicious events.
