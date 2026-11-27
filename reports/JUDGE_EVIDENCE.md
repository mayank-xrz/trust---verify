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

## Timestamped device-key revocation and recovery

Authority record `ed83eb3b-b061-45ec-92b8-b1e94d9ea2fc`, commit sequence 1.
The device's enrolled Ed25519 key was used to authenticate before revocation. The
authority revoked that device credential. Each first denial is the probe runner's
UTC receipt time for an explicit `DEVICE_REVOKED` decision. The authority timestamp
is written inside the transaction before commit, so elapsed time includes the
remaining commit work, HTTP acknowledgement, and probe delay.

| Node | Authority revocation timestamp (UTC) | First confirmed denial (UTC) | Elapsed ms |
| --- | --- | --- | ---: |
| node-a | 2026-11-26T23:31:32.055441+00:00 | 2026-11-26T23:31:32.060461+00:00 | 5.020 |
| node-b | 2026-11-26T23:31:32.055441+00:00 | 2026-11-26T23:31:32.062053+00:00 | 6.612 |
| node-c | 2026-11-26T23:31:32.055441+00:00 | 2026-11-26T23:31:32.061131+00:00 | 5.690 |

Last confirmed rejection: **6.612 ms**. On all three nodes, Alice's replacement
credential worked after recovery-code re-enrollment, her old credential remained
revoked, and Bob retained access to his resource.

## Detector evidence

Both datasets are synthetic. The original fixture is regression evidence. The second
fixture uses a different seeded generator with new identities, services, actions,
timing, clock offsets, and out-of-order arrivals. It includes explicit allow/deny entitlement context for report-archive downloads.

| Dataset | Alert policy | F1 | Median time to alert (ms) | False alerts / 1,000 benign |
| --- | --- | ---: | ---: | ---: |
| regression | All severities | 0.8333 | 0.0020 | 11.7188 |
| regression | Non-LOW alerts | 1.0000 | 0.0020 | 0.0000 |
| challenge | All severities | 0.8675 | 0.0019 | 10.5769 |
| challenge | Non-LOW alerts | 1.0000 | 0.0019 | 0.0000 |

Each event is counted once per policy. The median measures in-memory time to an
alert for correctly detected suspicious events. The original fixture has 1,024
benign and 30 suspicious events. The second has 1,040 benign and 36 suspicious events.
The previous challenge fixture carried no export entitlement context, and both policies missed all six suspicious archive downloads (30/36 detected). With explicit denial context and matching authorized downloads, both policies detect 36/36. The Non-LOW policy still produces zero false alerts on the fixture. Counting LOW notices produces the same 11 benign stale-key alerts. The new rule requires an explicit denial from trusted event metadata. Events with missing entitlement context remain outside this rule.

The separate authenticated localhost HTTP demo measured **0.8994 ms median** over 21 requests.
That includes request handling, audit logging, evaluation and the alert response.

## Reproduce

```sh
python -m scripts.measure_live_revocation --runs 1 # add --json for raw observations
python -m scripts.measure_detector_http
python -m scripts.evaluate_detector
```

The fixture scores measure rule behavior on labelled synthetic data. There is no independent holdout score in this submission. To score independent labels, run `python -m scripts.evaluate_detector --dataset path/to/labels.jsonl`.
Use one event per JSONL row in the [fixture format](../tests/fixtures/track4_detector.jsonl),
with `expected_suspicious` set to a boolean. Include benign and suspicious events.

Regenerate the second dataset with `python -m scripts.generate_detector_challenge`.
