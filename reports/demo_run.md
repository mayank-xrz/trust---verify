# Live Security Assessment

Run `make demo` after activating the project virtual environment. The run below completed on macOS arm64 with Python 3.15.2. Three loopback HTTP node processes used separate temporary state directories, plus a local detector process. The script exits with an error if the expected policy results, peer receipt evidence, or audit verification fail.

| Check | Observed result |
| --- | --- |
| Protected delivery | Node A sent to B and C. Each recipient read the payload with its own inbox credential. |
| Rotation | B accepted the retiring key during grace, accepted its new key, and denied first delivery under the old key after cutoff. |
| Receiver revocation | B explicitly denied the first delivery of an envelope sealed for the now-revoked key. |
| Peer application | Both A and C acknowledged application and blocked fresh sends under B’s revoked key. The acknowledgements matched audit sequences 9 and 4. |
| Unaffected traffic and recovery | C still received a message. A refreshed B’s key bundle after rotation and B received a message with its replacement key. |
| Recovery and evidence | The WAL reader discarded a torn entry, the backup verifier rejected damaged data, and all three audit chains verified. |
| Explainable alerts | The operator saw the policy denials for a disallowed service path and an unauthenticated key administration request. |

In this run, the operator request took **10.64 ms** through peer acknowledgement. The first receiver denial was observed **12.95 ms** after the client started the operator request. The client checked denial after the operator response returned, so that observation includes the peer acknowledgement wait. These are two observations from one loopback run. The [device-authorization benchmark](revocation_latency.md) separately measures commit-to-denial and watermark convergence with shared SQLite.

## Extended live checks

The expanded `make demo` starts an identity authority and a separate sender and receiver. It delivers a message using an enrolled device, revokes that device, checks that its fresh send receives `403 DEVICE_REVOKED`, then delivers a message from a second device. With the sender stopped, the receiver revokes its recipient key. On restart the sender starts with the old peer key, pulls the receiver's durable snapshot, persists the missed revocation locally, rejects the old key, and seals successfully after refreshing the replacement bundle.

The walkthrough video shows both extended checks. Rerun them with `python -m scripts.demo_device_security`.

[Walkthrough video](../docs/demo-walkthrough.mp4)

## Longer rotation window

`DEMO_GRACE_SECONDS=30 make demo` passed the in-grace and post-cutoff checks and all 12 acceptance checks in a separate localhost run. It exercised individual protected deliveries. It did not measure sustained traffic or multi-host behavior.
