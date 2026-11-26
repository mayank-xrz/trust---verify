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

In this run, the operator request took **19.83 ms** through peer acknowledgement. The first receiver denial was observed **23.39 ms** after the client started the operator request. The client checked denial after the operator response returned, so that observation includes the peer acknowledgement wait. These are two observations from one loopback run. The [device-authorization benchmark](revocation_latency.md) separately measures commit-to-denial and watermark convergence with shared SQLite.

[Walkthrough video](../docs/demo-walkthrough.mp4)
