# Demo operations and implementation coverage

<details>
<summary>Acceptance checks, operator commands, and manual configuration</summary>

### Track 4 checklist

`make demo` runs the local HTTP walkthrough and prints a pass/fail table for
the following twelve checks. Any failed check gives the command a nonzero exit
status.

| Objective | Evidence produced |
| --- | --- |
| Key rotation | Configurable HTTP-demo grace period and rejection after cutoff, plus three-node authorization checks |
| Revocation across nodes | Authority timestamp to each confirmed HTTP denial across three separate processes, with owner re-enrollment and unaffected-user access |
| Crash recovery | Consistent key version, preserved committed data, and revoked credentials still denied |
| Backup integrity | Damaged payload and missing or invalid pinned signatures rejected |
| Log integrity | User text stays within one event, and the chain and signed checkpoints verify |
| Routine vs suspicious activity | F1, median rule-evaluation time to alert, and false alerts per 1,000 benign events on both labelled synthetic fixtures and for both alert policies |
| Lateral movement | Rule and path evidence for disallowed service hops |
| Clock differences | Supported timestamp-gap range, ordering checks, and an `order_uncertain` example |
| Replay and recipient binding | Duplicate or wrong-recipient messages rejected |
| Forward secrecy | Long-term identity key alone cannot decrypt a completed earlier session |
| Delivery under loss or reordering | Valid reordered file delivered, incomplete file discarded and reported |
| Session resumption | Same peer resumes and a different identity is rejected |

Run `python -m scripts.evaluate_detector` to score both synthetic datasets with
all alerts and with non-LOW alerts. The original fixture is regression evidence.
The second fixture has a separate generator and was scored with the same rules.
Latency is measured inside the detector, in memory.

Operator CLI (run while nodes are up):

```bash
python3 -m demo.node.operator_cli status
python3 -m demo.node.operator_cli rotate --identity node-a
python3 -m demo.node.operator_cli revoke --identity node-a --key-id <KEY_ID> --reason "compromised"
python3 -m demo.node.operator_cli verify-logs
python3 -m demo.node.operator_cli alerts
```

`make demo` generates fresh credentials and binds its services to loopback. When running demo nodes separately, configure distinct random bearer tokens for each purpose:

- `DEMO_OPERATOR_TOKEN` authorizes key rotation and revocation. Set the same token in the CLI's environment when targeting that node. Successful actions are logged as `demo-operator`.
- `DEMO_PEER_ENROLL_TOKEN` authorizes registration of a trusted `GET /keys/public` bundle with `POST /peers`. Refresh the bundle after recipient key rotation.
- `DEMO_RECIPIENT_TOKEN` authorizes reads from that node's `GET /inbox/{receipt_id}`. Use a different recipient token for each node. `POST /receive` verifies and accepts a signed envelope and returns an opaque receipt, which grants no read access by itself.
- `DEMO_REVOCATION_SYNC_TOKEN` authorizes only peer revocation updates. Configure it across the trusted nodes when enabling `PEER_NODES`. Use a protected transport for bearer credentials outside loopback.

To enable device authorization on `POST /send`, set `DEMO_DEVICE_AUTHORITY_URL` to the identity service and `DEMO_DEVICE_RESOURCES` to a JSON object mapping recipient IDs to identity resource IDs. Send the device's access token as `X-Device-Authorization: Bearer <token>` alongside the operator credential. The authority checks `resource:write` for each send. An unconfigured node retains the operator-only demo path.

To enable reconnect recovery, set `DEMO_PEER_AUTHORITIES` to a JSON object mapping recipient IDs to their trusted HTTP URLs, with the shared revocation sync token set on the sender and recipients. Before sealing to a configured recipient, the sender pulls the recipient's durable revoked-key snapshot and merges it into local state. Sends to those recipients fail closed if the snapshot is unavailable. Use trusted HTTPS URLs outside loopback.

Keep each node's `DATA_DIR` across restarts. The inbox stores encrypted envelopes and the replay record in one SQLite transaction. A receipt stays readable while its recipient key is active or in grace. Expired and revoked keys make the associated contents unavailable. After restart, re-enroll the sending peer before accepting new messages.

[Live run results](../reports/demo_run.md)

The live assessment runs three loopback node processes with separate state directories. It verifies protected delivery, rotation grace and cutoff, receiver-side denial after recipient-key revocation, and rejection of new sends under the revoked key on both peers. It then checks unaffected traffic, delivery with a replacement key, and the audit chains. The peer acknowledgement includes an audit sequence for that specific revocation. The extended check also revokes a signed-in device, verifies a fresh send is denied while another device still delivers, and restarts a sender that missed a recipient-key revocation. The restarted sender fetches the recipient's current revocation snapshot before sealing.

</details>

<details>
<summary>Implementation coverage and runtime parameters</summary>

## Checklist coverage

| Track 4 objective | Code | Tests |
| :-- | :-- | :-- |
| Key rotation | `src/identity_keys/rotation.py` | `tests/test_part2_rotation.py`, `tests/test_rotation_signed_cutoff.py` |
| Revocation across nodes, re-enrolment | `src/identity_keys/revocation.py`, `reenroll.py` | `tests/test_part3_revocation_reenroll.py`, `tests/test_revocation_heartbeat.py` |
| Crash recovery | `src/identity_keys/rotation.py` | `tests/test_rotation_durability.py`, `tests/test_lifecycle_chaos.py` |
| Backup integrity | `src/identity_keys/backup.py` | `tests/test_part4_backup.py`, `tests/test_backup_pq_signatures.py` |
| Log integrity | `src/audit/` | `tests/test_log_injection.py`, `tests/test_audit_cli_verification.py` |
| Routine vs suspicious activity | `src/detector/rules.py` | `tests/test_detector_eval.py`, `tests/test_forgery_and_inedge_detection.py` |
| Lateral movement | `src/detector/graph_lateral.py` | `tests/test_detector_lateral_velocity.py` |
| Clock differences | `src/detector/clock_sync.py` | `tests/test_detector_clock_watermark.py` |
| Replay and recipient binding | `src/crypto/envelope.py`, `replay_cache.py` | `tests/test_replay_binding.py` |
| Forward secrecy | `src/crypto/handshake.py` | `tests/test_forward_secrecy.py` |
| Delivery under loss or reordering | `src/crypto/delivery.py` | `tests/test_delivery.py`, `tests/test_delivery_hardening.py` |
| Session resumption | `src/crypto/resumption.py` | `tests/test_resumption.py`, `tests/test_resumption_pq_signatures.py` |

## Documented parameters

**Key rotation grace period.** A grace period applies. It is set per rotation with `grace_seconds` (default 30 s in `src/identity_keys/api.py`). During the grace window the retiring key is still accepted; once `grace_until` passes it is rejected. `grace_seconds = 0` means an immediate cutoff with no grace. See [`docs/KEY_LIFECYCLE.md`](../docs/KEY_LIFECYCLE.md) for the state machine.

**Clock differences.** `ClockSyncBuffer` (`src/detector/clock_sync.py`) accepts up to ±2000 ms of skew by default (`max_skew_ms`). Events beyond that, and events whose order cannot be established, are flagged `order_uncertain` rather than dropped. The skew thresholds are constructor parameters.

**Delivery and replay.** Incomplete chunked messages are discarded after `DEFAULT_DELIVERY_TIMEOUT_SECONDS = 30.0` and logged as `delivery_failed_incomplete`. The replay cache keeps a sliding window of 256 counters per (sender, recipient, session).

**State on disk.** The track-4 adapter keeps sessions, enrolments, revocations and its audit chain under `TRACK4_STATE_DIR` (default: `$XDG_STATE_HOME/trust-but-verify/track4-local` or `~/.local/state/trust-but-verify/track4-local` for fresh state). An existing per-user temporary state directory remains readable for compatibility. To migrate it, stop the adapter and move the entire directory, including hidden files, to the durable path before restarting. State files contain private key material and must be protected like secrets. Locking uses `fcntl` and is not distributed across hosts.

</details>
