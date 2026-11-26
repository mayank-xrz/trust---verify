---
VIDEO_URL: VIDEO_URL
---

# Trust, but verify
Track 4 hackathon submission

## What the prototype does

The system lets services deliver protected messages, withdraw trust from a lost device, recover key state, and explain security decisions. The walkthrough video is {{VIDEO_URL}}.

## System design

- Messaging uses hybrid ML-KEM-768 and X25519 key establishment, ML-DSA-65 signatures, and AES-256-GCM protected envelopes. Receivers check recipient binding, reject duplicates, and hold incomplete transfers.
- The identity service rotates keys, persists committed state, revokes devices, and checks signatures against pinned backup keys before restoring. The service defaults to a 30-second rotation grace period. The local HTTP demo uses 2 seconds.
- The audit trail links records with SHA-256 and supports signed checkpoints. Deterministic detector rules inspect privilege changes, replay, and unexpected service paths.
- The sandbox requires an explicit feature flag and operator credentials. The offline judging adapter can use the existing Node.js crypto worker if Python cryptography is unavailable.

## Measured evidence

- Three independently running localhost nodes confirmed device revocation within {{REVOCATION_MS}} ms of the authority timestamp in the recorded run. All accepted the replacement credential and preserved the unaffected user's access.
- The original synthetic fixture is regression evidence. All severities yielded F1 {{REG_ALL_F1}}, median {{REG_ALL_MEDIAN}} ms, and {{REG_ALL_FP}} false alerts per 1,000 benign events. Non-LOW alerts yielded F1 {{REG_HIGH_F1}}, median {{REG_HIGH_MEDIAN}} ms, and {{REG_HIGH_FP}} false alerts per 1,000 benign events.
- The second synthetic fixture used a separate generator. All severities yielded F1 {{CHALLENGE_ALL_F1}}, median {{CHALLENGE_ALL_MEDIAN}} ms, and {{CHALLENGE_ALL_FP}} false alerts per 1,000 benign events. Non-LOW alerts yielded F1 {{CHALLENGE_HIGH_F1}}, median {{CHALLENGE_HIGH_MEDIAN}} ms, and {{CHALLENGE_HIGH_FP}} false alerts per 1,000 benign events.
- The detector's localhost HTTP demo returned the expected alert in a median of {{HTTP_MEDIAN}} ms across {{HTTP_SAMPLES}} requests. Fixture medians measure in-memory rule evaluation.

---

# Threat model and verification
Track 4 hackathon submission

## Threats and controls

- Spoofing and redirection. Enrolled public keys identify peers, signatures bind sender identity, and authenticated envelope fields bind the intended recipient.
- Tampering and replay. AEAD checks the payload and bound metadata. Persistent replay state rejects duplicate messages. The receiver withholds an incomplete or invalid file.
- Lost devices and unauthorized service calls. Revocation withdraws device trust. Graph policy and context-aware rules flag unexpected service paths even when a credential is valid.
- Audit and backup tampering. The audit chain and trusted checkpoints support verification. Backup restore checks a pinned ML-DSA signature and rejects corrupt state.
- Timing and availability. The detector buffers out-of-order events and marks uncertain timing. Key rotation, timeout, and crash recovery checks exercise failure handling.

## What the evidence covers

- The revocation measurement includes commit, HTTP acknowledgement, and probe delay. Separately running nodes shared one SQLite database. Database enforcement and replication watermark convergence are distinct.
- Both detector datasets are synthetic and were scored with the same rules. The second dataset exposed six missed suspicious report-archive downloads. LOW stale-key notices account for the reported benign alerts when all severities are counted.
- Endpoint compromise and network-level denial of service remain outside the prototype's guarantees. A trusted checkpoint or anchor is needed to detect wholesale audit replacement.

## Reproduce the submission checks

1. Install the pinned dependencies using the README instructions.
2. Run make test for the full test suite.
3. Run make demo for the HTTP walkthrough and 12 measured acceptance checks.
4. Run python -m scripts.evaluate_detector for both alert policies. The raw measurements and interpretation are in reports/JUDGE_EVIDENCE.md.
