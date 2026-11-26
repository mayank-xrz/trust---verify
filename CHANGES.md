# Track 4 crypto objectives — changes

| Objective | Files | Positive acceptance test | Negative acceptance test |
| --- | --- | --- | --- |
| Replay and binding | `src/crypto/envelope.py`, `src/crypto/replay_cache.py`, `src/crypto/events.py` | `test_valid_message_accepted` | `test_recipient_aad_tamper_rejected`, `test_duplicate_message_rejected`, `test_counter_out_of_window_rejected` |
| Forward secrecy | `src/crypto/handshake.py` | `test_each_session_uses_fresh_ephemerals` | `test_identity_key_exposure_does_not_decrypt_past_session`, `test_ephemeral_keys_absent_after_session` |
| Delivery | `src/crypto/delivery.py` | `test_reordered_chunks_deliver` | `test_missing_chunk_reports_incomplete`, `test_corrupt_chunk_discarded`, `test_duplicate_chunk_handled` |
| Resumption | `src/crypto/resumption.py` | `test_same_peer_resumes` | `test_different_identity_same_session_id_rejected`, `test_expired_ticket_rejected`, `test_replayed_ticket_rejected`, `test_ticket_bound_to_transcript` |

Shared files: `src/crypto/cli.py` provides the five commands; `tests/conftest.py` generates keys and temp state at runtime; `src/crypto/primitives.py` and `src/crypto/session.py` adapt to the pinned `pqcrypto` 1.0.0 API; `requirements.txt` and `requirements-test.txt` pin dependencies; `README.md` records setup, outputs, and limitations. No detector, rotation, revocation-broadcast, backup, or WAL implementation changed.

`pyproject.toml` and `Makefile` set the default test gate to the acceptance and core crypto suite. Legacy integration tests remain available by explicit path with `requirements-demo.txt`.
