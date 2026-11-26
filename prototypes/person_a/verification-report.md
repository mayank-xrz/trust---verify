# Track 4 adapter black-box verification

## Adapter under test

- Path: `/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py`
- Language and entry point: Python 3.12, `track4_service.py`.
- The adapter source was not modified for this verification.

## Toolkit version and exact contract

- Official `ScalerOpenSourceLabs/Track-4-Toolkit` checkout: commit `8901dfbdbfe048853e0bfa25b60583d1e6617a63` (`HEAD` matched the remote when checked).
- `protected_read` request fields: `actor`, `asset`, `challenge`, `public_key`.
- Authorized response fields: `ciphertext` (standard Base64 of raw ML-KEM-768 ciphertext) and `proof` (lowercase hexadecimal HMAC-SHA-256).
- HMAC key: the encapsulated ML-KEM shared secret. HMAC bytes: UTF-8 encoding of `challenge + stored_body`, with no delimiter.
- The validator default timeout is 8 seconds per operation; it limits each of stdout and stderr to 64 KiB.
- The validator docstring states: “No protected_read, cryptographic correctness, or timing score is tested here.”

## Public validator result

**Command** (from toolkit directory):
```text
../venv/bin/python validate.py --entry ../../outputs/track4_service.py
```

**Exit code:** 0. **Per-check result:** 22 PASS, 0 FAIL. Exact output:

```text
Local lost-device validator. Runs trusted code with your user permissions.
Fresh temporary state is not a security sandbox. Cryptography and latency are not tested.
PASS [format] clean setup: JSON response matches required structure.
PASS [setup] clean setup: Expected ready: true.
PASS [format] owner before device loss: JSON response matches required structure.
PASS [behavior] owner before device loss: Received allow with exact content.
PASS [format] peer before device loss: JSON response matches required structure.
PASS [behavior] peer before device loss: Received allow with exact content.
PASS [format] wrong owner: JSON response matches required structure.
PASS [behavior] wrong owner: Received deny without content.
PASS [format] revoke lost-device owner: JSON response matches required structure.
PASS [format] owner after revocation: JSON response matches required structure.
PASS [behavior] owner after revocation: Received deny without content.
PASS [format] audit revoked read: JSON response matches required structure.
PASS [behavior] audit revoked read: Expected matching request_id and deny decision.
PASS [format] unaffected peer: JSON response matches required structure.
PASS [behavior] unaffected peer: Received allow with exact content.
PASS [format] revocation persists across processes: JSON response matches required structure.
PASS [behavior] revocation persists across processes: Received deny without content.
PASS [format] fresh rerun setup: JSON response matches required structure.
PASS [setup] fresh rerun setup: Expected ready: true in new state directory.
PASS [format] fresh rerun owner: JSON response matches required structure.
PASS [behavior] fresh rerun owner: Received allow with exact content.
PASS [behavior] fake key stays out of output: Fake key marker must not appear in stdout or stderr.
Local scenario passed.
```

This pass covers setup, reads and exact returned content, wrong-owner denial, revocation, unaffected peer access, persistence between processes, audit correlation, and the synthetic key marker staying out of output. It does not establish cryptographic correctness.

The audited toolkit `tests/test_validate.py` checks the validator itself against a fresh-process stub and deliberately failing adapters: denied-content disclosure (including nested fields), missing revocation/body, bad JSON, execution error, timeout, and fake-key leakage. It does not add a `protected_read` check.

## `protected_read` results

Command to reproduce: `../work/venv/bin/python test_protected_read.py > protected-read-results.json` from the adapter directory. The script uses `pqcrypto==0.4.0`, launches the adapter as a separate process for each call, and records exact stdout/stderr. Synthetic plaintext bodies, private keys, and shared secrets are absent from this report and the JSON results.

### setup

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
{
  "op": "setup",
  "owners": {
    "asset-f583cb3e85434560": "actor-dc2107154f75625d"
  },
  "disabled": [],
  "contents": "[REDACTED PLAINTEXT BODY]",
  "key_material": "[REDACTED]"
}
```

**Raw stdout:**
```json
{"ready": true}
```

**Raw stderr:**
```text
[empty]
```

**Exit code:** 0

**Process ID:** 12499

**Assertions:**

- PASS: `exit_zero`
- PASS: `one_json_object`
- PASS: `state_in_selected_dir`
- PASS: `no_plaintext_or_secret_in_output`

### A authorized protected_read

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
{
  "op": "protected_read",
  "actor": "actor-dc2107154f75625d",
  "asset": "asset-f583cb3e85434560",
  "challenge": "adb7489b3c95dd29a90b70c94a469a8e41bafb70d1e4f804",
  "public_key": {
    "base64_length": 1580,
    "sha256_prefix": "c7e7e134837a"
  }
}
```

**Raw stdout:**
```json
{"ciphertext": "SAMqEYZ2cmjLi45Qf4ORUQ1RRg3PxcbAIPEKjmQfTMyDHmKF9C8UzZAvi/aZTaN/vtmyrXZC/pjCN2xGaToHcirMVHkCK4/b4eDNZbITW4WZ+iSKI1ZMz/vt8Wa4W0dTbNXjdKPtEKMBQD63nE5yG2AbNh/z9aa5Fpf4ekZlfH91yXXYHDlrIBMaUc+BNTIXk/NosOMumsi9OGlZeRcqTKn5j7QHtnLSxfPcPt6qUTDfofHCeeG2Z0UBKkXQ3XNYiP/BAPEHpfU8R27B2dNbB4jdN+zCMC2s0Z/UNIowx7wyHAc4gERWsILmMq6g0eQDTgzkAt8VW/TPARFwPBeYtoR1XGx2UeuBsg7t7N64jsUixJC78d342HBtfuy1rPdGWzWh/Mbd0NrdvXwZi6SBWq0wD2vhXCoXb3JdEdofzGdi7jd/nzrSntOyt6x7B8BE+y10mga5EPBuunrQgrHqvYmCOIQ6yVM4qOcbZFgUgmvyRV3V7YMnpDp6aG2Lmy6BEmAYUD87XNVP5EOO5fnIeBx6L4VEqQ98lYBWElaw6wBuJyZDl9A3zXCE5i/NmnazDogJTUwgekNbTKq8MhYccNmCMYXrlXkRE+dER0M7PHVKZ3D9TExuIY4KgxbQOmJJ4Gqsa3V6PQgreuOJwX1qQ9AHSgM5gYOjXE5KMipDbE/gxclhR0BNqoDmLvPyh00aXey+d5f60BlNi2ODC1lY/GmH5XjYPkzekv7pxAvvrRNlDxnMlcXrLCV6CPaaKImmIO/mn9JuYJt60HzwpIRw8tKbMhxZHYN0C0IPlJdl6WoBu5Xl9j/vU3rEP9Tw5Rd21isHlqwUVgqkXI6C48WAGVDWiIbviXGySY1AOb+PJFmAn55w+uP8/2laVsgUX+wU5I6kQpzBAyI35IdnPsfDacqvk3JgwtOo8pmbsbk0phlg366mMImdwwPhAceUnvkBSTBk+oXXog5LnBP8wbfLuzKcW1S0DBoTquKjkEgRknF6azud3xrboOAdP/YdAKJm4BR6QHGJflIvIwsx9+KJ9DUATTlBk3G+h9l/HGA9AYwMlJ+90eo2qXplYe4EmfxrnJg3Mqh9ebAaKefZSlYByd5mMuBeVBxKRKjeI4fMHw5l41JjV1svLecFVtdOWAheQxJPaUnjTgZ8h7q3aKN2hdMQmJX3L+MI9UZwjE7Vty4OClX/OI8GoajdVfbIosIKA2D45VRKuVtBvsLks79i43TKR6QfQSQeKvjX7gegoRlAbU2Gve9123/hAW2ve7x/ZGby9WmHu/PpEZvFLm1+KP6rawbE1uChQzQd+xZ+hjqtKlR9aYJCmp1YxcozYhEEmsEQoyxxV962bARMhuxbKv9PjdoH2J5AYmMhr6DtXv+iEpmH/ItL8ZVQ3W0lWN5Rtp4HOthUFbeJuo5nONFeFfisW5uxf2sz1RIUj8PRCts=", "proof": "6e606d74d26f75cdba7bbb9029ecc4e7f00b27ce37f0d4476cbf2f664b3825d2"}
```

**Raw stderr:**
```text
[empty]
```

**Exit code:** 0

**Process ID:** 12500

**Assertions:**

- PASS: `exit_zero`
- PASS: `separate_process`
- PASS: `authorized_fields`
- PASS: `standard_base64`
- PASS: `kem_ciphertext_length`
- PASS: `exact_hmac_transcript`
- PASS: `lowercase_hex_proof`
- PASS: `no_plaintext_or_secret_in_output`

### B unauthorized protected_read

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
{
  "op": "protected_read",
  "actor": "non-owner-59121231fbf5a5bf",
  "asset": "asset-f583cb3e85434560",
  "challenge": "adb7489b3c95dd29a90b70c94a469a8e41bafb70d1e4f804",
  "public_key": {
    "base64_length": 1580,
    "sha256_prefix": "c7e7e134837a"
  }
}
```

**Raw stdout:**
```json
{"decision": "deny"}
```

**Raw stderr:**
```text
[empty]
```

**Exit code:** 0

**Process ID:** 12501

**Assertions:**

- PASS: `exit_zero`
- PASS: `explicit_denial`
- PASS: `no_ciphertext_or_proof`
- PASS: `no_plaintext_or_secret_in_output`

### C1 invalid Base64

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
{
  "op": "protected_read",
  "actor": "actor-dc2107154f75625d",
  "asset": "asset-f583cb3e85434560",
  "challenge": "adb7489b3c95dd29a90b70c94a469a8e41bafb70d1e4f804",
  "public_key": {
    "base64_length": 4,
    "sha256_prefix": "53bc5cce8c57"
  }
}
```

**Raw stdout:**
```text
[empty]
```

**Raw stderr:**
```text
Request failed
```

**Exit code:** 1

**Process ID:** 12502

**Assertions:**

- PASS: `nonzero_exit`
- PASS: `no_stdout`
- PASS: `diagnostic_only_on_stderr`
- PASS: `no_traceback`
- PASS: `no_proof_or_plaintext`
- PASS: `no_plaintext_or_secret_in_output`

### C2 wrong key length

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
{
  "op": "protected_read",
  "actor": "actor-dc2107154f75625d",
  "asset": "asset-f583cb3e85434560",
  "challenge": "adb7489b3c95dd29a90b70c94a469a8e41bafb70d1e4f804",
  "public_key": {
    "base64_length": 28,
    "sha256_prefix": "064b9db4fce6"
  }
}
```

**Raw stdout:**
```text
[empty]
```

**Raw stderr:**
```text
Request failed
```

**Exit code:** 1

**Process ID:** 12503

**Assertions:**

- PASS: `nonzero_exit`
- PASS: `no_stdout`
- PASS: `diagnostic_only_on_stderr`
- PASS: `no_traceback`
- PASS: `no_proof_or_plaintext`
- PASS: `no_plaintext_or_secret_in_output`

### D tampered challenge

**Verdict:** PASS

**Command:**
```text
local HMAC recomputation
```

**Input summary (protected body and key material redacted):**
```json
{
  "original_challenge": "adb7489b3c95dd29a90b70c94a469a8e41bafb70d1e4f804",
  "altered_challenge": "0b72c31ed1f29af2daffdd122b1b2cdcd6285c4546cc50b2",
  "stored_body": "[REDACTED PLAINTEXT BODY]"
}
```

**Raw stdout:**
```json
{"ciphertext": "SAMqEYZ2cmjLi45Qf4ORUQ1RRg3PxcbAIPEKjmQfTMyDHmKF9C8UzZAvi/aZTaN/vtmyrXZC/pjCN2xGaToHcirMVHkCK4/b4eDNZbITW4WZ+iSKI1ZMz/vt8Wa4W0dTbNXjdKPtEKMBQD63nE5yG2AbNh/z9aa5Fpf4ekZlfH91yXXYHDlrIBMaUc+BNTIXk/NosOMumsi9OGlZeRcqTKn5j7QHtnLSxfPcPt6qUTDfofHCeeG2Z0UBKkXQ3XNYiP/BAPEHpfU8R27B2dNbB4jdN+zCMC2s0Z/UNIowx7wyHAc4gERWsILmMq6g0eQDTgzkAt8VW/TPARFwPBeYtoR1XGx2UeuBsg7t7N64jsUixJC78d342HBtfuy1rPdGWzWh/Mbd0NrdvXwZi6SBWq0wD2vhXCoXb3JdEdofzGdi7jd/nzrSntOyt6x7B8BE+y10mga5EPBuunrQgrHqvYmCOIQ6yVM4qOcbZFgUgmvyRV3V7YMnpDp6aG2Lmy6BEmAYUD87XNVP5EOO5fnIeBx6L4VEqQ98lYBWElaw6wBuJyZDl9A3zXCE5i/NmnazDogJTUwgekNbTKq8MhYccNmCMYXrlXkRE+dER0M7PHVKZ3D9TExuIY4KgxbQOmJJ4Gqsa3V6PQgreuOJwX1qQ9AHSgM5gYOjXE5KMipDbE/gxclhR0BNqoDmLvPyh00aXey+d5f60BlNi2ODC1lY/GmH5XjYPkzekv7pxAvvrRNlDxnMlcXrLCV6CPaaKImmIO/mn9JuYJt60HzwpIRw8tKbMhxZHYN0C0IPlJdl6WoBu5Xl9j/vU3rEP9Tw5Rd21isHlqwUVgqkXI6C48WAGVDWiIbviXGySY1AOb+PJFmAn55w+uP8/2laVsgUX+wU5I6kQpzBAyI35IdnPsfDacqvk3JgwtOo8pmbsbk0phlg366mMImdwwPhAceUnvkBSTBk+oXXog5LnBP8wbfLuzKcW1S0DBoTquKjkEgRknF6azud3xrboOAdP/YdAKJm4BR6QHGJflIvIwsx9+KJ9DUATTlBk3G+h9l/HGA9AYwMlJ+90eo2qXplYe4EmfxrnJg3Mqh9ebAaKefZSlYByd5mMuBeVBxKRKjeI4fMHw5l41JjV1svLecFVtdOWAheQxJPaUnjTgZ8h7q3aKN2hdMQmJX3L+MI9UZwjE7Vty4OClX/OI8GoajdVfbIosIKA2D45VRKuVtBvsLks79i43TKR6QfQSQeKvjX7gegoRlAbU2Gve9123/hAW2ve7x/ZGby9WmHu/PpEZvFLm1+KP6rawbE1uChQzQd+xZ+hjqtKlR9aYJCmp1YxcozYhEEmsEQoyxxV962bARMhuxbKv9PjdoH2J5AYmMhr6DtXv+iEpmH/ItL8ZVQ3W0lWN5Rtp4HOthUFbeJuo5nONFeFfisW5uxf2sz1RIUj8PRCts=", "proof": "6e606d74d26f75cdba7bbb9029ecc4e7f00b27ce37f0d4476cbf2f664b3825d2"}
```

**Raw stderr:**
```text
[empty]
```

**Assertions:**

- PASS: `challenge_changes_expected_proof`
- PASS: `response_matches_original_only`

## Process and state results

### malformed JSON process behavior

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
"[MALFORMED JSON]"
```

**Raw stdout:**
```text
[empty]
```

**Raw stderr:**
```text
Request failed
```

**Exit code:** 1

**Process ID:** 12504

**Assertions:**

- PASS: `nonzero_exit`
- PASS: `no_stdout`
- PASS: `stderr_only`
- PASS: `no_traceback`
- PASS: `no_plaintext_or_secret_in_output`

### fallback temp state and fresh processes

**Verdict:** PASS

**Command:**
```text
/Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/../work/venv/bin/python -B /Users/mayank/Documents/Codex/2026-11-26/files-pasted-by-the-user-role/outputs/track4_service.py
```

**Input summary (protected body and key material redacted):**
```json
{
  "setup": "[REDACTED PLAINTEXT BODY]",
  "read": {
    "op": "read",
    "actor": "actor-dc2107154f75625d",
    "asset": "asset-f583cb3e85434560",
    "request_id": "bf1ba5a0ff250bed"
  }
}
```

**Raw setup stdout / stderr:**
```text
{"ready": true}
```

```text
[empty]
```

**Read stdout (plaintext field redacted) / raw stderr:**
```text
{"decision": "allow", "body": "[REDACTED PLAINTEXT BODY]"}
```

```text
[empty]
```

**Setup/read process IDs:** 12505 / 12506

**Assertions:**

- PASS: `setup_exit_zero`
- PASS: `read_exit_zero`
- PASS: `separate_process`
- PASS: `fallback_state_file`
- PASS: `persisted_body_matches`
- PASS: `no_secret_in_diagnostics`
- PASS: `one_json_object_per_success`

- `TRACK4_STATE_DIR` persistence: setup and authorized `protected_read` ran in distinct processes; the selected state file existed.
- OS temp fallback: with `TRACK4_STATE_DIR` unset and an isolated `TMPDIR`, setup and read ran in distinct processes and used that temp directory.
- Diagnostics: successful calls had empty stderr. Malformed calls exited nonzero with a generic stderr message and no stdout. No private key, shared secret, or plaintext body was observed in captured diagnostics.

## Failures

None of the recorded assertions failed. The malformed-key and malformed-JSON calls returned nonzero as expected.

## Limitations

- The public validator does not test cryptographic correctness of `protected_read` or timing; the separate black-box test covers the specified KEM/HMAC exchange but does not make a timing claim.
- Distributed revocation, key rotation, messaging, chunking, and detection quality were not exercised by this adapter-focused run.
- This was a local macOS test with Python 3.12 and `pqcrypto==0.4.0`; the offline Linux judge was not available.

## Overall verdict

**PASS for the tested adapter contract.** The public lost-device validator passed, and independent `protected_read` requests produced the exact authorized ML-KEM/HMAC proof while denying unauthorized access and rejecting malformed keys without disclosing protected data. Timing, distributed behavior, and the broader messaging protocol remain unverified by this report.
