# Person A Integration Guide (`docs/API_FOR_PERSON_A.md`)

## 1. Authenticate a Device (Ed25519 Challenge-Response -> Bearer Token)

```python
import httpx
from src.identity_keys.crypto import b64e, ed25519_sign

ch = httpx.post(f"{NODE_URL}/api/v1/auth/challenge?device_id={device_id}").json()
sig = ed25519_sign(device_privkey, ch["challenge"].encode("utf-8"))
tok = httpx.post(
    f"{NODE_URL}/api/v1/auth/verify",
    json={"device_id": device_id, "challenge": ch["challenge"], "signature_b64": b64e(sig)},
).json()["access_token"]
```

## 2. Call `authorize` Before Every Protected Message or File Operation

```python
resp = httpx.post(
    f"{NODE_URL}/api/v1/authorize",
    headers={"Authorization": f"Bearer {tok}"},
    json={"resource_id": resource_id, "permission": "resource:read", "key_version_id": auth_kv_id},
).json()

if not resp["allowed"]:
    # Treat STATE_UNAVAILABLE, STALE_STATE, KEY_RETIRED, DEVICE_REVOKED as hard DENY
    raise PermissionError(f"Denied: {resp['reason_code']}")
```

## 3. Handling `reason_code` & Fail-Closed States
- `OWNER_ALLOWED` / `GRANT_ALLOWED`: Proceed with `resp["key_version_id"]` for envelope operations.
- `KEY_GRACE_VALID`: Allowed during grace window; audit `key.grace_used` is emitted automatically.
- `KEY_RETIRED` / `KEY_REVOKED` / `DEVICE_REVOKED` / `USER_DISABLED`: Hard deny; prompt re-authentication or re-enrollment.
- `STATE_UNAVAILABLE` / `STALE_STATE`: Node cannot verify authoritative state — **always treat as deny**, never fail open.

## 4. Fetch Public-Key Metadata
```python
meta = httpx.get(
    f"{NODE_URL}/api/v1/keys/metadata/{target_user_id}",
    headers={"Authorization": f"Bearer {tok}"},
).json()["devices"]
```
