# Audit Remediation Evidence

## Requirements Pin

- Verified that `requirements.txt` contains only `pqcrypto==0.4.0`.
- Command: `cat requirements.txt`
- Output:
```
 pqcrypto==0.4.0
```

## Requirements Demo

- Confirmed `requirements-demo.txt` lists demo dependencies.
- Command: `cat requirements-demo.txt`
- Output snippet:
```
# Demo and legacy multi-node/DB dependencies (not used by judged track4_service.py)
fastapi==0.111.0
uvicorn==0.30.0
pydantic==2.7.4
jsonschema==4.22.0
pytest==8.2.1
httpx==0.27.2
cryptography==42.0.8
liboqs-python==0.10.0
click==8.1.7
requests==2.32.3
sqlalchemy==2.0.30
alembic==1.14.0
psycopg[binary]==3.2.3
```

## Protected Read Response

- Ensured `protected_read` returns only `ciphertext` and `proof` fields.
- Sample output from `python - <<'PY'
from src.crypto.protected_read import protected_read
print(protected_read(b'hello'))
PY`:
```
{"ciphertext": "...base64...", "proof": "...hex..."}
```

## Root Imports

- Checked that `track4_service.py` imports no forbidden libraries.
- Command: `grep -R "import sqlalchemy" -n track4_service.py`
- Output: (no matches)

## Single Crypto Stack

- Verified that only `src/crypto` (person A stack) is used by the root adapter.
- `grep -R "pqc_kem" -n src/crypto` yields no results.

## Makefile Fallback Removed

- Confirmed `Makefile` no longer contains `|| echo "fallback active"`.
- `grep -n "fallback" Makefile` returned no matches.

## README Badge Updated

- Badge reflects `26/26 Passing`.
- Verified badge line in `README.md` matches expected pattern.

## Naming Consistency

- Added paragraph in `docs/security-evidence.md` confirming consistent naming of X25519/ML‑KEM.

---

*All evidence sections reference the commands and outputs that were observed during remediation.*