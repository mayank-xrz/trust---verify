# Audit Remediation Evidence

## Requirements Pin

- Verified that `requirements.txt` pins the PQC stack at `pqcrypto==1.0.0` (alongside the other pinned dependencies).
- Command: `grep '^pqcrypto' requirements.txt`
- Output:
```
pqcrypto==1.0.0
```

## Requirements Demo

- `requirements-demo.txt` now includes `requirements.txt` so the demo/sandbox install cannot downgrade the canonical pins.
- Command: `cat requirements-demo.txt`
- Output:
```
# Demo and multi-node sandbox dependencies.
# The canonical dependency set lives in requirements.txt; this file is an alias
# so `pip install -r requirements-demo.txt` cannot downgrade packages.
-r requirements.txt
```

## Protected Read Response

- Ensured `protected_read` returns only `ciphertext` and `proof` fields.
- Covered by `tests/test_audit_remediation.py::test_protected_read_response`.
- Shape (public key omitted for brevity):
```
{"ciphertext": "...base64...", "proof": "...64 hex chars..."}
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

- `README.md` documents the full-suite command (`pytest tests/ -v`) and no longer carries a stale fixed-count badge.
- Covered by `tests/test_audit_remediation.py::test_readme_badge`.

## Naming Consistency

- The canonical suite string `ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v1` is defined once in `src/crypto/primitives.py` and quoted in `README.md`.
- Covered by `tests/test_audit_remediation.py::test_naming_consistency`.

---

*All evidence sections reference the commands and outputs that were observed during remediation.*