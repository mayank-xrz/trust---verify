"""Deterministic negative and fuzz coverage for crypto and adapter boundaries (P2-2).

No third-party fuzzing dependency: a fixed-seed RNG makes every case
reproducible on any machine.
"""

from __future__ import annotations

import copy
import random
import string
from pathlib import Path

import pytest

import track4_service
from src.crypto.primitives import CryptoError, b64, canonical, kem_keypair, unb64
from src.crypto.protected_read import MAX_CHALLENGE_LENGTH, protected_read

RNG = random.Random(20261127)


def _random_ascii(length: int) -> str:
    return "".join(RNG.choice(string.printable) for _ in range(length))


def test_unb64_rejects_non_base64_and_wrong_sizes() -> None:
    for _ in range(200):
        value = "!" + _random_ascii(RNG.randrange(0, 24))
        with pytest.raises(CryptoError):
            unb64(value)
    for size in (0, 1, 7, 31, 33, 64):
        raw = bytes(RNG.randrange(256) for _ in range(size))
        if size == 32:
            assert unb64(b64(raw), 32) == raw
        else:
            with pytest.raises(CryptoError):
                unb64(b64(raw), 32)


def test_unb64_rejects_non_ascii_and_non_string() -> None:
    for value in ("é", "☃", b"AAAA", None, 123):
        with pytest.raises(CryptoError):
            unb64(value)  # type: ignore[arg-type]


def test_canonical_is_independent_of_dict_order() -> None:
    for _ in range(100):
        keys = [f"k{i}" for i in range(RNG.randrange(1, 10))]
        values = {key: RNG.randrange(-1000, 1000) for key in keys}
        items = list(values.items())
        RNG.shuffle(items)
        shuffled = dict(items)
        assert canonical(values) == canonical(shuffled)


def _valid_chain(length: int = 6) -> list[dict]:
    state: dict = {"audit_log": []}
    for idx in range(length):
        track4_service._append_audit(
            state, "read", f"actor-{idx}", f"asset-{idx}", f"req-{idx}", "allow"
        )
    assert track4_service.verify_chain(state["audit_log"])
    return state["audit_log"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda e: e.__setitem__("decision", "deny"),
        lambda e: e.__setitem__("seq", e["seq"] + 1),
        lambda e: e.__setitem__("prev_hash", "0" * 64),
        lambda e: e.pop("ts_utc", None),
        lambda e: e.__setitem__("entry_hash", "f" * 64),
        lambda e: e.__setitem__("unexpected", "field"),
    ],
)
def test_verify_chain_rejects_every_targeted_mutation(mutate) -> None:
    chain = _valid_chain()
    mutated = copy.deepcopy(chain)
    mutate(mutated[3])
    assert not track4_service.verify_chain(mutated)


def test_verify_chain_fuzz_never_accepts_a_corrupted_hash() -> None:
    chain = _valid_chain()
    for _ in range(100):
        mutated = copy.deepcopy(chain)
        idx = RNG.randrange(len(mutated))
        digest = list(mutated[idx]["entry_hash"])
        pos = RNG.randrange(len(digest))
        digest[pos] = RNG.choice("0123456789abcdef")
        if "".join(digest) == mutated[idx]["entry_hash"]:
            continue
        mutated[idx]["entry_hash"] = "".join(digest)
        assert not track4_service.verify_chain(mutated)


def test_verify_chain_rejects_truncation_only_when_anchored() -> None:
    chain = _valid_chain()
    anchor = {
        "seq_count": len(chain),
        "last_seq": len(chain) - 1,
        "genesis_hash": chain[0]["entry_hash"],
        "last_hash": chain[-1]["entry_hash"],
    }
    assert track4_service.verify_chain(chain[:-1], anchor=anchor) is False
    assert track4_service.verify_chain(chain, anchor=anchor) is True


def test_protected_read_rejects_boundary_challenges_and_keys() -> None:
    public, _ = kem_keypair()
    public_b64 = b64(public)
    for challenge in ("", "x" * (MAX_CHALLENGE_LENGTH + 1), None, 7, b"bytes"):
        with pytest.raises(CryptoError):
            protected_read(challenge, "body", public_b64)  # type: ignore[arg-type]
    for key in ("", "not-base64!", b64(b"short")):
        with pytest.raises(CryptoError):
            protected_read("challenge", "body", key)


def test_dispatch_rejects_malformed_requests(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TRACK4_STATE_DIR", str(tmp_path))
    for request in (
        {},
        {"op": "unknown"},
        {"op": "setup", "owners": [], "contents": {}, "disabled": []},
        {"op": "setup", "owners": {"a": 1}, "contents": {}, "disabled": []},
        {"op": "read", "actor": 1, "asset": "a", "request_id": "r"},
        {"op": "read", "actor": "a", "asset": "a"},
        {"op": "revoke", "actor": 7},
        {"op": "audit", "request_id": 7},
    ):
        with pytest.raises((ValueError, CryptoError)):
            track4_service.dispatch(request)


def test_dispatch_rejects_non_object_request() -> None:
    for request in ([], "setup", 7, None):
        with pytest.raises(ValueError):
            track4_service.dispatch(request)  # type: ignore[arg-type]


def test_dispatch_denies_fuzzed_protected_read_inputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("TRACK4_STATE_DIR", str(tmp_path))
    assert track4_service.dispatch(
        {
            "op": "setup",
            "owners": {"doc": "alice"},
            "contents": {"doc": "body"},
            "disabled": [],
            "key_material": "k",
        }
    ) == {"ready": True}
    public, _ = kem_keypair()
    for _ in range(50):
        request = {
            "op": "protected_read",
            "actor": "alice",
            "asset": "doc",
            "challenge": _random_ascii(RNG.randrange(0, MAX_CHALLENGE_LENGTH + 2)),
            "public_key": b64(public) if RNG.random() < 0.5 else _random_ascii(12),
        }
        result = track4_service.dispatch(request)
        # A malformed input is denied; a well-formed unique challenge returns
        # the protected-read payload. Neither path may raise or return junk.
        if result == {"decision": "deny"}:
            continue
        assert set(result) == {"ciphertext", "proof"}

