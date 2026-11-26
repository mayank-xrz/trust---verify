"""Regression tests for track4_service replay/timezone/audit-chain hardening (P1-2)."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest

import track4_service
from src.crypto.primitives import b64, kem_keypair


def _call(monkeypatch: pytest.MonkeyPatch, tmp_path: Path, request: dict) -> dict:
    monkeypatch.setenv("TRACK4_STATE_DIR", str(tmp_path))
    return track4_service.dispatch(request)


def _setup(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    assert _call(
        monkeypatch,
        tmp_path,
        {
            "op": "setup",
            "owners": {"doc": "alice"},
            "contents": {"doc": "body"},
            "disabled": [],
            "key_material": "k",
        },
    ) == {"ready": True}


def _state(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "track4-local" / "state.json").read_text(encoding="utf-8"))


def _anchor(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "track4-local" / ".audit_anchor.json").read_text(encoding="utf-8"))


def test_challenge_replay_is_blocked_across_request_ids(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _setup(monkeypatch, tmp_path)
    public, _ = kem_keypair()
    first = _call(
        monkeypatch,
        tmp_path,
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "doc",
            "request_id": "r1",
            "challenge": "single-use",
            "public_key": b64(public),
        },
    )
    assert "ciphertext" in first

    replay = _call(
        monkeypatch,
        tmp_path,
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "doc",
            "request_id": "r2",
            "challenge": "single-use",
            "public_key": b64(public),
        },
    )
    assert replay == {"decision": "deny"}

    entries = [e for e in _state(tmp_path)["audit_log"] if e["op"] == "protected_read"]
    assert entries[-1]["threat"]["threat"] == "CHALLENGE_REPLAY"


def test_anchor_advances_on_every_mutation(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _setup(monkeypatch, tmp_path)
    public, _ = kem_keypair()
    _call(
        monkeypatch,
        tmp_path,
        {
            "op": "protected_read",
            "actor": "alice",
            "asset": "doc",
            "challenge": "anchor-check",
            "public_key": b64(public),
        },
    )
    _call(monkeypatch, tmp_path, {"op": "audit", "request_id": "missing"})
    state = _state(tmp_path)
    anchor = _anchor(tmp_path)
    assert anchor["seq_count"] == len(state["audit_log"])
    assert anchor["last_seq"] == len(state["audit_log"]) - 1
    assert anchor["last_hash"] == state["audit_log"][-1]["entry_hash"]
    assert track4_service.verify_chain(state["audit_log"], anchor=anchor)


def test_audit_entries_carry_utc_timestamps(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _setup(monkeypatch, tmp_path)
    for entry in _state(tmp_path)["audit_log"]:
        ts = entry["ts_utc"]
        assert ts.endswith("Z")
        datetime.fromisoformat(ts.replace("Z", "+00:00"))


def test_verify_chain_rejects_missing_timestamp_and_bool_seq() -> None:
    body = {
        "seq": 0,
        "op": "setup",
        "actor": None,
        "asset": None,
        "request_id": None,
        "decision": "allow",
        "prev_hash": track4_service.GENESIS_HASH,
    }
    entry_hash = track4_service._compute_entry_hash(track4_service.GENESIS_HASH, body)
    assert not track4_service.verify_chain([{**body, "entry_hash": entry_hash}])

    with_ts = {**body, "ts_utc": "2026-11-27T00:00:00.000Z"}
    entry_hash = track4_service._compute_entry_hash(track4_service.GENESIS_HASH, with_ts)
    assert track4_service.verify_chain([{**with_ts, "entry_hash": entry_hash}])

    bool_seq = {**with_ts, "seq": False}
    entry_hash = track4_service._compute_entry_hash(track4_service.GENESIS_HASH, bool_seq)
    assert not track4_service.verify_chain([{**bool_seq, "entry_hash": entry_hash}])
