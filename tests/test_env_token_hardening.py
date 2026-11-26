"""Regression tests for fail-closed signing-key configuration (P1-5)."""

from __future__ import annotations

import base64

import pytest

from src.identity_keys.clock import SystemClock
from src.identity_keys.errors import StateUnavailable
from src.identity_keys.tokens import TokenAuthority, load_token_signing_keypair


def test_token_authority_fails_closed_without_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("TOKEN_SIGNING_SEED_B64", raising=False)
    with pytest.raises(StateUnavailable, match="TOKEN_SIGNING_SEED_B64 is required"):
        TokenAuthority(SystemClock())


def test_token_authority_rejects_malformed_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", "not-base64!!")
    with pytest.raises(StateUnavailable, match="not valid base64"):
        TokenAuthority(SystemClock())


def test_token_authority_rejects_wrong_length_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", base64.b64encode(b"short").decode())
    with pytest.raises(StateUnavailable, match="must decode to 32 bytes"):
        TokenAuthority(SystemClock())


def test_token_authority_accepts_valid_seed(monkeypatch: pytest.MonkeyPatch) -> None:
    seed = bytes(range(32))
    monkeypatch.setenv("TOKEN_SIGNING_SEED_B64", base64.b64encode(seed).decode())
    pub, priv = load_token_signing_keypair()
    assert priv == seed
    assert len(pub) == 32
    authority = TokenAuthority(SystemClock())
    token = authority.issue("alice", "device-1")
    assert authority.verify(token).user_id == "alice"


def test_reenrollment_service_fails_closed_without_seed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from src.identity_keys.audit_outbox import AuditEmitter
    from src.identity_keys.reenroll import ReenrollmentService

    monkeypatch.delenv("TOKEN_SIGNING_SEED_B64", raising=False)
    with pytest.raises(StateUnavailable, match="TOKEN_SIGNING_SEED_B64 is required"):
        ReenrollmentService(None, SystemClock(), AuditEmitter("node-a", SystemClock()))  # type: ignore[arg-type]


def test_local_secrets_are_generated_once_and_private(tmp_path) -> None:
    from scripts.local_secrets import SECRETS, ensure_local_secrets

    target = tmp_path / "local_env.json"
    first = ensure_local_secrets(target)
    second = ensure_local_secrets(target)
    assert first == second
    assert set(first) == set(SECRETS)
    for name, raw_len in SECRETS.items():
        assert len(base64.b64decode(first[name], validate=True)) == raw_len, name
    assert (target.stat().st_mode & 0o777) == 0o600

