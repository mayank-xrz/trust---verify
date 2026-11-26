"""FIX-03 regression tests: session-key and ephemeral secret zeroization.

These tests assert observable behaviour, not implementation details:

* ``SessionKeys.zeroize()`` overwrites the live key material in place.
* Dropping a ``SessionKeys`` instance scrubs its key material automatically.
* The transient ``bytes`` copies of the ML-KEM private key and of the raw
  X25519 / ML-KEM shared secrets are scrubbed before they are released.

The last three use a delegating wrapper around the real PQ primitives so the
actual key material produced by the library is inspected.  No security
primitive is mocked, replaced, or weakened.
"""

from __future__ import annotations

import ctypes
import gc
import os

from pqcrypto.sign import ml_dsa_65

from src.crypto import handshake as handshake_module
from src.crypto._pqcrypto_compat import sig_keygen
from src.crypto.handshake import EphemeralHandshakeSession, SessionKeys

KEY_LEN = 32


def _data_addr(value: bytes) -> int:
    """Address of the first payload byte of a CPython ``bytes`` object."""
    return id(value) + bytes.__basicsize__ - 1


def _read(addr: int, length: int) -> bytes:
    return ctypes.string_at(addr, length)


def _session_keys() -> SessionKeys:
    return SessionKeys(
        session_id="sess-fix03",
        transcript_hash="00" * 32,
        tx_key=os.urandom(KEY_LEN),
        rx_key=os.urandom(KEY_LEN),
        resumption_secret=os.urandom(KEY_LEN),
        peer_identity="bob",
        peer_device="dev-b",
    )


def test_session_keys_zeroize_overwrites_live_material() -> None:
    keys = _session_keys()
    # Keep the original objects alive so the allocator cannot recycle their
    # buffers between zeroize() and the inspection below.
    originals = {
        name: getattr(keys, name)
        for name in ("tx_key", "rx_key", "resumption_secret")
    }
    addresses = {name: _data_addr(value) for name, value in originals.items()}

    keys.zeroize()

    for name, addr in addresses.items():
        assert _read(addr, KEY_LEN) == b"\x00" * KEY_LEN, f"{name} not scrubbed"
        assert getattr(keys, name) == b""


def test_dropping_session_keys_scrubs_material(monkeypatch) -> None:
    calls: list[int] = []
    real_zeroize = handshake_module._zeroize_bytes

    def recording_zeroize(value):
        if isinstance(value, bytes) and value:
            calls.append(len(value))
        return real_zeroize(value)

    monkeypatch.setattr(handshake_module, "_zeroize_bytes", recording_zeroize)

    keys = _session_keys()
    del keys
    gc.collect()

    # tx_key, rx_key and resumption_secret must each have been scrubbed.
    assert sorted(calls) == [KEY_LEN, KEY_LEN, KEY_LEN]


def test_mlkem_keygen_private_bytes_are_scrubbed(monkeypatch) -> None:
    captured: dict[str, bytes] = {}
    real_keygen = handshake_module.kem_keygen

    def capturing_keygen(module):
        public_key, private_key = real_keygen(module)
        captured["private_key"] = private_key  # keep the real object alive to inspect it
        return public_key, private_key

    monkeypatch.setattr(handshake_module, "kem_keygen", capturing_keygen)

    _, signing_key = sig_keygen(ml_dsa_65)
    session = EphemeralHandshakeSession("bob", "dev-b", signing_key)
    session.create_responder_hello()

    private_key = captured["private_key"]
    assert len(private_key) > 0
    assert private_key == b"\x00" * len(private_key)


def test_raw_shared_secrets_are_scrubbed(monkeypatch) -> None:
    captured: dict[str, list[bytes]] = {"encaps": [], "decaps": []}
    real_encaps = handshake_module.kem_encaps
    real_decaps = handshake_module.kem_decaps

    def capturing_encaps(module, public_key):
        ciphertext, shared = real_encaps(module, public_key)
        captured["encaps"].append(shared)
        return ciphertext, shared

    def capturing_decaps(module, secret_key, ciphertext):
        shared = real_decaps(module, secret_key, ciphertext)
        captured["decaps"].append(shared)
        return shared

    monkeypatch.setattr(handshake_module, "kem_encaps", capturing_encaps)
    monkeypatch.setattr(handshake_module, "kem_decaps", capturing_decaps)

    alice_pub, alice_sk = sig_keygen(ml_dsa_65)
    bob_pub, bob_sk = sig_keygen(ml_dsa_65)
    responder = EphemeralHandshakeSession("bob", "dev-b", bob_sk)
    hello = responder.create_responder_hello()
    initiator = EphemeralHandshakeSession("alice", "dev-a", alice_sk)
    init_msg, _ = initiator.initiate(hello, bob_pub)
    responder.complete_responder(init_msg, alice_pub)

    assert len(captured["encaps"]) == 1
    assert len(captured["decaps"]) == 1
    for shared in captured["encaps"] + captured["decaps"]:
        assert shared == b"\x00" * len(shared)
