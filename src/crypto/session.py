"""Signed, peer-bound ephemeral ML-KEM handshake, symmetric ratchet, and directional AEAD traffic.

Forward-secrecy scope:
- Per-direction symmetric chain keys advance via HKDF-SHA256 after each message, and the
  previous chain key reference is replaced. Compromising a later chain key does not reveal
  earlier message keys in the same epoch.
- Rekeying (`Session.rekey()`) advances the epoch and derives a new root key from the old root,
  deleting old-epoch chain keys and skipped-key caches (strict cutoff: grace_epochs = 0).
- Limitations: CPython does not guarantee immediate memory zeroization of immutable `bytes`
  objects, and symmetric ratcheting alone does not provide post-compromise security without
  a fresh asymmetric handshake (`initiate`/`accept`/`finish`).
"""

import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from . import aead
from . import classical
from .primitives import (
    CryptoError,
    SUITE,
    b64,
    canonical,
    decapsulate,
    digest,
    encapsulate,
    hkdf,
    sign,
    unb64,
    verify,
)

VERSION = 1
MAX_MESSAGES_PER_EPOCH = 100000
MAX_SKIP = 1000


def _atomic_write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=f".{path.name}-", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, separators=(",", ":"), ensure_ascii=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
        dir_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def _check_protocol(value):
    if type(value.get("version")) is not int or value.get("version") != VERSION or value.get("suite") != SUITE:
        raise CryptoError("unsupported protocol or suite")


class TrustRegistry:
    """Keys arrive only from an approved out-of-band enrollment operation."""

    def __init__(self, state_path=None):
        self.state_path = Path(state_path) if state_path is not None else None
        self._keys = {}
        self._revoked_devices = set()
        self._revoked_identities = set()
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def _load(self):
        with self.state_path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        self._keys = {}
        for item in data.get("keys", []):
            self._keys[(item["identity"], item["device"])] = unb64(item["public_key"], ml_dsa_65.PUBLIC_KEY_SIZE)
        self._revoked_devices = {(item["identity"], item["device"]) for item in data.get("revoked_devices", [])}
        self._revoked_identities = set(data.get("revoked_identities", []))

    def _save(self):
        if self.state_path is None:
            return
        payload = {
            "keys": [
                {"identity": ident, "device": dev, "public_key": b64(pk)}
                for (ident, dev), pk in sorted(self._keys.items())
            ],
            "revoked_devices": [
                {"identity": ident, "device": dev} for ident, dev in sorted(self._revoked_devices)
            ],
            "revoked_identities": sorted(self._revoked_identities),
        }
        try:
            _atomic_write_json(self.state_path, payload)
        except OSError as exc:
            raise CryptoError("failed to persist trust registry") from exc

    def enroll(self, identity, device, public_key):
        if not isinstance(identity, str) or not identity or not isinstance(device, str) or not device:
            raise CryptoError("invalid peer identity")
        if not isinstance(public_key, bytes) or len(public_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
            raise CryptoError("invalid enrollment key")
        if identity in self._revoked_identities or (identity, device) in self._revoked_devices:
            raise CryptoError("peer trust revoked")
        existing = self._keys.get((identity, device))
        if existing is not None and existing != public_key:
            raise CryptoError("identity key replacement requires explicit rotation")
        self._keys[(identity, device)] = public_key
        self._save()

    def revoke(self, identity, device=None):
        if not isinstance(identity, str) or not identity:
            raise CryptoError("invalid peer identity")
        if device is None:
            self._revoked_identities.add(identity)
            for ident, dev in list(self._keys):
                if ident == identity:
                    self._revoked_devices.add((ident, dev))
                    self._keys.pop((ident, dev), None)
        else:
            if not isinstance(device, str) or not device:
                raise CryptoError("invalid peer device")
            self._revoked_devices.add((identity, device))
            self._keys.pop((identity, device), None)
        self._save()

    def is_revoked(self, identity, device=None):
        if identity in self._revoked_identities:
            return True
        if device is not None and (identity, device) in self._revoked_devices:
            return True
        return False

    def key(self, identity, device):
        if self.is_revoked(identity, device):
            raise CryptoError("peer trust revoked")
        try:
            return self._keys[(identity, device)]
        except KeyError as exc:
            raise CryptoError("untrusted peer") from exc


class PrekeyStore:
    def __init__(self, state_path=None):
        self.state_path = Path(state_path) if state_path is not None else None
        self._private = {}
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def _load(self):
        with self.state_path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        self._private = {}
        for prekey_id, entry in data.get("prekeys", {}).items():
            self._private[prekey_id] = (
                unb64(entry["kem_private"], ml_kem_768.SECRET_KEY_SIZE),
                unb64(entry["dh_private"], 48),
                int(entry["expires"]),
            )
        self.purge_expired()

    def _save(self):
        if self.state_path is None:
            return
        payload = {
            "prekeys": {
                prekey_id: {
                    "kem_private": b64(kem_priv),
                    "dh_private": b64(dh_priv),
                    "expires": expires,
                }
                for prekey_id, (kem_priv, dh_priv, expires) in self._private.items()
            }
        }
        try:
            _atomic_write_json(self.state_path, payload)
        except OSError as exc:
            raise CryptoError("failed to persist prekey store") from exc

    def purge_expired(self, now=None):
        cutoff = time.time() if now is None else now
        expired = [pid for pid, (_, _, exp) in self._private.items() if exp < cutoff]
        for pid in expired:
            del self._private[pid]
        if expired:
            self._save()
        return len(expired)

    def offer(self, identity, device, signing_secret, lifetime=300):
        self.purge_expired()
        public, private = ml_kem_768.generate_keypair()
        dh_public, dh_private = classical.keypair()
        expires = int(time.time()) + lifetime
        offer = {
            "version": VERSION,
            "suite": SUITE,
            "responder": identity,
            "responder_device": device,
            "prekey_id": secrets.token_hex(16),
            "kem_public_key": b64(public),
            "x25519_public_key": b64(dh_public),
            "expires": expires,
        }
        self._private[offer["prekey_id"]] = (private, dh_private, expires)
        self._save()
        return {**offer, "signature": b64(sign(signing_secret, "track4/v1/prekey", offer))}

    def take(self, prekey_id):
        self.purge_expired()
        try:
            private, dh_private, expires = self._private.pop(prekey_id)
        except KeyError as exc:
            raise CryptoError("prekey used or missing") from exc
        self._save()
        if expires < time.time():
            raise CryptoError("expired prekey")
        return private, dh_private


def _derive(kem_shared, dh_shared, init):
    transcript_hash = hashlib.sha256(canonical(init)).digest()
    salt = hashlib.sha256(b"track4/v1/handshake\x00" + transcript_hash).digest()
    return hkdf(
        b"track4/v1/hybrid-secret\x00" + kem_shared + dh_shared,
        salt,
        b"track4/v1/session-root\x00" + transcript_hash,
    )


def _key_confirmation_mac(root, init):
    transcript_digest = hashlib.sha256(canonical(init)).digest()
    salt = hashlib.sha256(b"track4/v1/confirm-salt\x00" + transcript_digest).digest()
    confirm_key = hkdf(
        root,
        salt,
        b"track4/v1/key-confirm\x00" + init["session_id"].encode("ascii"),
    )
    return hmac.new(confirm_key, transcript_digest, hashlib.sha256).hexdigest()


def _derive_chain_key(root, identity, device, epoch):
    label = canonical({"identity": identity, "device": device, "epoch": epoch})
    salt = hashlib.sha256(b"track4/v1/chain-init\x00" + label).digest()
    return hkdf(root, salt, b"track4/v1/chain-key\x00" + label)


def _ratchet_step(chain_key, sender, sender_device, counter, epoch):
    label = canonical({"sender": sender, "device": sender_device, "counter": counter, "epoch": epoch})
    salt = hashlib.sha256(b"track4/v1/ratchet\x00" + label).digest()
    material = hkdf(chain_key, salt, b"track4/v1/step\x00" + label, length=64)
    return material[:32], material[32:64]


def initiate(offer, initiator, initiator_device, signing_secret, registry, state_path=None):
    unsigned = {k: v for k, v in offer.items() if k != "signature"}
    _check_protocol(unsigned)
    if unsigned.get("expires", 0) < time.time():
        raise CryptoError("expired prekey")
    if registry.is_revoked(initiator, initiator_device):
        raise CryptoError("peer trust revoked")
    responder, responder_device = unsigned["responder"], unsigned["responder_device"]
    verify(
        registry.key(responder, responder_device),
        "track4/v1/prekey",
        unsigned,
        unb64(offer["signature"], ml_dsa_65.SIGNATURE_SIZE),
    )
    ciphertext, shared = encapsulate(unb64(unsigned["kem_public_key"], ml_kem_768.PUBLIC_KEY_SIZE))
    initiator_dh_public, initiator_dh_private = classical.keypair()
    dh_shared = classical.shared(initiator_dh_private, unb64(unsigned["x25519_public_key"], 44))
    init = {
        "version": VERSION,
        "suite": SUITE,
        "session_id": secrets.token_hex(16),
        "initiator": initiator,
        "initiator_device": initiator_device,
        "responder": responder,
        "responder_device": responder_device,
        "offer_hash": digest(unsigned),
        "prekey_id": unsigned["prekey_id"],
        "kem_ciphertext": b64(ciphertext),
        "x25519_public_key": b64(initiator_dh_public),
    }
    root = _derive(shared, dh_shared, init)
    session = Session(root, init, initiator, initiator_device, ready=False, state_path=state_path)
    return {**init, "signature": b64(sign(signing_secret, "track4/v1/init", init))}, session


def accept(offer, init_signed, responder_signing_secret, registry, prekeys, state_path=None):
    init = {k: v for k, v in init_signed.items() if k != "signature"}
    _check_protocol(init)
    unsigned_offer = {k: v for k, v in offer.items() if k != "signature"}
    if unsigned_offer.get("expires", 0) < time.time() or init.get("offer_hash") != digest(unsigned_offer):
        raise CryptoError("offer mismatch or expired")
    if (init.get("responder"), init.get("responder_device")) != (
        unsigned_offer["responder"],
        unsigned_offer["responder_device"],
    ):
        raise CryptoError("wrong responder")
    verify(
        registry.key(init["initiator"], init["initiator_device"]),
        "track4/v1/init",
        init,
        unb64(init_signed["signature"], ml_dsa_65.SIGNATURE_SIZE),
    )
    private, dh_private = prekeys.take(init["prekey_id"])
    shared = decapsulate(private, unb64(init["kem_ciphertext"], ml_kem_768.CIPHERTEXT_SIZE))
    dh_shared = classical.shared(dh_private, unb64(init["x25519_public_key"], 44))
    root = _derive(shared, dh_shared, init)
    ack = {
        "version": VERSION,
        "suite": SUITE,
        "session_id": init["session_id"],
        "transcript_hash": digest(init),
        "responder": init["responder"],
        "responder_device": init["responder_device"],
        "key_confirm": _key_confirmation_mac(root, init),
    }
    session = Session(root, init, init["responder"], init["responder_device"], ready=True, state_path=state_path)
    return {**ack, "signature": b64(sign(responder_signing_secret, "track4/v1/ack", ack))}, session


def finish(ack_signed, init_signed, registry, pending_session):
    ack = {k: v for k, v in ack_signed.items() if k != "signature"}
    init = {k: v for k, v in init_signed.items() if k != "signature"}
    _check_protocol(ack)
    if ack.get("session_id") != init.get("session_id") or ack.get("transcript_hash") != digest(init):
        raise CryptoError("handshake acknowledgment mismatch")
    if (ack.get("responder"), ack.get("responder_device")) != (init.get("responder"), init.get("responder_device")):
        raise CryptoError("wrong peer acknowledgment")
    verify(
        registry.key(ack["responder"], ack["responder_device"]),
        "track4/v1/ack",
        ack,
        unb64(ack_signed["signature"], ml_dsa_65.SIGNATURE_SIZE),
    )
    if pending_session.transcript != init or pending_session.identity != init["initiator"]:
        raise CryptoError("pending session mismatch")
    expected_confirm = _key_confirmation_mac(pending_session.root, init)
    actual_confirm = ack.get("key_confirm")
    if not isinstance(actual_confirm, str) or not hmac.compare_digest(actual_confirm, expected_confirm):
        raise CryptoError("key confirmation failed")
    pending_session.ready = True
    pending_session._persist()


class Session:
    """Directional AEAD session with epoch rekeying, symmetric ratchet, and atomic state persistence.

    Epoch policy: strict cutoff (`grace_epochs = 0`). After `rekey()` increments `epoch`,
    any packet from an earlier epoch is rejected.
    """

    grace_epochs = 0

    def __init__(self, root, transcript, identity, device, ready=True, state_path=None):
        self.root = root
        self.transcript = transcript
        self.identity = identity
        self.device = device
        self.state_path = Path(state_path) if state_path is not None else None
        self.epoch = 0
        self.send_counter = 0
        self.recv_counter = 0
        self._skipped_keys = {}
        self._send_lock = threading.Lock()
        self.ready = ready
        if (identity, device) == (transcript["initiator"], transcript["initiator_device"]):
            self.peer, self.peer_device = transcript["responder"], transcript["responder_device"]
        elif (identity, device) == (transcript["responder"], transcript["responder_device"]):
            self.peer, self.peer_device = transcript["initiator"], transcript["initiator_device"]
        else:
            raise CryptoError("session identity mismatch")
        self._send_chain_key = _derive_chain_key(self.root, self.identity, self.device, self.epoch)
        self._recv_chain_key = _derive_chain_key(self.root, self.peer, self.peer_device, self.epoch)
        if self.state_path is not None and self.ready:
            self._persist()

    def _persist(self):
        if self.state_path is None:
            return
        payload = {
            "session_id": self.transcript["session_id"],
            "identity": self.identity,
            "device": self.device,
            "peer": self.peer,
            "peer_device": self.peer_device,
            "transcript": self.transcript,
            "ready": self.ready,
            "epoch": self.epoch,
            "send_counter": self.send_counter,
            "recv_counter": self.recv_counter,
            "root": b64(self.root),
            "send_chain_key": b64(self._send_chain_key),
            "recv_chain_key": b64(self._recv_chain_key),
            "skipped_keys": {
                f"{ep}:{cnt}": b64(key) for (ep, cnt), key in self._skipped_keys.items()
            },
        }
        try:
            _atomic_write_json(self.state_path, payload)
        except OSError as exc:
            raise CryptoError("failed to persist session state") from exc

    @classmethod
    def load(cls, state_path):
        path = Path(state_path)
        with path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        inst = cls.__new__(cls)
        inst.root = unb64(data["root"], 32)
        inst.transcript = data["transcript"]
        inst.identity = data["identity"]
        inst.device = data["device"]
        inst.peer = data["peer"]
        inst.peer_device = data["peer_device"]
        inst.state_path = path
        inst.ready = bool(data["ready"])
        inst.epoch = int(data["epoch"])
        inst.send_counter = int(data["send_counter"])
        inst.recv_counter = int(data["recv_counter"])
        inst._send_chain_key = unb64(data["send_chain_key"], 32)
        inst._recv_chain_key = unb64(data["recv_chain_key"], 32)
        inst._skipped_keys = {
            tuple(map(int, k.split(":", 1))): unb64(v, 32)
            for k, v in data.get("skipped_keys", {}).items()
        }
        inst._send_lock = threading.Lock()
        return inst

    def rekey(self):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        with self._send_lock:
            new_epoch = self.epoch + 1
            salt = hashlib.sha256(b"track4/v1/rekey\x00" + new_epoch.to_bytes(8, "big")).digest()
            info = b"track4/v1/epoch-root\x00" + canonical(
                {"session_id": self.transcript["session_id"], "epoch": new_epoch}
            )
            self.root = hkdf(self.root, salt, info)
            self.epoch = new_epoch
            self.send_counter = 0
            self.recv_counter = 0
            self._skipped_keys.clear()
            self._send_chain_key = _derive_chain_key(self.root, self.identity, self.device, self.epoch)
            self._recv_chain_key = _derive_chain_key(self.root, self.peer, self.peer_device, self.epoch)
            self._persist()
            return self.epoch

    def encrypt(self, plaintext, message_id=None, epoch=None):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        target_epoch = self.epoch if epoch is None else epoch
        if type(target_epoch) is not int or target_epoch != self.epoch:
            raise CryptoError("invalid key epoch")
        if not isinstance(plaintext, bytes):
            raise CryptoError("message limit exceeded or invalid plaintext")
        with self._send_lock:
            if self.send_counter >= MAX_MESSAGES_PER_EPOCH:
                raise CryptoError("message limit exceeded")
            counter = self.send_counter
            next_chain, msg_key = _ratchet_step(
                self._send_chain_key, self.identity, self.device, counter, self.epoch
            )
            prev_chain = self._send_chain_key
            self._send_chain_key = next_chain
            self.send_counter = counter + 1
            try:
                self._persist()
            except Exception:
                self._send_chain_key = prev_chain
                self.send_counter = counter
                raise
        header = {
            "version": VERSION,
            "suite": SUITE,
            "session_id": self.transcript["session_id"],
            "sender": self.identity,
            "sender_device": self.device,
            "recipient": self.peer,
            "recipient_device": self.peer_device,
            "message_id": message_id or secrets.token_hex(16),
            "counter": counter,
            "epoch": self.epoch,
        }
        nonce = counter.to_bytes(12, "big")
        ciphertext, tag = aead.encrypt(msg_key, nonce, canonical(header), plaintext)
        return {"header": header, "ciphertext": b64(ciphertext), "tag": b64(tag)}

    def decrypt(self, packet, ledger, epoch=None):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        expected_epoch = self.epoch if epoch is None else epoch
        if type(expected_epoch) is not int or expected_epoch != self.epoch:
            raise CryptoError("invalid key epoch")
        header = packet["header"]
        _check_protocol(header)
        if type(header.get("epoch")) is not int:
            raise CryptoError("invalid key epoch")
        if (
            header.get("session_id"),
            header.get("sender"),
            header.get("sender_device"),
            header.get("recipient"),
            header.get("recipient_device"),
            header.get("epoch"),
        ) != (
            self.transcript["session_id"],
            self.peer,
            self.peer_device,
            self.identity,
            self.device,
            expected_epoch,
        ):
            raise CryptoError("recipient, session, or epoch mismatch")
        counter = header.get("counter")
        if type(counter) is not int or not 0 <= counter < MAX_MESSAGES_PER_EPOCH or not isinstance(
            header.get("message_id"), str
        ):
            raise CryptoError("invalid message metadata")

        skip_id = (expected_epoch, counter)
        if skip_id in self._skipped_keys:
            msg_key = self._skipped_keys.pop(skip_id)
        else:
            if counter < self.recv_counter:
                raise CryptoError("replay or stale counter")
            if counter - self.recv_counter > MAX_SKIP:
                raise CryptoError("message skip limit exceeded")
            chain = self._recv_chain_key
            idx = self.recv_counter
            while idx < counter:
                chain, skipped_key = _ratchet_step(
                    chain, self.peer, self.peer_device, idx, expected_epoch
                )
                self._skipped_keys[(expected_epoch, idx)] = skipped_key
                idx += 1
            chain, msg_key = _ratchet_step(
                chain, self.peer, self.peer_device, counter, expected_epoch
            )
            self._recv_chain_key = chain
            self.recv_counter = counter + 1

        plaintext = aead.decrypt(
            msg_key,
            counter.to_bytes(12, "big"),
            canonical(header),
            unb64(packet["ciphertext"]),
            unb64(packet["tag"], 16),
        )
        ledger.mark(
            header["session_id"],
            self.peer + "/" + self.peer_device,
            self.identity + "/" + self.device,
            counter,
            epoch=expected_epoch,
        )
        self._persist()
        return plaintext
