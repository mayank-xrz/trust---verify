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
import fcntl
import json
import os
from pathlib import Path
import secrets
import tempfile
import threading
import time
from contextlib import contextmanager

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from . import aead
from . import classical
from .node_bridge import call_node
from .primitives import (
    CryptoError,
    SUITE,
    b64,
    canonical,
    decapsulate,
    digest,
    encapsulate,
    hkdf,
    kem_keypair,
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
    def __init__(self, state_path=None, registry=None):
        self.state_path = Path(state_path) if state_path is not None else None
        self.registry = registry
        self._private = {}
        if self.state_path is not None and self.state_path.exists():
            self._load()

    def _load(self):
        with self.state_path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        self._private = {}
        for prekey_id, entry in data.get("prekeys", {}).items():
            self._private[prekey_id] = {
                "kem_private": unb64(entry["kem_private"], ml_kem_768.SECRET_KEY_SIZE),
                "dh_private": unb64(entry["dh_private"], 48),
                "created_at": entry.get("created_at", 0),
                "expires_at": entry.get("expires_at", entry.get("expires")),
                "revoked": entry.get("revoked", False),
                "offer": entry.get("offer"),
                "identity": entry.get("identity"),
                "device": entry.get("device"),
            }
        self.purge_expired()

    def _save(self):
        if self.state_path is None:
            return
        payload = {
            "prekeys": {
                prekey_id: {
                    "kem_private": b64(entry["kem_private"]),
                    "dh_private": b64(entry["dh_private"]),
                    "created_at": entry["created_at"],
                    "expires_at": entry["expires_at"],
                    "revoked": entry["revoked"],
                    "offer": entry.get("offer"),
                    "identity": entry.get("identity"),
                    "device": entry.get("device"),
                }
                for prekey_id, entry in self._private.items()
            }
        }
        try:
            _atomic_write_json(self.state_path, payload)
        except OSError as exc:
            raise CryptoError("failed to persist prekey store") from exc

    def purge_expired(self, now=None):
        cutoff = time.time() if now is None else now
        expired = [pid for pid, entry in self._private.items() if entry["expires_at"] <= cutoff]
        for pid in expired:
            del self._private[pid]
        if expired:
            self._save()
        return len(expired)

    def offer(self, identity, device, signing_secret, lifetime=300):
        self.purge_expired()
        if self.registry is not None and self.registry.is_revoked(identity, device):
            raise CryptoError("peer trust revoked")
        if type(lifetime) is not int or lifetime <= 0:
            raise CryptoError("invalid prekey lifetime")
        public, private = kem_keypair()
        dh_public, dh_private = classical.keypair()
        created = int(time.time())
        expires = created + lifetime
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
        signed_offer = {**offer, "signature": b64(sign(signing_secret, "track4/v1/prekey", offer))}
        self._private[offer["prekey_id"]] = {"kem_private": private, "dh_private": dh_private,
                                             "created_at": created, "expires_at": expires,
                                             "revoked": False, "offer": signed_offer,
                                             "identity": identity, "device": device}
        self._save()
        return signed_offer

    def bundle(self, prekey_id):
        self.purge_expired()
        entry = self._private.get(prekey_id)
        if entry is None or entry["revoked"] or entry.get("offer") is None or (
            self.registry is not None and self.registry.is_revoked(entry["identity"], entry["device"])
        ):
            raise CryptoError("expired or revoked prekey")
        return entry["offer"].copy()

    def take(self, prekey_id):
        self.purge_expired()
        try:
            entry = self._private.pop(prekey_id)
        except KeyError as exc:
            raise CryptoError("prekey used or missing") from exc
        self._save()
        if entry["revoked"] or entry["expires_at"] <= time.time() or (
            self.registry is not None and self.registry.is_revoked(entry["identity"], entry["device"])
        ):
            raise CryptoError("expired or revoked prekey")
        return entry["kem_private"], entry["dh_private"]

    def revoke(self, prekey_id):
        if prekey_id not in self._private:
            raise CryptoError("prekey used or missing")
        self._private[prekey_id]["revoked"] = True
        self._save()


def _handshake_derive(kem_shared, dh_shared, init, sender_id, sender_dev, recv_id, recv_dev, with_confirm=False):
    transcript_hash = hashlib.sha256(canonical(init)).digest()
    salt = hashlib.sha256(b"track4/v1/handshake\x00" + transcript_hash).digest()
    ikm = b"track4/v1/hybrid-secret\x00" + kem_shared + dh_shared
    info = b"track4/v1/session-root\x00" + transcript_hash
    s_label = canonical({"identity": sender_id, "device": sender_dev, "epoch": 0})
    r_label = canonical({"identity": recv_id, "device": recv_dev, "epoch": 0})
    req = {
        "op": "hkdf_session",
        "ikm": b64(ikm),
        "salt": b64(salt),
        "info": b64(info),
        "send_salt": b64(hashlib.sha256(b"track4/v1/chain-init\x00" + s_label).digest()),
        "send_info": b64(b"track4/v1/chain-key\x00" + s_label),
        "recv_salt": b64(hashlib.sha256(b"track4/v1/chain-init\x00" + r_label).digest()),
        "recv_info": b64(b"track4/v1/chain-key\x00" + r_label),
    }
    if with_confirm:
        req["confirm_salt"] = b64(hashlib.sha256(b"track4/v1/confirm-salt\x00" + transcript_hash).digest())
        req["confirm_info"] = b64(b"track4/v1/key-confirm\x00" + init["session_id"].encode("ascii"))
    res = call_node(req, CryptoError)
    root = unb64(res["root"], 32)
    send_chain = unb64(res["send_chain"], 32)
    recv_chain = unb64(res["recv_chain"], 32)
    if with_confirm:
        confirm_key = unb64(res["confirm_key"], 32)
        confirm_mac = hmac.new(confirm_key, transcript_hash, hashlib.sha256).hexdigest()
        return root, send_chain, recv_chain, confirm_mac
    return root, send_chain, recv_chain


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
    initiator_dh_public, dh_shared = classical.ephemeral_shared(unb64(unsigned["x25519_public_key"], 44))
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
    root, send_chain, recv_chain = _handshake_derive(
        shared, dh_shared, init, initiator, initiator_device, responder, responder_device, with_confirm=False
    )
    session = Session(
        root, init, initiator, initiator_device, ready=False, state_path=state_path,
        _initial_chains=(send_chain, recv_chain),
    )
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
    if registry.is_revoked(init["responder"], init["responder_device"]):
        raise CryptoError("peer trust revoked")
    verify(
        registry.key(init["initiator"], init["initiator_device"]),
        "track4/v1/init",
        init,
        unb64(init_signed["signature"], ml_dsa_65.SIGNATURE_SIZE),
    )
    private, dh_private = prekeys.take(init["prekey_id"])
    shared = decapsulate(private, unb64(init["kem_ciphertext"], ml_kem_768.CIPHERTEXT_SIZE))
    dh_shared = classical.shared(dh_private, unb64(init["x25519_public_key"], 44))
    root, send_chain, recv_chain, key_confirm = _handshake_derive(
        shared,
        dh_shared,
        init,
        init["responder"],
        init["responder_device"],
        init["initiator"],
        init["initiator_device"],
        with_confirm=True,
    )
    ack = {
        "version": VERSION,
        "suite": SUITE,
        "session_id": init["session_id"],
        "transcript_hash": digest(init),
        "responder": init["responder"],
        "responder_device": init["responder_device"],
        "key_confirm": key_confirm,
    }
    session = Session(
        root, init, init["responder"], init["responder_device"], ready=True, state_path=state_path,
        _initial_chains=(send_chain, recv_chain),
    )
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

    def __init__(self, root, transcript, identity, device, ready=True, state_path=None, auto_rekey_at=None, _initial_chains=None, max_messages_per_epoch=MAX_MESSAGES_PER_EPOCH):
        self.root = root
        self.transcript = transcript
        self.identity = identity
        self.device = device
        if state_path is None:
            label = canonical({"session_id": transcript["session_id"], "identity": identity, "device": device})
            filename = hashlib.sha256(label).hexdigest() + ".json"
            state_path = Path(os.environ.get("TRACK4_STATE_DIR") or tempfile.gettempdir()) / "track4-local" / "sessions" / filename
        self.state_path = Path(state_path)
        self.epoch = 0
        self.send_counter = 0
        self.recv_counter = 0
        self.max_messages_per_epoch = max_messages_per_epoch
        self.auto_rekey_at = max_messages_per_epoch if auto_rekey_at is None else auto_rekey_at
        if type(self.max_messages_per_epoch) is not int or not 1 <= self.max_messages_per_epoch <= MAX_MESSAGES_PER_EPOCH or type(self.auto_rekey_at) is not int or not 1 <= self.auto_rekey_at <= self.max_messages_per_epoch:
            raise CryptoError("invalid epoch message limit")
        self._skipped_keys = {}
        self._send_lock = threading.Lock()
        self.ready = ready
        if (identity, device) == (transcript["initiator"], transcript["initiator_device"]):
            self.peer, self.peer_device = transcript["responder"], transcript["responder_device"]
        elif (identity, device) == (transcript["responder"], transcript["responder_device"]):
            self.peer, self.peer_device = transcript["initiator"], transcript["initiator_device"]
        else:
            raise CryptoError("session identity mismatch")
        if _initial_chains is not None:
            self._send_chain_key, self._recv_chain_key = _initial_chains
        else:
            self._send_chain_key = _derive_chain_key(self.root, self.identity, self.device, self.epoch)
            self._recv_chain_key = _derive_chain_key(self.root, self.peer, self.peer_device, self.epoch)
        if self.state_path is not None and self.ready:
            if self.state_path.exists():
                raise CryptoError("session state already exists")
            self._persist()

    def _persist(self):
        if self.state_path is None:
            return
        if self.state_path.is_dir():
            raise CryptoError("invalid session state path")
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
            "max_messages_per_epoch": self.max_messages_per_epoch,
            "auto_rekey_at": self.auto_rekey_at,
            "recv_counter": self.recv_counter,
            "root": b64(self.root),
            "send_chain_key": b64(self._send_chain_key),
            "recv_chain_key": b64(self._recv_chain_key),
            "skipped_keys": {
                f"{ep}:{cnt}": b64(key) for (ep, cnt), key in self._skipped_keys.items()
            },
        }
        try:
            marker = self.state_path.with_name(self.state_path.name + ".counter")
            position = (self.epoch, self.send_counter)
            if marker.exists():
                with marker.open(encoding="utf-8") as stream:
                    old = json.load(stream)
                previous = (old["epoch"], old["send_counter"])
                if position < previous:
                    raise CryptoError("session counter rollback detected")
            # Write the high-water mark first. A crash between files fails closed on load.
            _atomic_write_json(marker, {"epoch": position[0], "send_counter": position[1]})
            _atomic_write_json(self.state_path, payload)
        except OSError as exc:
            raise CryptoError("failed to persist session state") from exc

    @classmethod
    def load(cls, state_path):
        path = Path(state_path)
        with path.open(encoding="utf-8") as stream:
            data = json.load(stream)
        marker = path.with_name(path.name + ".counter")
        if not marker.exists():
            raise CryptoError("session counter reservation missing")
        with marker.open(encoding="utf-8") as stream:
            high_water = json.load(stream)
        if (data.get("epoch"), data.get("send_counter")) != (high_water.get("epoch"), high_water.get("send_counter")):
            raise CryptoError("session counter rollback detected")
        for field in ("session_id", "identity", "device", "peer", "peer_device", "transcript", "root", "send_chain_key", "recv_chain_key", "epoch", "send_counter", "recv_counter", "ready"):
            if field not in data:
                raise CryptoError("incomplete session state")
        limit = data.get("max_messages_per_epoch", MAX_MESSAGES_PER_EPOCH)
        if (not isinstance(data["transcript"], dict) or
            type(limit) is not int or not 1 <= limit <= MAX_MESSAGES_PER_EPOCH or
            type(data["epoch"]) is not int or data["epoch"] < 0 or
            type(data["send_counter"]) is not int or not 0 <= data["send_counter"] <= limit or
            type(data["recv_counter"]) is not int or not 0 <= data["recv_counter"] <= limit or
            data["transcript"].get("session_id") != data["session_id"]):
            raise CryptoError("invalid session counter or identity")
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
        inst.max_messages_per_epoch = limit
        inst.auto_rekey_at = data.get("auto_rekey_at", limit)
        if type(inst.auto_rekey_at) is not int or not 1 <= inst.auto_rekey_at <= limit:
            raise CryptoError("invalid epoch message limit")
        inst._send_chain_key = unb64(data["send_chain_key"], 32)
        inst._recv_chain_key = unb64(data["recv_chain_key"], 32)
        inst._skipped_keys = {
            tuple(map(int, k.split(":", 1))): unb64(v, 32)
            for k, v in data.get("skipped_keys", {}).items()
        }
        inst._send_lock = threading.Lock()
        return inst

    @contextmanager
    def _disk_lock(self):
        if self.state_path is None:
            yield
            return
        lock_path = self.state_path.with_name(self.state_path.name + ".lock")
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def _refresh_for_send(self):
        if self.state_path is None:
            return
        try:
            fresh = type(self).load(self.state_path)
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise CryptoError("invalid persisted session state") from exc
        if fresh.transcript != self.transcript or (fresh.identity, fresh.device) != (self.identity, self.device):
            raise CryptoError("session state identity mismatch")
        if fresh.epoch < self.epoch or (fresh.epoch == self.epoch and fresh.send_counter < self.send_counter):
            raise CryptoError("session counter rollback detected")
        for name in ("root", "epoch", "send_counter", "recv_counter", "_send_chain_key", "_recv_chain_key", "_skipped_keys", "ready"):
            setattr(self, name, getattr(fresh, name))

    def _next_epoch_material(self, next_epoch):
        salt = hashlib.sha256(b"track4/v1/rekey\x00" + next_epoch.to_bytes(8, "big")).digest()
        info = b"track4/v1/epoch-root\x00" + canonical(
            {"session_id": self.transcript["session_id"], "epoch": next_epoch}
        )
        new_root = hkdf(self.root, salt, info)
        send_chain = _derive_chain_key(new_root, self.identity, self.device, next_epoch)
        recv_chain = _derive_chain_key(new_root, self.peer, self.peer_device, next_epoch)
        return new_root, send_chain, recv_chain

    def _rekey_locked(self):
        new_epoch = self.epoch + 1
        self.root, self._send_chain_key, self._recv_chain_key = self._next_epoch_material(new_epoch)
        self.epoch = new_epoch
        self.send_counter = 0
        self.recv_counter = 0
        self._skipped_keys.clear()
        self._persist()
        return self.epoch

    def rekey(self):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        with self._send_lock:
            with self._disk_lock():
                self._refresh_for_send()
                return self._rekey_locked()

    def encrypt(self, plaintext, message_id=None, epoch=None):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        if not isinstance(plaintext, bytes):
            raise CryptoError("message limit exceeded or invalid plaintext")
        with self._send_lock:
            with self._disk_lock():
                self._refresh_for_send()
                if epoch is None and self.send_counter >= self.auto_rekey_at:
                    self._rekey_locked()
                target_epoch = self.epoch if epoch is None else epoch
                if type(target_epoch) is not int or target_epoch != self.epoch:
                    raise CryptoError("invalid key epoch")
                if self.send_counter >= self.max_messages_per_epoch:
                    if epoch is not None:
                        raise CryptoError("explicit epoch exhausted")
                    self._rekey_locked()
                counter = self.send_counter
                next_chain, msg_key = _ratchet_step(
                    self._send_chain_key, self.identity, self.device, counter, self.epoch
                )
                self._send_chain_key = next_chain
                self.send_counter = counter + 1
                self._persist()
                reserved_epoch = self.epoch
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
            "epoch": reserved_epoch,
        }
        nonce = counter.to_bytes(12, "big")
        ciphertext, tag = aead.encrypt(msg_key, nonce, canonical(header), plaintext)
        return {"header": header, "ciphertext": b64(ciphertext), "tag": b64(tag)}

    def decrypt(self, packet, ledger, epoch=None):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        header = packet["header"]
        _check_protocol(header)
        pkt_epoch = header.get("epoch")
        if type(pkt_epoch) is not int:
            raise CryptoError("invalid key epoch")

        auto_advance = None
        if epoch is None:
            if pkt_epoch == self.epoch:
                expected_epoch = self.epoch
            elif pkt_epoch == self.epoch + 1:
                expected_epoch = pkt_epoch
                auto_advance = self._next_epoch_material(pkt_epoch)
            else:
                raise CryptoError("recipient, session, or epoch mismatch")
        else:
            if type(epoch) is not int or epoch != self.epoch:
                raise CryptoError("invalid key epoch")
            expected_epoch = epoch

        if (
            header.get("session_id"),
            header.get("sender"),
            header.get("sender_device"),
            header.get("recipient"),
            header.get("recipient_device"),
            pkt_epoch,
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
        if type(counter) is not int or not 0 <= counter < self.max_messages_per_epoch or not isinstance(
            header.get("message_id"), str
        ):
            raise CryptoError("invalid message metadata")

        if auto_advance is not None:
            new_root, new_send_chain, new_recv_chain = auto_advance
            if counter > MAX_SKIP:
                raise CryptoError("message skip limit exceeded")
            chain = new_recv_chain
            skipped = {}
            idx = 0
            while idx < counter:
                chain, sk = _ratchet_step(chain, self.peer, self.peer_device, idx, expected_epoch)
                skipped[(expected_epoch, idx)] = sk
                idx += 1
            chain, msg_key = _ratchet_step(chain, self.peer, self.peer_device, counter, expected_epoch)
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
            self.root = new_root
            self._send_chain_key = new_send_chain
            self._recv_chain_key = chain
            self.epoch = expected_epoch
            self.send_counter = 0
            self.recv_counter = counter + 1
            self._skipped_keys = skipped
            self._persist()
            return plaintext

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
