"""Signed, peer-bound ephemeral ML-KEM handshake and directional AEAD traffic."""
import hashlib
import secrets
import threading
import time

from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65

from . import aead
from . import classical
from .primitives import CryptoError, SUITE, b64, canonical, decapsulate, digest, encapsulate, hkdf, sign, unb64, verify

VERSION = 1


def _check_protocol(value):
    if type(value.get("version")) is not int or value.get("version") != VERSION or value.get("suite") != SUITE:
        raise CryptoError("unsupported protocol or suite")


class TrustRegistry:
    """Keys arrive only from an approved out-of-band enrollment operation."""
    def __init__(self):
        self._keys = {}

    def enroll(self, identity, device, public_key):
        if not isinstance(identity, str) or not identity or not isinstance(device, str) or not device:
            raise CryptoError("invalid peer identity")
        if not isinstance(public_key, bytes) or len(public_key) != ml_dsa_65.PUBLIC_KEY_SIZE:
            raise CryptoError("invalid enrollment key")
        existing = self._keys.get((identity, device))
        if existing is not None and existing != public_key:
            raise CryptoError("identity key replacement requires explicit rotation")
        self._keys[(identity, device)] = public_key

    def key(self, identity, device):
        try:
            return self._keys[(identity, device)]
        except KeyError as exc:
            raise CryptoError("untrusted peer") from exc


class PrekeyStore:
    def __init__(self):
        self._private = {}

    def offer(self, identity, device, signing_secret, lifetime=300):
        public, private = ml_kem_768.generate_keypair()
        dh_public, dh_private = classical.keypair()
        offer = {"version": VERSION, "suite": SUITE, "responder": identity,
                 "responder_device": device, "prekey_id": secrets.token_hex(16),
                 "kem_public_key": b64(public), "x25519_public_key": b64(dh_public),
                 "expires": int(time.time()) + lifetime}
        self._private[offer["prekey_id"]] = (private, dh_private)
        return {**offer, "signature": b64(sign(signing_secret, "track4/v1/prekey", offer))}

    def take(self, prekey_id):
        try:
            return self._private.pop(prekey_id)
        except KeyError as exc:
            raise CryptoError("prekey used or missing") from exc


def _derive(kem_shared, dh_shared, init):
    transcript_hash = hashlib.sha256(canonical(init)).digest()
    salt = hashlib.sha256(b"track4/v1/handshake\x00" + transcript_hash).digest()
    return hkdf(b"track4/v1/hybrid-secret\x00" + kem_shared + dh_shared,
                salt, b"track4/v1/session-root\x00" + transcript_hash)


def initiate(offer, initiator, initiator_device, signing_secret, registry):
    unsigned = {k: v for k, v in offer.items() if k != "signature"}
    _check_protocol(unsigned)
    if unsigned.get("expires", 0) < time.time():
        raise CryptoError("expired prekey")
    responder, responder_device = unsigned["responder"], unsigned["responder_device"]
    verify(registry.key(responder, responder_device), "track4/v1/prekey", unsigned,
           unb64(offer["signature"], ml_dsa_65.SIGNATURE_SIZE))
    ciphertext, shared = encapsulate(unb64(unsigned["kem_public_key"], ml_kem_768.PUBLIC_KEY_SIZE))
    initiator_dh_public, initiator_dh_private = classical.keypair()
    dh_shared = classical.shared(initiator_dh_private, unb64(unsigned["x25519_public_key"], 44))
    init = {"version": VERSION, "suite": SUITE, "session_id": secrets.token_hex(16),
            "initiator": initiator, "initiator_device": initiator_device,
            "responder": responder, "responder_device": responder_device,
            "offer_hash": digest(unsigned), "prekey_id": unsigned["prekey_id"],
            "kem_ciphertext": b64(ciphertext), "x25519_public_key": b64(initiator_dh_public)}
    root = _derive(shared, dh_shared, init)
    return {**init, "signature": b64(sign(signing_secret, "track4/v1/init", init))}, Session(root, init, initiator, initiator_device, ready=False)


def accept(offer, init_signed, responder_signing_secret, registry, prekeys):
    init = {k: v for k, v in init_signed.items() if k != "signature"}
    _check_protocol(init)
    unsigned_offer = {k: v for k, v in offer.items() if k != "signature"}
    if unsigned_offer.get("expires", 0) < time.time() or init.get("offer_hash") != digest(unsigned_offer):
        raise CryptoError("offer mismatch or expired")
    if (init.get("responder"), init.get("responder_device")) != (unsigned_offer["responder"], unsigned_offer["responder_device"]):
        raise CryptoError("wrong responder")
    verify(registry.key(init["initiator"], init["initiator_device"]), "track4/v1/init", init,
           unb64(init_signed["signature"], ml_dsa_65.SIGNATURE_SIZE))
    private, dh_private = prekeys.take(init["prekey_id"])
    shared = decapsulate(private, unb64(init["kem_ciphertext"], ml_kem_768.CIPHERTEXT_SIZE))
    dh_shared = classical.shared(dh_private, unb64(init["x25519_public_key"], 44))
    root = _derive(shared, dh_shared, init)
    ack = {"version": VERSION, "suite": SUITE, "session_id": init["session_id"],
           "transcript_hash": digest(init), "responder": init["responder"],
           "responder_device": init["responder_device"]}
    return {**ack, "signature": b64(sign(responder_signing_secret, "track4/v1/ack", ack))}, Session(root, init, init["responder"], init["responder_device"])


def finish(ack_signed, init_signed, registry, pending_session):
    ack = {k: v for k, v in ack_signed.items() if k != "signature"}
    init = {k: v for k, v in init_signed.items() if k != "signature"}
    _check_protocol(ack)
    if ack.get("session_id") != init.get("session_id") or ack.get("transcript_hash") != digest(init):
        raise CryptoError("handshake acknowledgment mismatch")
    if (ack.get("responder"), ack.get("responder_device")) != (init.get("responder"), init.get("responder_device")):
        raise CryptoError("wrong peer acknowledgment")
    verify(registry.key(ack["responder"], ack["responder_device"]), "track4/v1/ack", ack,
           unb64(ack_signed["signature"], ml_dsa_65.SIGNATURE_SIZE))
    if pending_session.transcript != init or pending_session.identity != init["initiator"]:
        raise CryptoError("pending session mismatch")
    pending_session.ready = True


class Session:
    def __init__(self, root, transcript, identity, device, ready=True):
        self.root = root
        self.transcript = transcript
        self.identity = identity
        self.device = device
        self.send_counter = 0
        self._send_lock = threading.Lock()
        self.ready = ready
        if (identity, device) == (transcript["initiator"], transcript["initiator_device"]):
            self.peer, self.peer_device = transcript["responder"], transcript["responder_device"]
        elif (identity, device) == (transcript["responder"], transcript["responder_device"]):
            self.peer, self.peer_device = transcript["initiator"], transcript["initiator_device"]
        else:
            raise CryptoError("session identity mismatch")

    def _key(self, sender, sender_device, counter):
        label = canonical({"sender": sender, "device": sender_device, "counter": counter})
        salt = hashlib.sha256(b"track4/v1/message-key\x00" + label).digest()
        return hkdf(self.root, salt, b"track4/v1/aes-256-gcm\x00" + label)

    def encrypt(self, plaintext, message_id=None, epoch=0):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        if type(epoch) is not int or epoch < 0:
            raise CryptoError("invalid key epoch")
        if not isinstance(plaintext, bytes):
            raise CryptoError("message limit exceeded or invalid plaintext")
        with self._send_lock:
            if self.send_counter >= 100000:
                raise CryptoError("message limit exceeded")
            counter = self.send_counter
            self.send_counter += 1
        header = {"version": VERSION, "suite": SUITE, "session_id": self.transcript["session_id"],
                  "sender": self.identity, "sender_device": self.device,
                  "recipient": self.peer, "recipient_device": self.peer_device,
                  "message_id": message_id or secrets.token_hex(16), "counter": counter, "epoch": epoch}
        key = self._key(self.identity, self.device, counter)
        nonce = counter.to_bytes(12, "big")
        ciphertext, tag = aead.encrypt(key, nonce, canonical(header), plaintext)
        return {"header": header, "ciphertext": b64(ciphertext), "tag": b64(tag)}

    def decrypt(self, packet, ledger, epoch=0):
        if not self.ready:
            raise CryptoError("handshake not confirmed")
        if type(epoch) is not int or epoch < 0:
            raise CryptoError("invalid key epoch")
        header = packet["header"]
        _check_protocol(header)
        if type(header.get("epoch")) is not int:
            raise CryptoError("invalid key epoch")
        if (header.get("session_id"), header.get("sender"), header.get("sender_device"),
            header.get("recipient"), header.get("recipient_device"), header.get("epoch")) != (
            self.transcript["session_id"], self.peer, self.peer_device, self.identity, self.device, epoch):
            raise CryptoError("recipient, session, or epoch mismatch")
        counter = header.get("counter")
        if type(counter) is not int or not 0 <= counter < 100000 or not isinstance(header.get("message_id"), str):
            raise CryptoError("invalid message metadata")
        key = self._key(self.peer, self.peer_device, counter)
        plaintext = aead.decrypt(key, counter.to_bytes(12, "big"), canonical(header),
                                 unb64(packet["ciphertext"]), unb64(packet["tag"], 16))
        ledger.mark(header["session_id"], self.peer + "/" + self.peer_device,
                    self.identity + "/" + self.device, counter)
        return plaintext
