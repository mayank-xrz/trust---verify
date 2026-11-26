"""Signed, recipient-bound AES-256-GCM envelopes with durable replay checks."""
import hashlib
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .handshake import derive
from .primitives import CryptoError, b64, canonical, unb64


class RecipientMismatch(CryptoError): pass
class ReplayRejected(CryptoError): pass
class CounterOutOfWindow(CryptoError): pass
class AEADFailed(CryptoError): pass


class EnvelopeCodec:
    def __init__(self, session, identity, device, cache, events):
        self.session = session
        self.identity = identity
        self.device = device
        self.cache = cache
        self.events = events
        if (identity, device) == (session.initiator, session.initiator_device):
            self.peer, self.peer_device = session.responder, session.responder_device
        elif (identity, device) == (session.responder, session.responder_device):
            self.peer, self.peer_device = session.initiator, session.initiator_device
        else:
            raise CryptoError("session identity mismatch")

    def _materials(self, header):
        if self.session.root is None:
            raise CryptoError("session closed")
        scope = canonical({"sender": header["sender_identity"], "sender_device": header["sender_device"],
                           "recipient": header["recipient_identity"], "recipient_device": header["recipient_device"],
                           "message_id": header["message_id"], "chunk_index": header["chunk_index"]})
        salt = bytes.fromhex(self.session.transcript_hash)
        key = derive(self.session.root, salt, b"track4/v2/chunk-key\x00" + scope)
        nonce = derive(self.session.root, salt, b"track4/v2/chunk-nonce\x00" + scope, 12)
        return key, nonce

    def seal(self, plaintext, *, message_id=None, chunk_index=0, chunk_count=1, whole_hash=None):
        if not isinstance(plaintext, bytes) or type(chunk_index) is not int or type(chunk_count) is not int or not 0 <= chunk_index < chunk_count <= 256:
            raise CryptoError("invalid chunk input")
        message_id = message_id or secrets.token_hex(16)
        if not isinstance(message_id, str) or not message_id:
            raise CryptoError("invalid message ID")
        counter = self.cache.reserve_send(self.session.session_id, self.identity, self.peer, message_id, chunk_index)
        header = {"version": 2, "session_id": self.session.session_id,
                  "sender_identity": self.identity, "sender_device": self.device,
                  "recipient_identity": self.peer, "recipient_device": self.peer_device,
                  "message_id": message_id, "counter": counter, "epoch": 0,
                  "chunk_index": chunk_index, "chunk_count": chunk_count,
                  "chunk_hash": hashlib.sha256(plaintext).hexdigest(),
                  "whole_hash": whole_hash or hashlib.sha256(plaintext).hexdigest()}
        key, nonce = self._materials(header)
        encrypted = AESGCM(key).encrypt(nonce, plaintext, canonical(header))
        ciphertext, tag = encrypted[:-16], encrypted[-16:]
        body = {"header": header, "ciphertext": b64(ciphertext), "tag": b64(tag)}
        return body

    def _reject(self, header, reason, exc_type):
        self.events.emit("message_rejected", "deny", actor=self.identity,
                         source_service=str(header.get("sender_identity", "")), target_service=self.identity,
                         session_id=str(header.get("session_id", "")), message_id=str(header.get("message_id", "")),
                         reason=reason)
        raise exc_type(reason)

    def open(self, packet):
        if not isinstance(packet, dict) or not isinstance(packet.get("header"), dict):
            self._reject({}, "malformed_envelope", CryptoError)
        header = packet["header"]
        if (header.get("recipient_identity"), header.get("recipient_device")) != (self.identity, self.device):
            self._reject(header, "recipient_mismatch", RecipientMismatch)
        if (header.get("sender_identity"), header.get("sender_device"), header.get("session_id")) != (self.peer, self.peer_device, self.session.session_id):
            self._reject(header, "peer_or_session_mismatch", CryptoError)
        if (header.get("version") != 2 or type(header.get("counter")) is not int or type(header.get("chunk_index")) is not int or
            type(header.get("chunk_count")) is not int or not 0 <= header["chunk_index"] < header["chunk_count"] <= 256 or
            header.get("epoch") != 0 or not isinstance(header.get("message_id"), str) or
            not isinstance(header.get("chunk_hash"), str) or len(header["chunk_hash"]) != 64 or
            not isinstance(header.get("whole_hash"), str) or len(header["whole_hash"]) != 64):
            self._reject(header, "malformed_envelope", CryptoError)
        reason = self.cache.check(self.session.session_id, self.peer, self.identity, header["message_id"], header["counter"])
        if reason:
            self._reject(header, reason, ReplayRejected if reason == "replay_rejected" else CounterOutOfWindow)
        try:
            key, nonce = self._materials(header)
            plaintext = AESGCM(key).decrypt(nonce, unb64(packet.get("ciphertext")) + unb64(packet.get("tag"), 16), canonical(header))
        except (InvalidTag, CryptoError, TypeError, KeyError, ValueError):
            self._reject(header, "aead_failed", AEADFailed)
        if hashlib.sha256(plaintext).hexdigest() != header.get("chunk_hash"):
            self._reject(header, "chunk_hash_mismatch", CryptoError)
        try:
            self.cache.mark(self.session.session_id, self.peer, self.identity, header["message_id"], header["counter"])
        except CryptoError as exc:
            reason = str(exc)
            self._reject(header, reason, ReplayRejected if reason == "replay_rejected" else CounterOutOfWindow)
        self.events.emit("message_accepted", "allow", actor=self.identity,
                         source_service=self.peer, target_service=self.identity,
                         session_id=self.session.session_id, message_id=header["message_id"])
        return plaintext
