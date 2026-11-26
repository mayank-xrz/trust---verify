"""Authenticated ephemeral X25519 + ML-KEM-768 session establishment."""
from dataclasses import dataclass
import hashlib
import secrets

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import ml_kem_768

from .primitives import CryptoError, b64, canonical, sign, unb64, verify

HYBRID_SUITE = "ML-KEM-768+X25519+ML-DSA-65+AES-256-GCM+HKDF-SHA256/v2"


def derive(secret, salt, label, length=32):
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=label).derive(secret)


@dataclass
class HybridSession:
    session_id: str
    initiator: str
    initiator_device: str
    responder: str
    responder_device: str
    transcript: dict
    transcript_hash: str
    root: bytes
    signatures: dict

    def close(self):
        # Immutable Python bytes cannot be reliably zeroized. Drop the reference.
        self.root = None


def establish(initiator, initiator_device, responder, responder_device,
              initiator_signing_secret, initiator_signing_public,
              responder_signing_secret, responder_signing_public):
    """Run both sides locally; return their matching session views and public transcript.

    Ephemeral private keys and shared secrets remain local to this function, then lose
    all live references on return. Identity keys sign only the public transcript.
    """
    ix = x25519.X25519PrivateKey.generate()
    rx = x25519.X25519PrivateKey.generate()
    kem_public, kem_private = ml_kem_768.keygen()
    kem_ciphertext, initiator_kem_shared = ml_kem_768.encaps(kem_public)
    responder_kem_shared = ml_kem_768.decaps(kem_private, kem_ciphertext)
    ix_public = ix.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    rx_public = rx.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    transcript = {"version": 2, "suite": HYBRID_SUITE,
                  "session_id": secrets.token_hex(16), "initiator": initiator,
                  "initiator_device": initiator_device, "responder": responder,
                  "responder_device": responder_device, "initiator_x25519": b64(ix_public),
                  "responder_x25519": b64(rx_public), "responder_mlkem": b64(kem_public),
                  "mlkem_ciphertext": b64(kem_ciphertext)}
    initiator_sig = sign(initiator_signing_secret, "track4/v2/handshake", transcript)
    responder_sig = sign(responder_signing_secret, "track4/v2/handshake", transcript)
    verify_handshake(transcript, initiator_signing_public, initiator_sig)
    verify_handshake(transcript, responder_signing_public, responder_sig)
    transcript_hash = hashlib.sha256(canonical(transcript)).digest()
    ix_shared = ix.exchange(rx.public_key())
    rx_shared = rx.exchange(ix.public_key())
    if ix_shared != rx_shared or initiator_kem_shared != responder_kem_shared:
        raise CryptoError("hybrid handshake secret mismatch")
    secret_i = transcript_hash + ix_shared + initiator_kem_shared
    secret_r = transcript_hash + rx_shared + responder_kem_shared
    root_i = derive(secret_i, transcript_hash, b"track4/v2/session-root")
    root_r = derive(secret_r, transcript_hash, b"track4/v2/session-root")
    if root_i != root_r:
        raise CryptoError("hybrid handshake confirmation failed")
    fields = (transcript["session_id"], initiator, initiator_device, responder,
              responder_device, transcript, transcript_hash.hex())
    signatures = {"initiator": b64(initiator_sig), "responder": b64(responder_sig)}
    return HybridSession(*fields, root_i, signatures), HybridSession(*fields, root_r, signatures)


def verify_handshake(transcript, public_key, signature, events=None):
    try:
        verify(public_key, "track4/v2/handshake", transcript, signature)
    except CryptoError:
        if events is not None:
            events.emit("signature_invalid", "deny", actor=str(transcript.get("initiator", "")),
                        source_service=str(transcript.get("initiator", "")),
                        target_service=str(transcript.get("responder", "")),
                        session_id=str(transcript.get("session_id", "")), reason="signature_invalid")
        raise


def attempt_identity_only_recovery(packet, identity_secret, public_transcript, events):
    """Demonstrate an offline identity-key-only attack against a recorded packet.

    This exercises one concrete candidate derivation; it is not a proof that no
    imaginable attack exists. An actual offline attacker would not be observable.
    """
    header = packet["header"]
    transcript_hash = hashlib.sha256(canonical(public_transcript)).digest()
    guessed_root = derive(identity_secret + transcript_hash, transcript_hash,
                          b"track4/v2/identity-only-guess")
    scope = canonical({"sender": header["sender_identity"], "sender_device": header["sender_device"],
                       "recipient": header["recipient_identity"], "recipient_device": header["recipient_device"],
                       "message_id": header["message_id"], "chunk_index": header["chunk_index"]})
    key = derive(guessed_root, transcript_hash, b"track4/v2/chunk-key\x00" + scope)
    nonce = derive(guessed_root, transcript_hash, b"track4/v2/chunk-nonce\x00" + scope, 12)
    try:
        AESGCM(key).decrypt(nonce, unb64(packet["ciphertext"]) + unb64(packet["tag"], 16), canonical(header))
    except InvalidTag:
        events.emit("message_rejected", "deny", actor=header["sender_identity"],
                    source_service=header["sender_identity"], target_service=header["recipient_identity"],
                    session_id=header["session_id"], message_id=header["message_id"],
                    reason="identity_key_only_cannot_decrypt")
        return None
    raise CryptoError("identity-only recovery unexpectedly succeeded")
