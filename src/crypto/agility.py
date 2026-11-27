"""Cryptographic Agility & Multi-Family PQC Defense (`track4/v2-paranoid`).

Provides defense-in-depth against future breakthroughs in structured lattice
cryptanalysis by combining three independent hard problems for key agreement:
- Classical ECDH: X25519
- Module-LWE (NIST FIPS 203 Cat 5): ML-KEM-1024
- Code-based Quasi-Cyclic Syndrome Decoding (non-lattice): HQC-256

And dual post-quantum signatures from two independent mathematical families:
- Lattice-based (NIST FIPS 204 Cat 5): ML-DSA-87
- Hash-based stateless (NIST FIPS 205): SLH-DSA-SHA2-128f
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from dataclasses import dataclass
from typing import Dict, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.kem import hqc_256, ml_kem_1024
from pqcrypto.sign import ml_dsa_87

try:
    from pqcrypto.sign import slh_dsa_sha2_128f
except ImportError:
    # pqcrypto 0.4.0 exposes the same standardized parameter set under its
    # pre-FIPS SPHINCS+ name. Keep one internal name without changing the
    # primitive or implementing a substitute.
    from pqcrypto.sign import sphincs_sha2_128f_simple as slh_dsa_sha2_128f

from ._pqcrypto_compat import kem_decaps, kem_encaps, kem_keygen, sig_keygen, sig_sign, sig_verify
from .handshake import HandshakeError, SessionKeys, _best_effort_zeroize


def _require_v2_paranoid() -> None:
    if hqc_256 is None or slh_dsa_sha2_128f is None:
        raise HandshakeError("track4/v2-paranoid requires HQC-256 and SLH-DSA-SHA2-128f")

SUITE_V1 = "track4/v1"
SUITE_V2_PARANOID = "track4/v2-paranoid"


@dataclass
class DualIdentityKeypair:
    """Long-term dual-family identity keys: ML-DSA-87 (lattice) + SLH-DSA-SHA2-128f (hash)."""
    mldsa_public: bytes
    mldsa_secret: bytes
    slhdsa_public: bytes
    slhdsa_secret: bytes

    @classmethod
    def generate(cls) -> "DualIdentityKeypair":
        _require_v2_paranoid()
        mldsa_pk, mldsa_sk = sig_keygen(ml_dsa_87)
        slh_pk, slh_sk = sig_keygen(slh_dsa_sha2_128f)
        return cls(
            mldsa_public=mldsa_pk,
            mldsa_secret=mldsa_sk,
            slhdsa_public=slh_pk,
            slhdsa_secret=slh_sk,
        )

    def public_bundle(self) -> Tuple[bytes, bytes]:
        return self.mldsa_public, self.slhdsa_public


def _hkdf_sha512(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    return HKDF(
        algorithm=hashes.SHA512(),
        length=length,
        salt=salt,
        info=info,
    ).derive(ikm)


class ParanoidHandshakeSession:
    """Triple-family KEM (X25519 + ML-KEM-1024 + HQC-256) + Dual Signatures (ML-DSA-87 + SLH-DSA)."""

    def __init__(self, identity: str, device: str, identity_keys: DualIdentityKeypair) -> None:
        self.identity = identity
        self.device = device
        self._id_keys = identity_keys
        self._x25519_priv: Optional[X25519PrivateKey] = None
        self._mlkem_priv: Optional[bytearray] = None
        self._hqc_priv: Optional[bytearray] = None

    def has_ephemeral_secrets(self) -> bool:
        return (
            self._x25519_priv is not None
            or self._mlkem_priv is not None
            or self._hqc_priv is not None
        )

    def _wipe_ephemerals(self) -> None:
        _best_effort_zeroize(self._mlkem_priv)
        _best_effort_zeroize(self._hqc_priv)
        self._mlkem_priv = None
        self._hqc_priv = None
        self._x25519_priv = None

    def create_responder_hello(self) -> Dict[str, str]:
        self._x25519_priv = X25519PrivateKey.generate()
        x25519_pub = self._x25519_priv.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        mlkem_pub, mlkem_priv = kem_keygen(ml_kem_1024)
        hqc_pub, hqc_priv = kem_keygen(hqc_256)
        self._mlkem_priv = bytearray(mlkem_priv)
        self._hqc_priv = bytearray(hqc_priv)

        hello = {
            "suite": SUITE_V2_PARANOID,
            "responder_identity": self.identity,
            "responder_device": self.device,
            "session_id": "sess-v2-" + secrets.token_hex(16),
            "x25519_pub": base64.b64encode(x25519_pub).decode("ascii"),
            "mlkem1024_pub": base64.b64encode(mlkem_pub).decode("ascii"),
            "hqc256_pub": base64.b64encode(hqc_pub).decode("ascii"),
        }
        msg = b"track4/v2/hello\x00" + json.dumps(hello, sort_keys=True, separators=(",", ":")).encode("utf-8")
        hello["sig_mldsa87"] = base64.b64encode(sig_sign(ml_dsa_87, self._id_keys.mldsa_secret, msg)).decode("ascii")
        hello["sig_slhdsa"] = base64.b64encode(sig_sign(slh_dsa_sha2_128f, self._id_keys.slhdsa_secret, msg)).decode("ascii")
        return hello

    def initiate(
        self,
        responder_hello: Dict[str, str],
        responder_public_bundle: Tuple[bytes, bytes],
    ) -> Tuple[Dict[str, str], SessionKeys]:
        if responder_hello.get("suite") != SUITE_V2_PARANOID:
            raise HandshakeError("Unsupported or downgraded suite")
        unsigned = {k: v for k, v in responder_hello.items() if k not in ("sig_mldsa87", "sig_slhdsa")}
        msg = b"track4/v2/hello\x00" + json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        resp_mldsa_pk, resp_slh_pk = responder_public_bundle
        sig1 = base64.b64decode(responder_hello["sig_mldsa87"], validate=True)
        sig2 = base64.b64decode(responder_hello["sig_slhdsa"], validate=True)
        if not sig_verify(ml_dsa_87, resp_mldsa_pk, msg, sig1) or not sig_verify(slh_dsa_sha2_128f, resp_slh_pk, msg, sig2):
            raise HandshakeError("Responder dual PQC signature verification failed")

        resp_x25519 = X25519PublicKey.from_public_bytes(base64.b64decode(unsigned["x25519_pub"], validate=True))
        eph_x25519 = X25519PrivateKey.generate()
        init_x25519_pub = eph_x25519.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        x25519_ss = eph_x25519.exchange(resp_x25519)
        mlkem_ct, mlkem_ss = kem_encaps(ml_kem_1024, base64.b64decode(unsigned["mlkem1024_pub"], validate=True))
        hqc_ct, hqc_ss = kem_encaps(hqc_256, base64.b64decode(unsigned["hqc256_pub"], validate=True))

        transcript = {
            "suite": SUITE_V2_PARANOID,
            "session_id": unsigned["session_id"],
            "initiator_identity": self.identity,
            "initiator_device": self.device,
            "responder_identity": unsigned["responder_identity"],
            "responder_device": unsigned["responder_device"],
            "resp_x25519_pub": unsigned["x25519_pub"],
            "resp_mlkem1024_pub": unsigned["mlkem1024_pub"],
            "resp_hqc256_pub": unsigned["hqc256_pub"],
            "init_x25519_pub": base64.b64encode(init_x25519_pub).decode("ascii"),
            "mlkem1024_ct": base64.b64encode(mlkem_ct).decode("ascii"),
            "hqc256_ct": base64.b64encode(hqc_ct).decode("ascii"),
        }
        th_bytes = hashlib.sha512(json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()
        ikm = bytearray(th_bytes + x25519_ss + mlkem_ss + hqc_ss)
        try:
            tx_key = _hkdf_sha512(bytes(ikm), th_bytes, b"track4/v2/initiator-to-responder")
            rx_key = _hkdf_sha512(bytes(ikm), th_bytes, b"track4/v2/responder-to-initiator")
            resumption_secret = _hkdf_sha512(bytes(ikm), th_bytes, b"track4/v2/resumption-secret")
        finally:
            _best_effort_zeroize(ikm)
            del eph_x25519
            self._wipe_ephemerals()

        tmsg = b"track4/v2/transcript\x00" + th_bytes
        init_msg = {
            **transcript,
            "sig_mldsa87": base64.b64encode(sig_sign(ml_dsa_87, self._id_keys.mldsa_secret, tmsg)).decode("ascii"),
            "sig_slhdsa": base64.b64encode(sig_sign(slh_dsa_sha2_128f, self._id_keys.slhdsa_secret, tmsg)).decode("ascii"),
        }
        return init_msg, SessionKeys(
            session_id=unsigned["session_id"],
            transcript_hash=th_bytes.hex(),
            tx_key=tx_key,
            rx_key=rx_key,
            resumption_secret=resumption_secret,
            peer_identity=unsigned["responder_identity"],
            peer_device=unsigned["responder_device"],
        )

    def complete_responder(
        self,
        init_msg: Dict[str, str],
        initiator_public_bundle: Tuple[bytes, bytes],
    ) -> SessionKeys:
        if self._x25519_priv is None or self._mlkem_priv is None or self._hqc_priv is None:
            raise HandshakeError("No ephemeral keys present")
        if init_msg.get("suite") != SUITE_V2_PARANOID:
            self._wipe_ephemerals()
            raise HandshakeError("Unsupported or downgraded suite")

        transcript = {k: v for k, v in init_msg.items() if k not in ("sig_mldsa87", "sig_slhdsa")}
        th_bytes = hashlib.sha512(json.dumps(transcript, sort_keys=True, separators=(",", ":")).encode("utf-8")).digest()
        tmsg = b"track4/v2/transcript\x00" + th_bytes
        init_mldsa_pk, init_slh_pk = initiator_public_bundle
        sig1 = base64.b64decode(init_msg["sig_mldsa87"], validate=True)
        sig2 = base64.b64decode(init_msg["sig_slhdsa"], validate=True)
        if not sig_verify(ml_dsa_87, init_mldsa_pk, tmsg, sig1) or not sig_verify(slh_dsa_sha2_128f, init_slh_pk, tmsg, sig2):
            self._wipe_ephemerals()
            raise HandshakeError("Initiator dual PQC signature verification failed")

        init_x25519 = X25519PublicKey.from_public_bytes(base64.b64decode(transcript["init_x25519_pub"], validate=True))
        x25519_ss = self._x25519_priv.exchange(init_x25519)
        mlkem_ss = kem_decaps(ml_kem_1024, bytes(self._mlkem_priv), base64.b64decode(transcript["mlkem1024_ct"], validate=True))
        hqc_ss = kem_decaps(hqc_256, bytes(self._hqc_priv), base64.b64decode(transcript["hqc256_ct"], validate=True))

        ikm = bytearray(th_bytes + x25519_ss + mlkem_ss + hqc_ss)
        try:
            rx_key = _hkdf_sha512(bytes(ikm), th_bytes, b"track4/v2/initiator-to-responder")
            tx_key = _hkdf_sha512(bytes(ikm), th_bytes, b"track4/v2/responder-to-initiator")
            resumption_secret = _hkdf_sha512(bytes(ikm), th_bytes, b"track4/v2/resumption-secret")
        finally:
            _best_effort_zeroize(ikm)
            self._wipe_ephemerals()

        return SessionKeys(
            session_id=transcript["session_id"],
            transcript_hash=th_bytes.hex(),
            tx_key=tx_key,
            rx_key=rx_key,
            resumption_secret=resumption_secret,
            peer_identity=transcript["initiator_identity"],
            peer_device=transcript["initiator_device"],
        )
