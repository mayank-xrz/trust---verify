"""Short-lived Ed25519-signed bearer tokens for API authentication."""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass
from datetime import timedelta

from .clock import Clock
from .crypto import (
    b64d,
    b64e,
    canonical_json_bytes,
    ed25519_sign,
    ed25519_verify,
)
from .errors import NotAuthorized, StateUnavailable


def load_token_signing_keypair() -> tuple[bytes, bytes]:
    """Load the shared Ed25519 token-signing keypair from the environment.

    Fails closed: a missing, malformed, or wrong-length seed is a configuration
    error, not a reason to mint an ephemeral key that peers cannot verify.
    """
    seed_b64 = os.environ.get("TOKEN_SIGNING_SEED_B64", "").strip()
    if not seed_b64:
        raise StateUnavailable("TOKEN_SIGNING_SEED_B64 is required")
    try:
        priv = b64d(seed_b64)
    except Exception as exc:
        raise StateUnavailable("TOKEN_SIGNING_SEED_B64 is not valid base64") from exc
    if len(priv) != 32:
        raise StateUnavailable("TOKEN_SIGNING_SEED_B64 must decode to 32 bytes")
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    pub = (
        Ed25519PrivateKey.from_private_bytes(priv)
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )
    return pub, priv


@dataclass(frozen=True)
class ActorContext:
    """Authenticated caller identity derived strictly from verified token/signature."""

    user_id: str
    device_id: str
    token_jti: str


class TokenAuthority:
    """Issues and verifies short-lived Ed25519-signed bearer tokens."""

    def __init__(self, clock: Clock, ttl_seconds: int = 300) -> None:
        self.clock = clock
        self.ttl_seconds = ttl_seconds
        self._pub, self._priv = load_token_signing_keypair()

    def issue(self, user_id: str, device_id: str) -> str:
        """Issue a signed bearer token containing user_id, device_id, exp, and jti."""
        now = self.clock.now()
        claims = {
            "user_id": user_id,
            "device_id": device_id,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=self.ttl_seconds)).timestamp()),
            "jti": str(uuid.uuid4()),
        }
        payload_b = canonical_json_bytes(claims)
        sig_b = ed25519_sign(self._priv, payload_b)
        return f"{b64e(payload_b)}.{b64e(sig_b)}"

    def verify(self, token: str, *, max_clock_skew_seconds: int = 30) -> ActorContext:
        """Verify token signature, iat skew, and expiry; raise NotAuthorized on any failure."""
        try:
            parts = token.split(".")
            if len(parts) != 2:
                raise NotAuthorized("Malformed bearer token", reason_code="INVALID_TOKEN")
            payload_b = b64d(parts[0])
            sig_b = b64d(parts[1])
            if not ed25519_verify(self._pub, payload_b, sig_b):
                raise NotAuthorized("Invalid token signature", reason_code="INVALID_TOKEN")
            claims = json.loads(payload_b.decode("utf-8"))
            now_ts = int(self.clock.now().timestamp())
            exp_ts = int(claims["exp"])
            iat_ts = int(claims["iat"])
            if iat_ts > now_ts + max_clock_skew_seconds or iat_ts > exp_ts:
                raise NotAuthorized("Bearer token issued in the future", reason_code="TOKEN_IAT_INVALID")
            if now_ts >= exp_ts:
                raise NotAuthorized("Bearer token expired", reason_code="TOKEN_EXPIRED")
            return ActorContext(
                user_id=str(claims["user_id"]),
                device_id=str(claims["device_id"]),
                token_jti=str(claims["jti"]),
            )
        except NotAuthorized:
            raise
        except Exception as exc:
            raise NotAuthorized("Token verification failed", reason_code="INVALID_TOKEN") from exc
