"""Domain exception hierarchy for identity_keys (fail-closed)."""

from __future__ import annotations


class IdentityKeysError(Exception):
    """Base error for identity, key lifecycle, and storage operations."""

    reason_code: str = "IDENTITY_KEYS_ERROR"

    def __init__(self, message: str, reason_code: str | None = None) -> None:
        super().__init__(message)
        if reason_code is not None:
            self.reason_code = reason_code


class NotAuthorized(IdentityKeysError):
    reason_code = "NOT_AUTHORIZED"


class IllegalTransition(IdentityKeysError):
    reason_code = "ILLEGAL_TRANSITION"


class Revoked(IdentityKeysError):
    reason_code = "REVOKED"


class StateUnavailable(IdentityKeysError):
    reason_code = "STATE_UNAVAILABLE"


class IntegrityError(IdentityKeysError):
    reason_code = "INTEGRITY_ERROR"


class NotFound(IdentityKeysError):
    reason_code = "NOT_FOUND"


class Conflict(IdentityKeysError):
    reason_code = "CONFLICT"
