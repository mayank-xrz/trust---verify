"""Track 4 cryptographic building blocks. Protocol version 1 & v2-paranoid agility."""
from .policy import (
    DEFAULT_MEDIA_FORMATS,
    MAX_DEVICES_PER_USER,
    MAX_FILE_SIZE_BYTES,
    DeviceLimitExceededError,
    DevicePolicyError,
    FilePolicyError,
    FileSizeLimitError,
    MediaFormatError,
    SingleDeviceRegistry,
    TimezoneMismatchError,
    normalize_timezone,
    validate_shared_file,
)


def __getattr__(name):
    # The organizer adapter imports submodules without the full crypto system.
    if name == "SecureCryptoSystem":
        from .system import SecureCryptoSystem

        return SecureCryptoSystem
    if name in {"SUITE_V1", "SUITE_V2_PARANOID", "DualIdentityKeypair", "ParanoidHandshakeSession"}:
        from . import agility

        return getattr(agility, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "DualIdentityKeypair",
    "ParanoidHandshakeSession",
    "SUITE_V1",
    "SUITE_V2_PARANOID",
    "SecureCryptoSystem",
    "MAX_FILE_SIZE_BYTES",
    "MAX_DEVICES_PER_USER",
    "DEFAULT_MEDIA_FORMATS",
    "FilePolicyError",
    "FileSizeLimitError",
    "MediaFormatError",
    "DevicePolicyError",
    "DeviceLimitExceededError",
    "TimezoneMismatchError",
    "SingleDeviceRegistry",
    "normalize_timezone",
    "validate_shared_file",
]
