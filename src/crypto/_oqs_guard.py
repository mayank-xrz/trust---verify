"""Safe native liboqs discovery to avoid runtime source builds on minimal hosts."""

from __future__ import annotations
import ctypes.util
import os
from typing import Any, Tuple


def has_native_liboqs() -> bool:
    """Return True when the native liboqs shared library is already installed."""
    install_path = os.environ.get("OQS_INSTALL_PATH")
    candidates = [
        os.path.join(install_path, "lib", "liboqs.so") if install_path else "",
        os.path.join(install_path, "lib", "liboqs.dylib") if install_path else "",
        "/usr/local/lib/liboqs.so",
        "/usr/local/lib/liboqs.dylib",
        "/usr/lib/liboqs.so",
    ]
    if any(p and os.path.exists(p) for p in candidates):
        return True
    return bool(ctypes.util.find_library("oqs") or ctypes.util.find_library("liboqs"))


def load_oqs_if_available() -> Tuple[Any, bool]:
    """Import oqs only if native liboqs exists, avoiding auto-install SystemExit."""
    if not has_native_liboqs():
        return None, False
    try:
        import oqs
        return oqs, True
    except BaseException:
        return None, False
