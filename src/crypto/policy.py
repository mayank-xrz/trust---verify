"""File sharing and single-device policy enforcement.

Constraints enforced:
1. Maximum shared file size: 20 MiB (20 * 1024 * 1024 bytes).
2. Allowed media & document formats: standard default image, audio, video, and non-executable
   document formats, verified by both extension/MIME allowlist and magic-byte header checks.
3. Single active device per user: a user identity may have at most 1 active registered device
   at any time (`MAX_DEVICES_PER_USER = 1`).
"""

from __future__ import annotations
import hashlib
import json
import re
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, Optional, Set, Tuple
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

MAX_FILE_SIZE_BYTES = 20 * 1024 * 1024  # 20 MiB
MAX_DEVICES_PER_USER = 1

# Extension -> canonical MIME type(s) for all standard default media & document formats.
# Active/executable extensions (.exe, .dll, .sh, .bat, .js, .py, .svg, .html, etc.) are excluded.
DEFAULT_MEDIA_FORMATS: Dict[str, Set[str]] = {
    # Images
    ".jpg": {"image/jpeg"},
    ".jpeg": {"image/jpeg"},
    ".png": {"image/png"},
    ".gif": {"image/gif"},
    ".webp": {"image/webp"},
    ".bmp": {"image/bmp", "image/x-ms-bmp"},
    ".tif": {"image/tiff"},
    ".tiff": {"image/tiff"},
    ".heic": {"image/heic"},
    ".heif": {"image/heif"},
    ".ico": {"image/x-icon", "image/vnd.microsoft.icon"},
    # Audio
    ".mp3": {"audio/mpeg"},
    ".wav": {"audio/wav", "audio/x-wav"},
    ".ogg": {"audio/ogg", "application/ogg"},
    ".flac": {"audio/flac", "audio/x-flac"},
    ".aac": {"audio/aac"},
    ".m4a": {"audio/mp4", "audio/x-m4a"},
    ".opus": {"audio/opus", "audio/ogg"},
    # Video
    ".mp4": {"video/mp4"},
    ".mov": {"video/quicktime"},
    ".avi": {"video/x-msvideo"},
    ".mkv": {"video/x-matroska"},
    ".webm": {"video/webm", "audio/webm"},
    ".m4v": {"video/x-m4v", "video/mp4"},
    # Safe non-executable documents & text
    ".pdf": {"application/pdf"},
    ".txt": {"text/plain"},
    ".csv": {"text/csv", "text/plain"},
    ".json": {"application/json"},
    ".md": {"text/markdown", "text/plain"},
}

CANONICAL_MIME: Dict[str, str] = {
    ext: sorted(mimes)[0] for ext, mimes in DEFAULT_MEDIA_FORMATS.items()
}


class FilePolicyError(ValueError):
    """Base error for file sharing policy violations."""
    reason = "file_policy_violation"


class FileSizeLimitError(FilePolicyError):
    reason = "file_too_large"


class MediaFormatError(FilePolicyError):
    reason = "disallowed_media_format"


class DevicePolicyError(ValueError):
    """Base error for single-device policy violations."""
    reason = "device_policy_violation"


class DeviceLimitExceededError(DevicePolicyError):
    reason = "device_limit_exceeded"


class TimezoneMismatchError(DevicePolicyError):
    reason = "timezone_mismatch_threat"

    def __init__(self, message: str, threat_details: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(message)
        self.threat_details: Dict[str, Any] = threat_details or {}


_OFFSET_RE = re.compile(r"^(?:UTC|GMT)?([+-])(\d{2}):?(\d{2})$", re.IGNORECASE)


def normalize_timezone(tz: str) -> str:
    """Validate and canonicalize an IANA timezone name or fixed UTC offset."""
    if not isinstance(tz, str) or not tz.strip():
        raise TimezoneMismatchError(
            "Invalid or empty timezone",
            threat_details={"threat": "INVALID_TIMEZONE", "request_timezone": str(tz)},
        )
    raw = tz.strip()
    if raw.upper() in ("Z", "UTC", "GMT"):
        return "UTC"
    m = _OFFSET_RE.match(raw)
    if m:
        sign, hh, mm = m.group(1), int(m.group(2)), int(m.group(3))
        if hh > 14 or mm >= 60:
            raise TimezoneMismatchError(
                f"Invalid UTC offset timezone: {raw}",
                threat_details={"threat": "INVALID_TIMEZONE", "request_timezone": raw},
            )
        return f"UTC{sign}{hh:02d}:{mm:02d}"
    try:
        zi = ZoneInfo(raw)
        return zi.key
    except ZoneInfoNotFoundError as exc:
        raise TimezoneMismatchError(
            f"Unknown timezone: {raw}",
            threat_details={"threat": "INVALID_TIMEZONE", "request_timezone": raw},
        ) from exc


def _verify_magic_bytes(ext: str, data: bytes) -> bool:
    """Verify file header bytes match the declared default media format."""
    if ext == ".png":
        return data.startswith(b"\x89PNG\r\n\x1a\n")
    if ext in (".jpg", ".jpeg"):
        return data.startswith(b"\xff\xd8\xff")
    if ext == ".gif":
        return data.startswith((b"GIF87a", b"GIF89a"))
    if ext == ".webp":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP"
    if ext == ".bmp":
        return data.startswith(b"BM")
    if ext in (".tif", ".tiff"):
        return data.startswith((b"II*\x00", b"MM\x00*"))
    if ext == ".ico":
        return data.startswith(b"\x00\x00\x01\x00")
    if ext == ".pdf":
        return data.startswith(b"%PDF-")
    if ext == ".wav":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WAVE"
    if ext == ".avi":
        return len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"AVI "
    if ext in (".ogg", ".opus"):
        return data.startswith(b"OggS")
    if ext == ".flac":
        return data.startswith(b"fLaC")
    if ext == ".mp3":
        return data.startswith(b"ID3") or (len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xE0) == 0xE0)
    if ext == ".aac":
        return len(data) >= 2 and data[0] == 0xFF and (data[1] & 0xF0) == 0xF0
    if ext in (".mp4", ".mov", ".m4a", ".m4v", ".heic", ".heif"):
        return len(data) >= 12 and data[4:8] == b"ftyp"
    if ext in (".mkv", ".webm"):
        return data.startswith(b"\x1a\x45\xdf\xa3")
    if ext in (".txt", ".csv", ".json", ".md"):
        if b"\x00" in data or data.startswith((b"MZ", b"\x7fELF", b"\xca\xfe\xba\xbe")):
            return False
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            return False
        if ext == ".json":
            try:
                json.loads(text)
            except ValueError:
                return False
        return True
    return False


def validate_shared_file(
    filename: str,
    data: bytes,
    *,
    mime_type: Optional[str] = None,
    max_bytes: int = MAX_FILE_SIZE_BYTES,
) -> Dict[str, object]:
    """Validate filename, 20 MB size cap, default media format, and magic bytes."""
    if not isinstance(filename, str) or not filename or "\x00" in filename:
        raise MediaFormatError("Invalid filename")
    if "/" in filename or "\\" in filename or ".." in filename:
        raise MediaFormatError("Path traversal not allowed in shared filename")
    if not isinstance(data, (bytes, bytearray)):
        raise FilePolicyError("Shared file data must be bytes")
    raw = bytes(data)
    if len(raw) == 0:
        err = FilePolicyError("Shared file cannot be empty")
        err.reason = "empty_file"
        raise err
    if len(raw) > max_bytes:
        raise FileSizeLimitError(
            f"Shared file exceeds 20 MB limit ({len(raw)} bytes > {max_bytes} bytes)"
        )

    ext = Path(filename).suffix.lower()
    if ext not in DEFAULT_MEDIA_FORMATS:
        raise MediaFormatError(f"Unsupported or disallowed file format: '{ext or '<none>'}'")

    allowed_mimes = DEFAULT_MEDIA_FORMATS[ext]
    if mime_type is not None:
        normalized_mime = mime_type.split(";", 1)[0].strip().lower()
        if normalized_mime not in allowed_mimes:
            raise MediaFormatError(
                f"MIME type '{normalized_mime}' does not match extension '{ext}'"
            )
        resolved_mime = normalized_mime
    else:
        resolved_mime = CANONICAL_MIME[ext]

    if not _verify_magic_bytes(ext, raw):
        err = MediaFormatError(f"File signature does not match declared format '{ext}'")
        err.reason = "magic_bytes_mismatch"
        raise err

    return {
        "filename": filename,
        "extension": ext,
        "mime_type": resolved_mime,
        "size": len(raw),
        "sha256": hashlib.sha256(raw).hexdigest(),
    }


class SingleDeviceRegistry:
    """Persistent SQLite registry enforcing strictly 1 active device per user."""

    def __init__(self, db_path: str | Path, max_devices_per_user: int = MAX_DEVICES_PER_USER) -> None:
        if max_devices_per_user != 1:
            raise ValueError("Policy mandates strictly 1 device per user")
        self.db_path = Path(db_path)
        self.max_devices_per_user = max_devices_per_user
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS user_devices (
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('active', 'revoked')),
                    PRIMARY KEY (user_id, device_id)
                )
                """
            )
            db.execute(
                """
                CREATE UNIQUE INDEX IF NOT EXISTS ix_one_active_device_per_user
                ON user_devices(user_id)
                WHERE status = 'active'
                """
            )
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS user_login_state (
                    user_id TEXT PRIMARY KEY,
                    last_device_id TEXT NOT NULL,
                    last_timezone TEXT NOT NULL,
                    last_login_ts REAL NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=5.0)
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def active_device(self, user_id: str) -> Optional[str]:
        with self._connect() as db:
            row = db.execute(
                "SELECT device_id FROM user_devices WHERE user_id=? AND status='active'",
                (user_id,),
            ).fetchone()
            return str(row[0]) if row is not None else None

    def register_device(self, user_id: str, device_id: str) -> None:
        if not user_id or not device_id:
            raise DevicePolicyError("user_id and device_id must be non-empty")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT status FROM user_devices WHERE user_id=? AND device_id=?",
                (user_id, device_id),
            ).fetchone()
            if existing is not None:
                if existing[0] == "revoked":
                    err = DevicePolicyError(f"Device {device_id} for user {user_id} is revoked")
                    err.reason = "device_revoked"
                    raise err
                return

            active = db.execute(
                "SELECT device_id FROM user_devices WHERE user_id=? AND status='active'",
                (user_id,),
            ).fetchone()
            if active is not None and active[0] != device_id:
                raise DeviceLimitExceededError(
                    f"User '{user_id}' already has active device '{active[0]}'; maximum 1 device allowed"
                )
            db.execute(
                "INSERT INTO user_devices (user_id, device_id, status) VALUES (?, ?, 'active')",
                (user_id, device_id),
            )

    def verify_device(self, user_id: str, device_id: str) -> None:
        """Fail closed if user has another active device or this device is revoked."""
        with self._connect() as db:
            row = db.execute(
                "SELECT status FROM user_devices WHERE user_id=? AND device_id=?",
                (user_id, device_id),
            ).fetchone()
            if row is not None and row[0] == "revoked":
                err = DevicePolicyError(f"Device {device_id} for user {user_id} is revoked")
                err.reason = "device_revoked"
                raise err
            active = db.execute(
                "SELECT device_id FROM user_devices WHERE user_id=? AND status='active'",
                (user_id,),
            ).fetchone()
            if active is not None and active[0] != device_id:
                raise DeviceLimitExceededError(
                    f"User '{user_id}' bound to device '{active[0]}', rejected '{device_id}'"
                )

    def revoke_device(self, user_id: str, device_id: str) -> None:
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO user_devices (user_id, device_id, status)
                VALUES (?, ?, 'revoked')
                ON CONFLICT(user_id, device_id) DO UPDATE SET status='revoked'
                """,
                (user_id, device_id),
            )

    def replace_device(self, user_id: str, old_device_id: str, new_device_id: str) -> None:
        """Atomically revoke old_device_id and activate new_device_id (strictly <= 1 active)."""
        if not old_device_id or not new_device_id or old_device_id == new_device_id:
            raise DevicePolicyError("old_device_id and new_device_id must be distinct non-empty IDs")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            existing_new = db.execute(
                "SELECT status FROM user_devices WHERE user_id=? AND device_id=?",
                (user_id, new_device_id),
            ).fetchone()
            if existing_new is not None and existing_new[0] == "revoked":
                err = DevicePolicyError(f"Device {new_device_id} was previously revoked")
                err.reason = "device_revoked"
                raise err
            db.execute(
                "UPDATE user_devices SET status='revoked' WHERE user_id=? AND status='active'",
                (user_id,),
            )
            db.execute(
                """
                INSERT INTO user_devices (user_id, device_id, status)
                VALUES (?, ?, 'active')
                ON CONFLICT(user_id, device_id) DO UPDATE SET status='active'
                """,
                (user_id, new_device_id),
            )

    def verify_access_timezone(self, user_id: str, device_id: str, request_timezone: str) -> None:
        """Bind user/device to its last login timezone; reject cross-timezone anomalies."""
        self.verify_device(user_id, device_id)
        norm_tz = normalize_timezone(request_timezone)
        now = time.time()
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT last_device_id, last_timezone, last_login_ts FROM user_login_state WHERE user_id=?",
                (user_id,),
            ).fetchone()
            if row is None:
                db.execute(
                    """
                    INSERT INTO user_login_state (user_id, last_device_id, last_timezone, last_login_ts)
                    VALUES (?, ?, ?, ?)
                    """,
                    (user_id, device_id, norm_tz, now),
                )
                return

            last_device, last_tz, last_ts = row
            if norm_tz != last_tz or device_id != last_device:
                details: Dict[str, Any] = {
                    "threat": "ANOMALOUS_TIMEZONE_ACCESS",
                    "severity": "HIGH",
                    "user_id": user_id,
                    "last_device": str(last_device),
                    "current_device": device_id,
                    "last_timezone": str(last_tz),
                    "request_timezone": norm_tz,
                    "last_login_ts": float(last_ts),
                    "detail": (
                        f"Access rejected for '{user_id}': device/timezone differs from last login "
                        f"(last='{last_device}' @ '{last_tz}', current='{device_id}' @ '{norm_tz}') "
                        "and can cause session hijack or distributed clock/auth fault."
                    ),
                }
                raise TimezoneMismatchError(details["detail"], threat_details=details)

            db.execute(
                "UPDATE user_login_state SET last_login_ts=? WHERE user_id=?",
                (now, user_id),
            )

    def reset_login_timezone(self, user_id: str, new_timezone: str, device_id: Optional[str] = None) -> None:
        """Explicit administrative update of a user's baseline login timezone (e.g., approved travel)."""
        norm_tz = normalize_timezone(new_timezone)
        target_dev = device_id or self.active_device(user_id)
        if not target_dev:
            raise DevicePolicyError(f"No active device for user '{user_id}'")
        with self._connect() as db:
            db.execute("BEGIN IMMEDIATE")
            db.execute(
                """
                INSERT INTO user_login_state (user_id, last_device_id, last_timezone, last_login_ts)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id) DO UPDATE SET
                    last_device_id=excluded.last_device_id,
                    last_timezone=excluded.last_timezone,
                    last_login_ts=excluded.last_login_ts
                """,
                (user_id, target_dev, norm_tz, time.time()),
            )
