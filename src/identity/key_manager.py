"""Atomic Key Rotation, Grace Period, and Cutoff Enforcement."""

from __future__ import annotations
import base64
import enum
import json
import os
import secrets
import time
from typing import Dict, Any, Optional, List, Tuple


class KeyStateEnum(str, enum.Enum):
    ACTIVE = "ACTIVE"
    GRACE_PERIOD = "GRACE_PERIOD"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"


class KeyRecord:
    def __init__(
        self,
        key_id: str,
        owner_node_id: str,
        algorithm: str,
        public_key_b64: str,
        private_key_b64: str,
        state: KeyStateEnum = KeyStateEnum.ACTIVE,
        created_at: float = 0.0,
        activated_at: float = 0.0,
        grace_period_cutoff: float = 0.0,
        expires_at: float = 0.0,
        revocation_reason: Optional[str] = None,
        version: int = 1,
    ):
        self.key_id = key_id
        self.owner_node_id = owner_node_id
        self.algorithm = algorithm
        self.public_key_b64 = public_key_b64
        self.private_key_b64 = private_key_b64
        self.state = state
        self.created_at = created_at or time.time()
        self.activated_at = activated_at or time.time()
        self.grace_period_cutoff = grace_period_cutoff
        self.expires_at = expires_at
        self.revocation_reason = revocation_reason
        self.version = version

    def to_dict(self, include_private: bool = False) -> Dict[str, Any]:
        data: Dict[str, Any] = {
            "key_id": self.key_id,
            "owner_node_id": self.owner_node_id,
            "algorithm": self.algorithm,
            "public_key_b64": self.public_key_b64,
            "state": self.state.value if isinstance(self.state, KeyStateEnum) else str(self.state),
            "created_at": int(self.created_at),
            "activated_at": int(self.activated_at),
            "grace_period_cutoff": int(self.grace_period_cutoff),
            "expires_at": int(self.expires_at),
            "revocation_reason": self.revocation_reason,
            "version": self.version,
        }
        if include_private:
            data["private_key_b64"] = self.private_key_b64
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> KeyRecord:
        return cls(
            key_id=data["key_id"],
            owner_node_id=data["owner_node_id"],
            algorithm=data["algorithm"],
            public_key_b64=data["public_key_b64"],
            private_key_b64=data.get("private_key_b64", ""),
            state=KeyStateEnum(data["state"]),
            created_at=data["created_at"],
            activated_at=data.get("activated_at", 0),
            grace_period_cutoff=data.get("grace_period_cutoff", 0),
            expires_at=data.get("expires_at", 0),
            revocation_reason=data.get("revocation_reason"),
            version=data.get("version", 1),
        )


class KeyManager:
    """Manages atomic key rotation, grace period transition, and cutoff enforcement."""

    def __init__(
        self,
        node_id: str,
        grace_period_seconds: float = 30.0,
        default_key_ttl_seconds: float = 3600.0,
        wal_manager: Optional[Any] = None,
    ):
        self.node_id = node_id
        self.grace_period_seconds = grace_period_seconds
        self.default_key_ttl_seconds = default_key_ttl_seconds
        self.wal_manager = wal_manager
        self.keys: Dict[str, KeyRecord] = {}
        self.active_key_id: Optional[str] = None
        self.key_history: List[str] = []

    def enroll_initial_key(self, algorithm: str, public_key: bytes, private_key: bytes) -> KeyRecord:
        """Enrolls the initial node keypair (Version 1)."""
        key_id = f"key-{self.node_id[:8]}-{secrets.token_hex(4)}"
        now = time.time()
        record = KeyRecord(
            key_id=key_id,
            owner_node_id=self.node_id,
            algorithm=algorithm,
            public_key_b64=base64.b64encode(public_key).decode("ascii"),
            private_key_b64=base64.b64encode(private_key).decode("ascii"),
            state=KeyStateEnum.ACTIVE,
            created_at=now,
            activated_at=now,
            expires_at=now + self.default_key_ttl_seconds,
            version=1,
        )

        if self.wal_manager:
            self.wal_manager.append_entry("ENROLL_KEY", record.to_dict(include_private=True))

        self.keys[key_id] = record
        self.active_key_id = key_id
        self.key_history.append(key_id)
        return record

    def rotate_key(
        self,
        new_public_key: bytes,
        new_private_key: bytes,
        algorithm: Optional[str] = None,
    ) -> Tuple[KeyRecord, Optional[KeyRecord]]:
        """Atomically rotates active key.

        The current active key is transitioned to GRACE_PERIOD with cutoff = now + grace_period_seconds.
        The new key is activated immediately with version = old.version + 1.
        """
        now = time.time()
        old_record = self.keys.get(self.active_key_id) if self.active_key_id else None
        new_version = (old_record.version + 1) if old_record else 1
        algo = algorithm or (old_record.algorithm if old_record else "ML-KEM-768")

        new_key_id = f"key-{self.node_id[:8]}-{secrets.token_hex(4)}"
        new_record = KeyRecord(
            key_id=new_key_id,
            owner_node_id=self.node_id,
            algorithm=algo,
            public_key_b64=base64.b64encode(new_public_key).decode("ascii"),
            private_key_b64=base64.b64encode(new_private_key).decode("ascii"),
            state=KeyStateEnum.ACTIVE,
            created_at=now,
            activated_at=now,
            expires_at=now + self.default_key_ttl_seconds,
            version=new_version,
        )

        # Log atomic rotation intent in WAL before applying in memory
        if self.wal_manager:
            self.wal_manager.append_entry(
                "ROTATE_KEY_BEGIN",
                {
                    "old_key_id": old_record.key_id if old_record else None,
                    "new_key_record": new_record.to_dict(include_private=True),
                },
            )

        # Transition old key into GRACE_PERIOD
        if old_record and old_record.state == KeyStateEnum.ACTIVE:
            old_record.state = KeyStateEnum.GRACE_PERIOD
            old_record.grace_period_cutoff = now + self.grace_period_seconds

        self.keys[new_key_id] = new_record
        self.active_key_id = new_key_id
        self.key_history.append(new_key_id)

        if self.wal_manager:
            self.wal_manager.append_entry(
                "ROTATE_KEY_COMMIT",
                {"active_key_id": new_key_id, "retired_key_id": old_record.key_id if old_record else None},
            )

        return new_record, old_record

    def enforce_cutoffs(self) -> List[str]:
        """Scans all keys and enforces grace period cutoffs and TTL expiration.

        Keys whose grace period has expired are transitioned to EXPIRED and their private keys purged.
        Returns list of newly expired key IDs.
        """
        now = time.time()
        expired_ids = []
        for key_id, record in self.keys.items():
            if record.state == KeyStateEnum.GRACE_PERIOD:
                if now >= record.grace_period_cutoff:
                    record.state = KeyStateEnum.EXPIRED
                    record.private_key_b64 = ""  # Purge secret material
                    expired_ids.append(key_id)
            elif record.state == KeyStateEnum.ACTIVE:
                if record.expires_at > 0 and now >= record.expires_at:
                    record.state = KeyStateEnum.EXPIRED
                    record.private_key_b64 = ""
                    expired_ids.append(key_id)

        if expired_ids and self.wal_manager:
            self.wal_manager.append_entry("ENFORCE_CUTOFFS", {"expired_key_ids": expired_ids})

        return expired_ids

    def revoke_key(self, key_id: str, reason: str) -> bool:
        """Immediately revokes key, marking it REVOKED and purging secrets."""
        record = self.keys.get(key_id)
        if not record:
            return False

        record.state = KeyStateEnum.REVOKED
        record.revocation_reason = reason
        record.private_key_b64 = ""

        if self.active_key_id == key_id:
            self.active_key_id = None

        if self.wal_manager:
            self.wal_manager.append_entry("REVOKE_KEY", {"key_id": key_id, "reason": reason})

        return True

    def get_active_key(self) -> Optional[KeyRecord]:
        """Returns the currently active key if still valid."""
        self.enforce_cutoffs()
        if not self.active_key_id:
            return None
        rec = self.keys.get(self.active_key_id)
        if rec and rec.state == KeyStateEnum.ACTIVE:
            return rec
        return None

    def get_key_for_decryption(self, key_id: str) -> Optional[KeyRecord]:
        """Returns key for decapsulation/decryption if ACTIVE or within GRACE_PERIOD."""
        self.enforce_cutoffs()
        record = self.keys.get(key_id)
        if not record:
            return None
        if record.state in (KeyStateEnum.ACTIVE, KeyStateEnum.GRACE_PERIOD):
            return record
        return None
