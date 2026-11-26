"""Deterministic sandbox seeder for users, devices, roles, permissions, and resources."""

from __future__ import annotations

import argparse
import hashlib
import uuid
from datetime import datetime, timezone

from sqlalchemy.orm import Session, sessionmaker

from src.identity_keys.clock import SystemClock
from src.identity_keys.crypto import generate_ed25519_keypair, public_key_fingerprint
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.models import (
    Device,
    Enrollment,
    Permission,
    Resource,
    Role,
    RolePermission,
    User,
    UserRole,
)


def _det_uuid(seed: int, tag: str) -> str:
    digest = hashlib.sha256(f"{seed}:{tag}".encode("utf-8")).digest()
    return str(uuid.UUID(bytes=digest[:16], version=4))


def seed_database(session_factory: sessionmaker[Session], seed: int = 42) -> dict[str, str]:
    """Seed deterministic synthetic users, roles, permissions, devices, and resources."""
    now = SystemClock().now().astimezone(timezone.utc)
    perm_names = [
        "resource:read",
        "resource:write",
        "resource:share",
        "key:rotate",
        "device:revoke",
        "device:approve_reenroll",
        "backup:create",
        "backup:restore",
    ]
    with tx_session(session_factory) as session:
        perms: dict[str, str] = {}
        for name in perm_names:
            pid = _det_uuid(seed, f"perm:{name}")
            perms[name] = pid
            if not session.get(Permission, pid):
                session.add(Permission(permission_id=pid, name=name))

        roles_spec = {
            "viewer": ["resource:read"],
            "editor": ["resource:read", "resource:write", "resource:share"],
            "admin": perm_names,
        }
        roles: dict[str, str] = {}
        for rname, rperms in roles_spec.items():
            rid = _det_uuid(seed, f"role:{rname}")
            roles[rname] = rid
            if not session.get(Role, rid):
                session.add(Role(role_id=rid, name=rname))
                for p in rperms:
                    session.add(RolePermission(role_id=rid, permission_id=perms[p]))

        users_spec = [("alice", "editor"), ("bob", "viewer"), ("carol", "admin")]
        user_ids: dict[str, str] = {}
        for handle, rname in users_spec:
            uid = _det_uuid(seed, f"user:{handle}")
            user_ids[handle] = uid
            if not session.get(User, uid):
                session.add(User(user_id=uid, handle=handle, status="active", created_at=now))
                session.flush()
                session.add(UserRole(user_id=uid, role_id=roles[rname]))

                eid = _det_uuid(seed, f"enroll:{handle}")
                did = _det_uuid(seed, f"device:{handle}")
                pub, _ = generate_ed25519_keypair()
                session.add(
                    Enrollment(
                        enrollment_id=eid,
                        user_id=uid,
                        device_id=did,
                        kind="first",
                        status="completed",
                        nonce=hashlib.sha256(f"{seed}:{handle}:nonce".encode()).hexdigest(),
                        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
                        created_at=now,
                        completed_at=now,
                    )
                )
                session.flush()
                session.add(
                    Device(
                        device_id=did,
                        user_id=uid,
                        label=f"{handle}-laptop",
                        status="enrolled",
                        public_key=pub,
                        public_key_alg="Ed25519",
                        public_key_fingerprint=public_key_fingerprint(pub),
                        enrolled_at=now,
                        enrollment_id=eid,
                    )
                )

        res_id = "brief-alpha"
        if not session.get(Resource, res_id):
            session.add(
                Resource(
                    resource_id=res_id,
                    owner_user_id=user_ids["alice"],
                    kind="document",
                    created_at=now,
                )
            )
    return user_ids


def main() -> None:
    parser = argparse.ArgumentParser(description="Seed synthetic Track 4 sandbox data.")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--database-url", default=None)
    args = parser.parse_args()
    engine = create_db_engine(args.database_url)
    sf = create_session_factory(engine)
    seeded = seed_database(sf, seed=args.seed)
    print(f"Seeded sandbox users: {seeded}")


if __name__ == "__main__":
    main()
