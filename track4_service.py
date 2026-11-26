"""Track 4 Adapter Contract v1 entrypoint backed by identity_keys + SQLAlchemy."""

from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from alembic import command
from alembic.config import Config
from src.identity_keys.audit_outbox import AuditEmitter
from src.identity_keys.clock import SystemClock
from src.identity_keys.crypto import (
    b64d,
    b64e,
    generate_ed25519_keypair,
    hmac_sha256_hex,
    ml_kem_768_encaps,
    public_key_fingerprint,
)
from src.identity_keys.db import create_db_engine, create_session_factory, tx_session
from src.identity_keys.models import (
    AuditOutbox,
    Device,
    Enrollment,
    Permission,
    Resource,
    Revocation,
    Role,
    RolePermission,
    User,
    UserRole,
)
from src.identity_keys.services import AuthzService, transition_device_status
from src.identity_keys.tokens import ActorContext

REPO_ROOT = Path(__file__).resolve().parent


def _state_dir() -> Path:
    base = os.environ.get("TRACK4_STATE_DIR") or tempfile.gettempdir()
    p = Path(base) / "tbv_adapter_state"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _db_url() -> str:
    return f"sqlite+pysqlite:///{_state_dir() / 'adapter.db'}"


def _alembic_cfg(url: str) -> Config:
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def _det_uuid(tag: str) -> str:
    return str(uuid.UUID(bytes=hashlib.sha256(tag.encode("utf-8")).digest()[:16], version=4))


def dispatch(request: dict[str, Any]) -> dict[str, Any]:
    op = request.get("op")
    url = _db_url()
    clock = SystemClock()
    now = clock.now()

    if op == "setup":
        db_file = _state_dir() / "adapter.db"
        if db_file.exists():
            db_file.unlink()
        command.upgrade(_alembic_cfg(url), "head")
        engine = create_db_engine(url)
        sf = create_session_factory(engine)
        owners: dict[str, str] = request["owners"]
        contents: dict[str, str] = request["contents"]
        disabled: set[str] = set(request.get("disabled", []))
        # key_material is never logged or returned
        _seed_digest = hashlib.sha256(
            str(request.get("key_material", "")).encode("utf-8")
        ).hexdigest()

        with tx_session(sf) as session:
            perm_id = _det_uuid("perm:resource:read")
            role_id = _det_uuid("role:owner")
            session.add(Permission(permission_id=perm_id, name="resource:read"))
            session.add(Role(role_id=role_id, name="owner"))
            session.flush()
            session.add(RolePermission(role_id=role_id, permission_id=perm_id))

            actors = sorted(set(owners.values()) | disabled)
            for actor in actors:
                status = "disabled" if actor in disabled else "active"
                session.add(User(user_id=actor, handle=actor, status=status, created_at=now))
                session.flush()
                session.add(UserRole(user_id=actor, role_id=role_id))
                eid = _det_uuid(f"enroll:{actor}")
                did = _det_uuid(f"device:{actor}")
                pub, _ = generate_ed25519_keypair()
                session.add(
                    Enrollment(
                        enrollment_id=eid,
                        user_id=actor,
                        device_id=did,
                        kind="first",
                        status="completed",
                        nonce=hashlib.sha256(f"nonce:{actor}".encode()).hexdigest(),
                        expires_at=datetime(2030, 1, 1, tzinfo=timezone.utc),
                        created_at=now,
                        completed_at=now,
                    )
                )
                session.flush()
                dev = Device(
                    device_id=did,
                    user_id=actor,
                    label=f"{actor}-primary",
                    status="enrolled" if status == "active" else "revoked",
                    public_key=pub,
                    public_key_alg="Ed25519",
                    public_key_fingerprint=public_key_fingerprint(pub),
                    enrolled_at=now if status == "active" else None,
                    revoked_at=now if status == "disabled" else None,
                    revoked_reason="initial_disabled" if status == "disabled" else None,
                    enrollment_id=eid,
                )
                session.add(dev)

            for asset_id, owner_id in owners.items():
                body = contents[asset_id]
                session.add(
                    Resource(
                        resource_id=asset_id,
                        owner_user_id=owner_id,
                        kind="synthetic",
                        created_at=now,
                        content_ciphertext=body.encode("utf-8"),
                    )
                )
            AuditEmitter("node-a", clock).emit(
                session,
                actor_id="system",
                device_id=None,
                action="setup",
                target="cluster",
                outcome="allow",
                reason_code="READY",
                metadata={"seed_digest": _seed_digest},
            )
        return {"ready": True}

    engine = create_db_engine(url)
    sf = create_session_factory(engine)
    emitter = AuditEmitter("node-a", clock)

    if op == "revoke":
        actor = request["actor"]
        with tx_session(sf) as session:
            user = session.get(User, actor)
            if user:
                user.status = "disabled"
            devs = session.execute(select(Device).where(Device.user_id == actor)).scalars().all()
            for dev in devs:
                if dev.status != "revoked":
                    transition_device_status(dev, "revoked", now, "device_loss")
                    session.add(
                        Revocation(
                            revocation_id=str(uuid.uuid4()),
                            target_type="device",
                            target_id=dev.device_id,
                            user_id=actor,
                            revoked_by_actor="operator",
                            reason_code="DEVICE_LOSS",
                            committed_at=now,
                        )
                    )
            emitter.emit(
                session,
                actor_id=actor,
                device_id=None,
                action="revoke",
                target=actor,
                outcome="allow",
                reason_code="REVOKED",
            )
        return {}

    if op in ("read", "protected_read"):
        actor = request["actor"]
        asset = request["asset"]
        req_id = request.get("request_id") or str(uuid.uuid4())
        did = _det_uuid(f"device:{actor}")
        ctx = ActorContext(user_id=actor, device_id=did, token_jti=req_id)
        authz = AuthzService(sf, clock, emitter, node_id="node-a")
        dec = authz.authorize(ctx, asset, "resource:read", correlation_id=req_id)
        if not dec.allowed:
            return {"decision": "deny"}

        with tx_session(sf) as session:
            res = session.get(Resource, asset)
            body = res.content_ciphertext.decode("utf-8") if res and res.content_ciphertext else ""

        if op == "read":
            return {"decision": "allow", "body": body}

        client_pk = b64d(request["public_key"])
        ct, ss = ml_kem_768_encaps(client_pk)
        proof = hmac_sha256_hex(ss, (request["challenge"] + body).encode("utf-8"))
        return {"decision": "allow", "ciphertext": b64e(ct), "proof": proof}

    if op == "audit":
        req_id = request["request_id"]
        with tx_session(sf) as session:
            rows = session.execute(select(AuditOutbox)).scalars().all()
            for row in rows:
                if row.payload.get("correlation_id") == req_id:
                    return {"request_id": req_id, "decision": row.payload["outcome"]}
        return {"request_id": req_id, "decision": "deny"}

    return {"error": "unsupported_operation"}


def main() -> int:
    try:
        request = json.load(sys.stdin)
        if not isinstance(request, dict):
            raise ValueError("Request must be an object")
        response = dispatch(request)
        encoded = json.dumps(response, allow_nan=False)
    except Exception:
        print("Request failed; inspect team application locally.", file=sys.stderr)
        return 1
    sys.stdout.write(encoded + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
