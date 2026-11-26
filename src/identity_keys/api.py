"""Thin FastAPI application for Person B multi-node identity & authorization service."""

from __future__ import annotations

import os
from contextlib import asynccontextmanager
from dataclasses import dataclass
from hmac import compare_digest
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit_outbox import AuditEmitter
from .clock import Clock, SystemClock
from .db import create_db_engine, create_session_factory
from .errors import IdentityKeysError, NotAuthorized
from .key_lifecycle import EnvelopeEncryptionService
from .reenroll import ReenrollmentService
from .revocation import NodeSyncManager, RevocationService
from .rotation import RotationService, arm_crash_point, verify_cluster_sync
from .services import AuthzService, IdentityService, KeyMetadataService
from .tokens import ActorContext, TokenAuthority


class EnrollRequest(BaseModel):
    enrollment_id: str
    nonce: str
    label: str
    public_key_b64: str
    proof_of_possession_b64: str
    public_key_alg: str = "Ed25519"


class VerifyIdentityRequest(BaseModel):
    device_id: str
    challenge: str
    signature_b64: str


class AuthorizeRequest(BaseModel):
    resource_id: str
    permission: str
    key_version_id: str | None = None
    # Optional ignored fields to prove actor spoofing in body is never trusted
    actor_id: str | None = None
    label: str | None = None


class InitiateRotationRequest(BaseModel):
    key_set_id: str
    grace_seconds: int = 30
    idempotency_key: str


class SyncNotificationRequest(BaseModel):
    payload: dict[str, Any]
    hmac: str


class ArmCrashRequest(BaseModel):
    crash_point: str | None = None


class RevokeDeviceRequest(BaseModel):
    device_id: str
    reason_code: str = "DEVICE_LOST"


class RevokeKeyVersionRequest(BaseModel):
    key_version_id: str
    reason_code: str = "KEY_COMPROMISED"


class RevokePermissionRequest(BaseModel):
    user_id: str
    grant_id_or_perm: str
    reason_code: str = "POLICY_VIOLATION"


class EmergencyRotateRequest(BaseModel):
    key_set_id: str
    idempotency_key: str


class ReenrollBeginRequest(BaseModel):
    user_id: str


class ReenrollCompleteRequest(BaseModel):
    enrollment_id: str
    nonce: str
    label: str
    new_public_key_b64: str
    pop_signature_b64: str
    old_device_ids: list[str] | None = None
    recovery_code: str | None = None
    admin_approval: dict[str, Any] | None = None


class AdminApprovalRequest(BaseModel):
    user_id: str
    new_pk_fingerprint: str
    enrollment_id: str
    ttl_seconds: int = 600


@dataclass(frozen=True)
class EnrollmentCaller:
    """Authenticated actor allowed to drive an enrollment."""

    actor_id: str
    is_admin: bool


def _admin_enroll_token_valid(provided: str | None) -> bool:
    """Constant-time admin enrollment token check; fails closed when env is unset."""
    expected = os.environ.get("ADMIN_ENROLL_TOKEN", "").strip()
    if not expected or not provided:
        return False
    return compare_digest(provided.strip(), expected)


def create_app(
    *,
    node_id: str | None = None,
    database_url: str | None = None,
    clock: Clock | None = None,
) -> FastAPI:
    """Create a FastAPI node instance backed by the authoritative DB."""
    resolved_node: str = node_id or os.environ.get("NODE_ID") or "node-a"
    resolved_clock = clock or SystemClock()
    engine = create_db_engine(database_url)
    session_factory = create_session_factory(engine)
    emitter = AuditEmitter(node_id=resolved_node, clock=resolved_clock)
    token_auth = TokenAuthority(clock=resolved_clock)

    identity_svc = IdentityService(session_factory, resolved_clock, emitter, token_auth)
    authz_svc = AuthzService(
        session_factory,
        resolved_clock,
        emitter,
        node_id=resolved_node,
        max_cache_staleness_ms=int(os.environ.get("MAX_CACHE_STALENESS_MS", "500")),
    )
    metadata_svc = KeyMetadataService(session_factory)
    rotation_svc = RotationService(session_factory, resolved_clock, emitter, node_id=resolved_node)
    envelope_svc = EnvelopeEncryptionService(session_factory, resolved_clock, emitter)
    revocation_svc = RevocationService(
        session_factory, resolved_clock, emitter, node_id=resolved_node
    )
    sync_mgr = NodeSyncManager(
        session_factory,
        resolved_clock,
        node_id=resolved_node,
        stale_after_ms=int(os.environ.get("STALE_AFTER_MS", "2000")),
        heartbeat_interval_ms=int(os.environ.get("HEARTBEAT_INTERVAL_MS", "0")),
        audit_emitter=emitter,
    )
    reenroll_svc = ReenrollmentService(session_factory, resolved_clock, emitter)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        sync_mgr.start_heartbeat()
        try:
            yield
        finally:
            sync_mgr.stop_heartbeat()

    app = FastAPI(title=f"Trust-But-Verify Identity Node ({resolved_node})", lifespan=lifespan)
    app.state.engine = engine
    app.state.token_authority = token_auth
    app.state.identity_svc = identity_svc
    app.state.authz_svc = authz_svc
    app.state.rotation_svc = rotation_svc
    app.state.envelope_svc = envelope_svc
    app.state.revocation_svc = revocation_svc
    app.state.sync_mgr = sync_mgr
    app.state.reenroll_svc = reenroll_svc

    def require_actor(authorization: str | None = Header(default=None)) -> ActorContext:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = authorization[len("Bearer ") :].strip()
        try:
            return token_auth.verify(token)
        except NotAuthorized as exc:
            raise HTTPException(status_code=401, detail=exc.reason_code) from exc

    def authenticate_enrollment_caller(
        *,
        authorization: str | None,
        admin_enroll_token: str | None,
    ) -> EnrollmentCaller:
        """Authenticate the enrollment caller, fail closed.

        An explicitly supplied admin token is always validated, so a wrong/empty
        value is a 401 even if a bearer token is also present.  When
        ``ADMIN_ENROLL_TOKEN`` is unset the admin path is disabled entirely.
        """
        if admin_enroll_token is not None:
            if not _admin_enroll_token_valid(admin_enroll_token):
                raise HTTPException(status_code=401, detail="INVALID_ADMIN_ENROLL_TOKEN")
            return EnrollmentCaller(actor_id="admin-enroll-token", is_admin=True)
        if not authorization:
            raise HTTPException(status_code=401, detail="ENROLL_AUTH_REQUIRED")
        actor = require_actor(authorization)
        return EnrollmentCaller(actor_id=actor.user_id, is_admin=False)

    def assert_enrollment_target(caller: EnrollmentCaller, target_user_id: str) -> None:
        if not caller.is_admin and caller.actor_id != target_user_id:
            raise HTTPException(status_code=403, detail="ENROLL_USER_MISMATCH")

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        from sqlalchemy import text

        try:
            with session_factory() as session:
                session.execute(text("SELECT 1"))
        except Exception as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        return {"status": "ok", "node_id": resolved_node}

    @app.get("/node/status")
    def node_status() -> dict[str, Any]:
        return {
            "node_id": resolved_node,
            "status": "online",
            "timestamp": resolved_clock.now().isoformat(),
            "monotonic_ns": resolved_clock.monotonic_ns(),
        }

    @app.post("/api/v1/enroll/start")
    def start_enroll(
        user_id: str,
        kind: str = "first",
        authorization: str | None = Header(default=None),
        x_admin_enroll_token: str | None = Header(default=None),
    ) -> dict[str, str]:
        caller = authenticate_enrollment_caller(
            authorization=authorization,
            admin_enroll_token=x_admin_enroll_token,
        )
        assert_enrollment_target(caller, user_id)
        if kind not in ("first", "recovery", "re_enroll"):
            raise HTTPException(status_code=400, detail="INVALID_ENROLLMENT_KIND")
        if kind in ("recovery", "re_enroll") and not caller.is_admin:
            raise HTTPException(status_code=403, detail="RECOVERY_REQUIRES_ADMIN")
        # The persisted enum predates the API spelling; keep one canonical value.
        stored_kind = "re_enroll" if kind == "recovery" else kind
        try:
            return identity_svc.start_enrollment(
                user_id=user_id,
                kind=stored_kind,
                initiated_by=caller.actor_id,
                initiated_by_admin=caller.is_admin,
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=400, detail=exc.reason_code) from exc

    @app.post("/api/v1/enroll")
    def enroll(
        req: EnrollRequest,
        authorization: str | None = Header(default=None),
        x_admin_enroll_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        caller = authenticate_enrollment_caller(
            authorization=authorization,
            admin_enroll_token=x_admin_enroll_token,
        )
        try:
            target_user_id, enrollment_kind = identity_svc.get_enrollment_target(
                req.enrollment_id
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=404, detail=exc.reason_code) from exc
        assert_enrollment_target(caller, target_user_id)
        if enrollment_kind in ("recovery", "re_enroll") and not caller.is_admin:
            raise HTTPException(status_code=403, detail="RECOVERY_REQUIRES_ADMIN")
        try:
            return identity_svc.enroll_device(
                enrollment_id=req.enrollment_id,
                nonce=req.nonce,
                label=req.label,
                public_key_b64=req.public_key_b64,
                proof_of_possession_b64=req.proof_of_possession_b64,
                public_key_alg=req.public_key_alg,
                initiated_by=caller.actor_id,
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/api/v1/auth/challenge")
    def auth_challenge(device_id: str) -> dict[str, str]:
        try:
            return identity_svc.issue_challenge(device_id=device_id)
        except IdentityKeysError as exc:
            raise HTTPException(status_code=404, detail=exc.reason_code) from exc

    @app.post("/api/v1/auth/verify")
    def verify_identity(req: VerifyIdentityRequest) -> dict[str, Any]:
        try:
            return identity_svc.verify_identity(
                device_id=req.device_id,
                challenge=req.challenge,
                signature_b64=req.signature_b64,
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=401, detail=exc.reason_code) from exc

    @app.post("/api/v1/authorize")
    def authorize(
        req: AuthorizeRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        if sync_mgr.last_sync_at is None:
            sync_mgr.pull_revocations()
        if sync_mgr.is_stale():
            return {
                "allowed": False,
                "reason_code": "STALE_STATE",
                "key_version_id": req.key_version_id,
                "decision_id": "stale-deny",
                "node_id": resolved_node,
            }
        decision = authz_svc.authorize(
            actor, req.resource_id, req.permission, key_version_id=req.key_version_id
        )
        return {
            "allowed": decision.allowed,
            "reason_code": decision.reason_code,
            "key_version_id": decision.key_version_id,
            "decision_id": decision.decision_id,
            "node_id": resolved_node,
        }

    @app.get("/node/sync-status")
    def node_sync_status() -> dict[str, Any]:
        return sync_mgr.sync_status()

    @app.post("/revocations/device")
    def api_revoke_device(
        req: RevokeDeviceRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            return revocation_svc.revoke_device(actor, req.device_id, req.reason_code)
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/revocations/key-version")
    def api_revoke_key_version(
        req: RevokeKeyVersionRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            return revocation_svc.revoke_key_version(actor, req.key_version_id, req.reason_code)
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/revocations/permission")
    def api_revoke_permission(
        req: RevokePermissionRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            return revocation_svc.revoke_permission(
                actor, req.user_id, req.grant_id_or_perm, req.reason_code
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/rotations/emergency")
    def api_emergency_rotate(
        req: EmergencyRotateRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            return revocation_svc.emergency_rotate(
                key_set_id=req.key_set_id,
                idempotency_key=req.idempotency_key,
                actor_ctx=actor,
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/reenroll/recovery-codes")
    def api_generate_codes(actor: ActorContext = Depends(require_actor)) -> dict[str, Any]:
        return {"codes": reenroll_svc.generate_recovery_codes(actor.user_id)}

    @app.post("/reenroll/approve")
    def api_approve_reenroll(
        req: AdminApprovalRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            return reenroll_svc.create_admin_approval(
                actor,
                user_id=req.user_id,
                new_pk_fingerprint=req.new_pk_fingerprint,
                enrollment_id=req.enrollment_id,
                ttl_seconds=req.ttl_seconds,
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/reenroll/begin")
    def api_reenroll_begin(req: ReenrollBeginRequest) -> dict[str, str]:
        try:
            return reenroll_svc.begin_reenrollment(req.user_id)
        except IdentityKeysError as exc:
            raise HTTPException(status_code=400, detail=exc.reason_code) from exc

    @app.post("/reenroll/complete")
    def api_reenroll_complete(req: ReenrollCompleteRequest) -> dict[str, Any]:
        try:
            return reenroll_svc.complete_reenrollment(
                enrollment_id=req.enrollment_id,
                nonce=req.nonce,
                label=req.label,
                new_public_key_b64=req.new_public_key_b64,
                pop_signature_b64=req.pop_signature_b64,
                old_device_ids=req.old_device_ids,
                recovery_code=req.recovery_code,
                admin_approval=req.admin_approval,
            )
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/rotations")
    def create_rotation(
        req: InitiateRotationRequest, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, str]:
        try:
            rot_id = rotation_svc.initiate_rotation(
                key_set_id=req.key_set_id,
                grace_seconds=req.grace_seconds,
                idempotency_key=req.idempotency_key,
                actor_ctx=actor,
            )
            return {"rotation_id": rot_id}
        except IdentityKeysError as exc:
            status = 409 if exc.reason_code in ("ROTATION_IN_FLIGHT", "VERSION_CONFLICT") else 403
            raise HTTPException(status_code=status, detail=exc.reason_code) from exc

    @app.get("/rotations/{rotation_id}")
    def get_rotation(
        rotation_id: str, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            with session_factory() as session:
                rotation_svc._require_rotate_permission(session, actor)
            return rotation_svc.get_rotation(rotation_id)
        except NotAuthorized as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc
        except IdentityKeysError as exc:
            raise HTTPException(status_code=404, detail=exc.reason_code) from exc

    @app.get("/keys/{key_set_id}/metadata")
    def get_key_set_meta(
        key_set_id: str, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            with session_factory() as session:
                rotation_svc._require_rotate_permission(session, actor)
            return rotation_svc.get_key_set_metadata(key_set_id)
        except NotAuthorized as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc
        except IdentityKeysError as exc:
            raise HTTPException(status_code=404, detail=exc.reason_code) from exc

    @app.post("/resources/{resource_id}/rewrap")
    def rewrap_resource(
        resource_id: str, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, str]:
        try:
            return envelope_svc.rewrap_resource(resource_id, actor)
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    @app.post("/internal/sync")
    def internal_sync(req: SyncNotificationRequest) -> dict[str, Any]:
        if not verify_cluster_sync(req.payload, req.hmac):
            raise HTTPException(status_code=401, detail="INVALID_CLUSTER_HMAC")
        # Never trust push payload as truth: re-read authoritative DB state
        watermark = sync_mgr.pull_revocations()
        ks_id = str(req.payload.get("key_set_id", ""))
        current_version = None
        if ks_id:
            meta = rotation_svc.get_key_set_metadata(ks_id)
            current_version = meta["current_version"]
        return {
            "synced": True,
            "node_id": resolved_node,
            "watermark": watermark,
            "current_version": current_version,
        }

    @app.post("/internal/test/arm-crash")
    def arm_crash(req: ArmCrashRequest) -> dict[str, Any]:
        try:
            arm_crash_point(req.crash_point)
            return {"armed": req.crash_point}
        except (IdentityKeysError, ValueError) as exc:
            raise HTTPException(status_code=403, detail=str(exc)) from exc

    @app.get("/api/v1/keys/metadata/{target_user_id}")
    def get_key_metadata(
        target_user_id: str, actor: ActorContext = Depends(require_actor)
    ) -> dict[str, Any]:
        try:
            return {"devices": metadata_svc.get_public_key_metadata(actor, target_user_id)}
        except IdentityKeysError as exc:
            raise HTTPException(status_code=403, detail=exc.reason_code) from exc

    return app


app = create_app()
