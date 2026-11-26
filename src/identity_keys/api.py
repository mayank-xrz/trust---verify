"""Thin FastAPI application for Person B multi-node identity & authorization service."""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel

from .audit_outbox import AuditEmitter
from .clock import Clock, SystemClock
from .db import create_db_engine, create_session_factory
from .errors import IdentityKeysError, NotAuthorized
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
    # Optional ignored fields to prove actor spoofing in body is never trusted
    actor_id: str | None = None
    label: str | None = None


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
        max_cache_staleness_ms=int(os.environ.get("MAX_CACHE_STALENESS_MS", "5000")),
    )
    metadata_svc = KeyMetadataService(session_factory)

    app = FastAPI(title=f"Trust-But-Verify Identity Node ({resolved_node})")
    app.state.engine = engine
    app.state.session_factory = session_factory
    app.state.token_authority = token_auth
    app.state.identity_svc = identity_svc
    app.state.authz_svc = authz_svc

    def require_actor(authorization: str | None = Header(default=None)) -> ActorContext:
        if not authorization or not authorization.startswith("Bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = authorization[len("Bearer ") :].strip()
        try:
            return token_auth.verify(token)
        except NotAuthorized as exc:
            raise HTTPException(status_code=401, detail=exc.reason_code) from exc

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
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
    def start_enroll(user_id: str, kind: str = "first") -> dict[str, str]:
        try:
            return identity_svc.start_enrollment(user_id=user_id, kind=kind)
        except IdentityKeysError as exc:
            raise HTTPException(status_code=400, detail=exc.reason_code) from exc

    @app.post("/api/v1/enroll")
    def enroll(req: EnrollRequest) -> dict[str, Any]:
        try:
            return identity_svc.enroll_device(
                enrollment_id=req.enrollment_id,
                nonce=req.nonce,
                label=req.label,
                public_key_b64=req.public_key_b64,
                proof_of_possession_b64=req.proof_of_possession_b64,
                public_key_alg=req.public_key_alg,
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
        decision = authz_svc.authorize(actor, req.resource_id, req.permission)
        return {
            "allowed": decision.allowed,
            "reason_code": decision.reason_code,
            "key_version_id": decision.key_version_id,
            "decision_id": decision.decision_id,
            "node_id": resolved_node,
        }

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
