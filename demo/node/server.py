"""FastAPI Mock Service Node exposing PQC protected endpoints, audit logging & detector integration (P4-09).

Configured via environment variables:
- NODE_ID (default: 'node-a')
- PORT (default: 8001)
- PEER_NODES (default: comma-separated peer URLs)
- KEY_AUTHORITY_URL (default: 'http://localhost:8000')
- GRACE_PERIOD_SECONDS (default: 5.0)

Validates all inbound and outbound envelope/key/audit payloads against schemas/.
"""

from __future__ import annotations

import base64
import json
import os
import secrets
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import jsonschema
import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pqcrypto.kem import ml_kem_768
from pqcrypto.sign import ml_dsa_65
from pydantic import BaseModel, Field

from demo.node.adapters import NodeAdapters
from demo.node.inbox import RecipientInbox
from demo.node.sandbox_api import SandboxController, create_sandbox_router
from demo.node.ui import render_dashboard_html
from src.crypto.primitives import CryptoError, unb64
from src.crypto.replay_cache import CounterOutOfWindowError, ReplayRejectedError

# Load Frozen JSON Schemas
SCHEMAS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "schemas"))


class RecipientKeyStateError(CryptoError):
    def __init__(self, state: str, cutoff: float):
        super().__init__(f"Recipient key is {state}")
        self.state = state
        self.cutoff = cutoff

def _load_schema(filename: str) -> Dict[str, Any]:
    path = os.path.join(SCHEMAS_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

ENVELOPE_SCHEMA = _load_schema("envelope.schema.json")
KEY_STATE_SCHEMA = _load_schema("key_state.schema.json")
AUDIT_EVENT_SCHEMA = _load_schema("audit_event.schema.json")

ENVELOPE_VALIDATOR = jsonschema.validators.validator_for(ENVELOPE_SCHEMA)(ENVELOPE_SCHEMA)
ENVELOPE_VALIDATOR.check_schema(ENVELOPE_SCHEMA)


# Request/Response Models
class EnrollRequest(BaseModel):
    node_id: str
    public_key_b64: Optional[str] = None
    role: str = "node"
    device_id: Optional[str] = None


class PeerKeys(BaseModel):
    node_id: str = Field(min_length=1)
    signing_public_key_b64: str
    kem_key_id: str = Field(min_length=1)
    kem_key_version: int = Field(ge=1)
    kem_public_key_b64: str


class SendRequest(BaseModel):
    target_node_url: Optional[str] = None
    recipient_id: str
    payload: Dict[str, Any]

class RevokeKeyRequest(BaseModel):
    key_id: str
    reason: str = "administrative revocation"
    target_node_id: Optional[str] = None


class DeliveryReceipt(BaseModel):
    status: str
    receipt_id: str
    message_id: str
    sequence: int
    record_hash: str


def _require_bearer(authorization: Optional[str], token: Optional[str], scope: str) -> None:
    if not token:
        raise HTTPException(status_code=503, detail=f"{scope} is disabled")
    scheme, _, credential = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not secrets.compare_digest(credential.encode(), token.encode()):
        raise HTTPException(status_code=401, detail=f"{scope} requires a bearer token",
                            headers={"WWW-Authenticate": "Bearer"})


def _schema_envelope(envelope: Dict[str, Any]) -> Dict[str, Any]:
    fields = (
        "sender_id", "recipient_id", "session_id", "kem_ciphertext", "nonce", "ciphertext", "signature"
    )
    header = {field: envelope.get(field) for field in ("sender_id", "recipient_id", "session_id")}
    header["seq_num"] = envelope.get("sequence_number")
    if type(header["seq_num"]) is not int or not 0 <= header["seq_num"] < 2**63:
        raise ValueError("Invalid envelope sequence number")
    suite = envelope.get("algorithm_suite")
    if suite != {"kem": "ML-KEM-768", "sig": "ML-DSA-65", "aead": "AES-256-GCM"}:
        raise ValueError("Unsupported envelope algorithms")
    if envelope.get("version") != "1.0.0":
        raise ValueError("Unsupported envelope version")
    if (
        envelope.get("associated_data", header) != header
        or envelope.get("seq_num", header["seq_num"]) != header["seq_num"]
    ):
        raise ValueError("Envelope header is inconsistent")
    result = {field: envelope.get(field) for field in fields}
    result.update(
        version=envelope["version"],
        seq_num=header["seq_num"],
        associated_data=header,
        sig_alg=suite["sig"],
        kem_alg=suite["kem"],
    )
    ENVELOPE_VALIDATOR.validate(result)
    return result


def create_app(
    node_id: Optional[str] = None,
    data_dir: Optional[str] = None,
    grace_period_seconds: Optional[float] = None,
    peer_nodes: Optional[List[str]] = None,
    peer_enroll_token: Optional[str] = None,
    operator_token: Optional[str] = None,
    recipient_token: Optional[str] = None,
    revocation_sync_token: Optional[str] = None,
) -> FastAPI:
    # Resolve configuration from environment variables or params
    node_id = node_id or os.environ.get("NODE_ID", "node-a")
    data_dir = data_dir or os.environ.get("DATA_DIR", f"/tmp/tbv_data_{node_id}")
    grace_period_sec = float(grace_period_seconds or os.environ.get("GRACE_PERIOD_SECONDS", "5.0"))

    peers_env = os.environ.get("PEER_NODES", "")
    peers_list = peer_nodes or [p.strip() for p in peers_env.split(",") if p.strip()]
    peer_enroll_token = peer_enroll_token or os.environ.get("DEMO_PEER_ENROLL_TOKEN")
    operator_token = operator_token or os.environ.get("DEMO_OPERATOR_TOKEN")
    recipient_token = recipient_token or os.environ.get("DEMO_RECIPIENT_TOKEN")
    revocation_sync_token = revocation_sync_token or os.environ.get("DEMO_REVOCATION_SYNC_TOKEN")
    credentials = [token for token in (peer_enroll_token, operator_token, recipient_token, revocation_sync_token) if token]
    if len(credentials) != len(set(credentials)):
        raise ValueError("Demo peer, operator, recipient and sync credentials must be distinct")

    app = FastAPI(title=f"Trust-But-Verify Node Service [{node_id}]", version="1.0.0")

    # Initialize typed adapter cluster
    os.makedirs(data_dir, mode=0o700, exist_ok=True)
    adapters = NodeAdapters(node_id=node_id, data_dir=data_dir, grace_period_sec=grace_period_sec)

    boot_time = time.time()
    crypto = adapters.crypto
    identity = adapters.identity
    audit = adapters.audit
    if crypto.is_mock or identity.is_mock or audit.is_mock:
        raise RuntimeError("Protected transport requires real crypto, lifecycle and audit providers")
    key_lock = threading.Lock()
    inbox = RecipientInbox(Path(data_dir) / f"{node_id}_inbox.sqlite3", node_id)

    # In-memory peer bindings and operational metrics
    enrolled_nodes: Dict[str, Dict[str, Any]] = {}
    recent_alerts: List[Dict[str, Any]] = []
    trusted_peers: Dict[str, PeerKeys] = {}
    message_stats = {"sent": 0, "received": 0, "rejected": 0}
    crypto_latencies: List[float] = []
    last_revocation_ms = 0.0

    # Attach components for programmatic access (compatible with test harnesses)
    app.state.node_id = node_id
    app.state.adapters = adapters
    app.state.key_manager = identity.key_manager
    app.state.revocation = identity.revocation
    app.state.audit_logger = audit.logger
    app.state.messaging = crypto.messaging
    app.state.sig_provider = crypto.sig
    app.state.kem_provider = crypto.kem
    app.state.enrolled_nodes = enrolled_nodes
    app.state.recent_alerts = recent_alerts

    sandbox = SandboxController(
        node_id=node_id,
        data_dir=data_dir,
        grace_period_sec=grace_period_sec,
        audit_logger=audit.logger,
        audit_verifier=audit.verifier,
        recent_alerts=recent_alerts,
        boot_time=boot_time,
    )

    def require_operator(request: Request, authorization: Optional[str] = Header(default=None)) -> str:
        try:
            _require_bearer(authorization, operator_token, "Key administration")
        except HTTPException as exc:
            if exc.status_code == 401:
                audit.logger.log_event(
                    service=node_id, action="OPERATOR_AUTH_DENIED", subject="unauthenticated",
                    resource=request.url.path, status="DENIED",
                )
                recent_alerts.append({
                    "alert_id": f"alert-operator-{time.time_ns()}",
                    "rule_name": "UNAUTHORIZED_KEY_ADMINISTRATION",
                    "severity": "HIGH",
                    "description": f"Unauthenticated request to {request.url.path}",
                })
            raise
        return "demo-operator"

    if os.environ.get("DEMO_SANDBOX_ENABLED") == "1":
        app.include_router(create_sandbox_router(sandbox, require_operator))

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    def active_key():
        with key_lock:
            return identity.key_manager.get_active_key()

    def recipient_private_key(key_id: str) -> bytes:
        with key_lock:
            record = identity.key_manager.get_key_for_decryption(key_id)
            if record is not None and record.owner_node_id == node_id and record.private_key_b64:
                return unb64(record.private_key_b64, ml_kem_768.SECRET_KEY_SIZE)
            record = identity.key_manager.keys.get(key_id)
            if record is not None and record.owner_node_id == node_id:
                raise RecipientKeyStateError(record.state.value.lower(), record.grace_period_cutoff)
        raise CryptoError("Unknown recipient key")

    def _service_info() -> Dict[str, Any]:
        active = active_key()
        return {
            "name": "Trust-But-Verify",
            "tagline": "Post-Quantum Cryptographic Zero-Trust Defense & Explainable Detection",
            "node_id": node_id,
            "status": "online",
            "active_key_id": getattr(active, "key_id", None) if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "pqc_standards": ["NIST FIPS 203 (ML-KEM-768)", "NIST FIPS 204 (ML-DSA-65)"],
            "endpoints": {
                "dashboard_ui": "/",
                "health": "/health",
                "interactive_swagger_docs": "/docs",
                "metrics": "/metrics",
                "verify_audit_logs": "/logs/verify",
                "send_envelope": "POST /send",
                "receive_envelope": "POST /receive",
                "read_inbox": "GET /inbox/{receipt_id}",
                "rotate_key": "POST /keys/rotate",
                "revoke_key": "POST /keys/revoke",
                "enroll_device": "POST /enroll",
                "public_keys": "GET /keys/public",
                "enroll_peer": "POST /peers",
            },
        }

    @app.get("/api/info")
    def api_info(_actor: str = Depends(require_operator)):
        return _service_info()

    @app.get("/", response_class=HTMLResponse)
    def root(request: Request, authorization: Optional[str] = Header(default=None)):
        accept = request.headers.get("accept", "")
        if "application/json" in accept and "text/html" not in accept:
            require_operator(request, authorization)
            return JSONResponse(_service_info())
        return HTMLResponse(content=render_dashboard_html())

    @app.get("/health")
    def health_check():
        active = active_key()
        return {
            "status": "healthy",
            "node_id": node_id,
            "active_key_id": getattr(active, "key_id", None) if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "uptime_seconds": round(time.time() - boot_time, 2),
            "timestamp_ns": time.time_ns(),
        }

    @app.get("/keys/public", response_model=PeerKeys)
    def public_keys():
        active = active_key()
        if active is None:
            raise HTTPException(status_code=503, detail="No active recipient key")
        return PeerKeys(
            node_id=node_id,
            signing_public_key_b64=base64.b64encode(crypto.sig_public_key).decode("ascii"),
            kem_key_id=active.key_id,
            kem_key_version=active.version,
            kem_public_key_b64=active.public_key_b64,
        )

    @app.post("/peers")
    def enroll_peer(keys: PeerKeys, authorization: Optional[str] = Header(default=None)):
        _require_bearer(authorization, peer_enroll_token, "Peer enrollment")
        try:
            unb64(keys.signing_public_key_b64, ml_dsa_65.PUBLIC_KEY_SIZE)
            unb64(keys.kem_public_key_b64, ml_kem_768.PUBLIC_KEY_SIZE)
        except CryptoError as exc:
            raise HTTPException(status_code=422, detail="Invalid peer public keys") from exc
        with key_lock:
            previous = trusted_peers.get(keys.node_id)
            if previous is not None and previous != keys:
                same_signer = previous.signing_public_key_b64 == keys.signing_public_key_b64
                fresh_key = (
                    keys.kem_key_version > previous.kem_key_version
                    and keys.kem_key_id != previous.kem_key_id
                    and keys.kem_public_key_b64 != previous.kem_public_key_b64
                )
                if not same_signer or not fresh_key:
                    raise HTTPException(status_code=409, detail="Conflicting or stale peer key binding")
            trusted_peers[keys.node_id] = keys
        return {"status": "enrolled", "node_id": keys.node_id, "kem_key_id": keys.kem_key_id}

    @app.post("/enroll")
    def enroll_device(req: EnrollRequest, _actor: str = Depends(require_operator)):
        now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pub_b64 = req.public_key_b64 or base64.b64encode(crypto.sig_public_key).decode("ascii")
        dev_id = req.device_id or f"dev-{req.node_id}"

        key_state_record = {
            "key_id": f"key-{req.node_id}-v1",
            "identity_id": req.node_id,
            "device_id": dev_id,
            "version": 1,
            "algorithm": getattr(crypto.kem, "algorithm_name", "ML-KEM-768"),
            "public_key": pub_b64,
            "status": "active",
            "created_at": now_iso,
            "grace_cutoff": None,
            "revoked_at": None,
            "authority_sig": base64.b64encode(crypto.sig.sign(f"{req.node_id}:{pub_b64}".encode())).decode("ascii"),
        }

        # Validate with key_state schema if loaded
        if KEY_STATE_SCHEMA:
            try:
                jsonschema.validate(instance=key_state_record, schema=KEY_STATE_SCHEMA)
            except jsonschema.ValidationError as e:
                raise HTTPException(status_code=422, detail=f"Key state schema validation failed: {e.message}")

        enrolled_nodes[req.node_id] = key_state_record

        rec = audit.logger.log_event(
            service=node_id,
            action="DEVICE_ENROLLMENT",
            subject=req.node_id,
            resource=f"/enroll/{req.node_id}",
            status="SUCCESS",
            metadata={"role": req.role, "device_id": dev_id},
        )
        return {
            "status": "enrolled",
            "node_id": req.node_id,
            "role": req.role,
            "key_state": key_state_record,
            "audit_sequence": getattr(rec, "sequence", 0),
        }

    @app.post("/send")
    def send_message(req: SendRequest, _actor: str = Depends(require_operator)):
        t0 = time.perf_counter()
        sender_id = node_id
        recipient_id = req.recipient_id

        # 1. Lateral movement check
        viol = audit.lateral_graph.check_call(sender_id, recipient_id, "SEND_MESSAGE")
        if viol:
            recent_alerts.append({
                "alert_id": f"alert-lateral-{time.time_ns()}",
                "rule_name": "LATERAL_MOVEMENT_VIOLATION",
                "severity": "HIGH",
                "description": getattr(viol, "reason", "Lateral movement policy violation"),
                "evidence": getattr(viol, "to_dict", lambda: {})(),
            })
            audit.logger.log_event(
                service=node_id,
                action="LATERAL_SEND_BLOCKED",
                subject=sender_id,
                resource=f"node://{recipient_id}",
                status="DENIED",
                metadata={"reason": "unauthorized lateral path"},
            )
            raise HTTPException(status_code=403, detail="Lateral movement violation: unauthorized call path")

        with key_lock:
            peer = trusted_peers.get(recipient_id)
        if peer is None:
            raise HTTPException(status_code=403, detail="Recipient transport keys are not enrolled")
        plaintext_bytes = json.dumps(req.payload, sort_keys=True).encode("utf-8")
        raw_env = crypto.messaging.seal_for_recipient(
            recipient_id, plaintext_bytes, peer.kem_key_id,
            unb64(peer.kem_public_key_b64, ml_kem_768.PUBLIC_KEY_SIZE), crypto.kem, crypto.sig,
        )
        envelope = _schema_envelope(raw_env)
        for field in ("seq_num", "associated_data", "sig_alg", "kem_alg"):
            raw_env[field] = envelope[field]

        latency = (time.perf_counter() - t0) * 1000.0
        crypto_latencies.append(latency)
        message_stats["sent"] += 1

        audit.logger.log_event(
            service=node_id,
            action="MESSAGE_DISPATCHED",
            subject=sender_id,
            resource=f"node://{recipient_id}",
            status="SUCCESS",
            metadata={"session_id": envelope["session_id"], "seq_num": envelope["seq_num"]},
        )

        return {"status": "dispatched", "envelope": raw_env}

    @app.post("/receive", response_model=DeliveryReceipt)
    def receive_message(envelope: Dict[str, Any]):
        t0 = time.perf_counter()
        try:
            _schema_envelope(envelope)
        except (ValueError, jsonschema.ValidationError) as exc:
            message_stats["rejected"] += 1
            raise HTTPException(status_code=422, detail="Invalid protected envelope") from exc
        sender_id = envelope["sender_id"]

        # 2. Lateral movement check
        viol = audit.lateral_graph.check_call(sender_id, node_id, "RECEIVE_MESSAGE")
        if viol:
            message_stats["rejected"] += 1
            alert_obj = {
                "alert_id": f"alert-lateral-{time.time_ns()}",
                "rule_name": "LATERAL_MOVEMENT_VIOLATION",
                "severity": "HIGH",
                "description": getattr(viol, "reason", "Unauthorized lateral movement path"),
                "evidence": getattr(viol, "to_dict", lambda: {})(),
            }
            recent_alerts.append(alert_obj)
            audit.logger.log_event(
                service=node_id,
                action="LATERAL_RECEIVE_BLOCKED",
                subject=sender_id,
                resource="/receive",
                status="DENIED",
                metadata={"error": alert_obj["description"]},
            )
            raise HTTPException(status_code=403, detail=alert_obj["description"])

        with key_lock:
            peer = trusted_peers.get(sender_id)
        if peer is None:
            message_stats["rejected"] += 1
            raise HTTPException(status_code=403, detail="Sender transport keys are not enrolled")

        try:
            sender_public_key = unb64(peer.signing_public_key_b64, ml_dsa_65.PUBLIC_KEY_SIZE)
            crypto.messaging.decrypt_for_recipient(
                envelope, crypto.kem, crypto.sig, sender_public_key, recipient_private_key,
            )
            try:
                receipt_id = inbox.accept(envelope, sender_public_key)
            except (ReplayRejectedError, CounterOutOfWindowError) as exc:
                raise crypto.ReplayAttackError(str(exc)) from exc
            latency = (time.perf_counter() - t0) * 1000.0
            crypto_latencies.append(latency)
            message_stats["received"] += 1

            rec = audit.logger.log_event(
                service=node_id,
                action="MESSAGE_RECEIVED",
                subject=sender_id,
                resource="/receive",
                status="SUCCESS",
                metadata={"session_id": envelope["session_id"], "message_id": envelope["message_id"]},
            )
            return DeliveryReceipt(
                status="delivered",
                receipt_id=receipt_id,
                message_id=envelope["message_id"],
                sequence=rec.sequence,
                record_hash=rec.entry_hash,
            )

        except (crypto.RecipientMismatchError, crypto.ReplayAttackError, crypto.MessageTamperedError, KeyError, TypeError, ValueError) as e:
            message_stats["rejected"] += 1
            err_type = type(e).__name__
            audit.logger.log_event(
                service=node_id,
                action=f"{err_type.upper()}_BLOCKED",
                subject=sender_id,
                resource="/receive",
                status="DENIED",
                metadata={"error": str(e)},
            )
            metadata = {"error": str(e), "source_service": sender_id, "target_service": node_id}
            if isinstance(e, RecipientKeyStateError):
                metadata.update({
                    "authenticated_sender": True,
                    "recipient_key_state": e.state,
                    "seconds_since_cutoff": time.time() - e.cutoff,
                })
            alerts = audit.rule_engine.evaluate_event({
                "event_id": envelope.get("message_id", str(uuid.uuid4())),
                "timestamp_ns": time.time_ns(),
                "action": f"{err_type.upper()}_BLOCKED",
                "subject": sender_id,
                "service": node_id,
                "resource": "/receive",
                "status": "DENIED",
                "metadata": metadata,
            })
            for a in alerts:
                recent_alerts.append(getattr(a, "to_dict", lambda: a)())
            raise HTTPException(status_code=400, detail=str(e))

    @app.get("/inbox/{receipt_id}")
    def read_inbox(receipt_id: uuid.UUID, authorization: Optional[str] = Header(default=None)):
        _require_bearer(authorization, recipient_token, "Recipient inbox")
        delivery = inbox.get(receipt_id.hex)
        if delivery is None:
            raise HTTPException(status_code=404, detail="Receipt not found")
        envelope, sender_public_key = delivery
        try:
            plaintext = crypto.messaging.decrypt_for_recipient(
                envelope, crypto.kem, crypto.sig, sender_public_key, recipient_private_key,
            )
        except (CryptoError, crypto.RecipientMismatchError, crypto.MessageTamperedError) as exc:
            raise HTTPException(status_code=410, detail="Delivered message is no longer readable") from exc

        try:
            payload = json.loads(plaintext.decode("utf-8"))
        except (ValueError, UnicodeError):
            payload = {"raw": base64.b64encode(plaintext).decode("ascii")}
        return JSONResponse(
            {"message_id": envelope["message_id"], "payload": payload},
            headers={"Cache-Control": "no-store"},
        )

    @app.post("/keys/rotate")
    def rotate_key(actor: str = Depends(require_operator)):
        new_pub, new_priv = crypto.kem.generate_keypair()
        with key_lock:
            new_rec, old_rec = identity.key_manager.rotate_key(new_pub, new_priv)

        audit.logger.log_event(
            service=node_id,
            action="ROTATE_KEY_SUCCESS",
            subject=actor,
            resource="/keys/rotate",
            status="SUCCESS",
            metadata={"new_key_id": new_rec.key_id, "old_key_id": old_rec.key_id if old_rec else None},
        )
        return {
            "status": "rotated",
            "active_key": new_rec.to_dict(),
            "grace_key": old_rec.to_dict() if old_rec else None,
        }

    def apply_key_revocation(req: RevokeKeyRequest, actor: str):
        with key_lock:
            event = identity.revocation.create_revocation(
                req.key_id, req.target_node_id or node_id, req.reason, signer=crypto.sig
            )
            identity.key_manager.revoke_key(req.key_id, req.reason)
        audit.logger.log_event(
            service=node_id,
            action="REVOKE_KEY_SUCCESS",
            subject=actor,
            resource=f"/keys/{req.key_id}",
            status="SUCCESS",
            metadata={"revocation_id": event.revocation_id, "reason": req.reason},
        )
        return event

    @app.post("/internal/keys/revoke")
    def sync_revocation(req: RevokeKeyRequest, authorization: Optional[str] = Header(default=None)):
        _require_bearer(authorization, revocation_sync_token, "Peer revocation")
        apply_key_revocation(req, "demo-revocation-peer")
        return {"status": "acknowledged", "node_id": node_id}

    @app.post("/keys/revoke")
    def revoke_key(req: RevokeKeyRequest, actor: str = Depends(require_operator)):
        nonlocal last_revocation_ms
        t0 = time.perf_counter()
        rev_ev = apply_key_revocation(req, actor)

        acknowledged = 0
        if revocation_sync_token:
            payload = req.model_dump()
            payload["target_node_id"] = rev_ev.target_node_id
            for peer_url in peers_list:
                try:
                    p_req = urllib.request.Request(
                        f"{peer_url.rstrip('/')}/internal/keys/revoke",
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                    )
                    p_req.add_unredirected_header("Authorization", f"Bearer {revocation_sync_token}")
                    with urllib.request.urlopen(p_req, timeout=1.0) as response:
                        if response.status == 200:
                            acknowledged += 1
                except (OSError, ValueError):
                    continue

        last_revocation_ms = (time.perf_counter() - t0) * 1000.0
        return {
            "status": "revoked",
            "key_id": req.key_id,
            "propagation_latency_ms": round(last_revocation_ms, 2),
            "peer_acknowledgements": acknowledged,
            "peer_failures": len(peers_list) - acknowledged,
            "revocation": rev_ev.to_dict(),
        }

    @app.get("/logs/verify")
    def verify_logs(_actor: str = Depends(require_operator)):
        log_path = getattr(audit.logger, "log_file_path", f"{data_dir}/{node_id}_audit.log")
        anchor_path = os.path.join(data_dir, f".{node_id}_audit_anchor.json")
        if hasattr(audit.verifier, "verify_file"):
            anchor_arg = anchor_path if os.path.exists(anchor_path) else None
            try:
                result = audit.verifier.verify_file(log_path, anchor_path=anchor_arg)
            except TypeError:
                result = audit.verifier.verify_file(log_path)
            if getattr(result, "is_valid", False) and hasattr(audit.verifier, "save_anchor") and os.path.exists(log_path):
                audit.verifier.save_anchor(log_path, anchor_path)
        else:
            result = audit.verifier.verify_file(log_path)
        res_dict = result.to_dict() if hasattr(result, "to_dict") else {
            "is_valid": getattr(result, "is_valid", False),
            "total_records": getattr(result, "total_records", 0),
            "first_error": getattr(result, "first_error", None),
            "tampered_index": getattr(result, "tampered_index", None),
        }
        if not getattr(result, "is_valid", False):
            raise HTTPException(status_code=409, detail=res_dict)
        return res_dict

    @app.get("/metrics")
    def node_metrics(_actor: str = Depends(require_operator)):
        active = active_key()
        sorted_lats = sorted(crypto_latencies) if crypto_latencies else [0.0]
        p50 = sorted_lats[int(len(sorted_lats) * 0.50)]
        p95 = sorted_lats[int(len(sorted_lats) * 0.95)] if len(sorted_lats) > 1 else p50

        return {
            "node_id": node_id,
            "status": "healthy",
            "active_key_id": getattr(active, "key_id", None) if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "messages": message_stats,
            "crypto_latency_ms": {
                "p50": round(p50, 2),
                "p95": round(p95, 2),
            },
            "last_revocation_propagation_ms": round(last_revocation_ms, 2),
            "alerts_count": len(recent_alerts),
            "alerts": recent_alerts[-10:],
            "enrolled_nodes_count": len(enrolled_nodes),
            "uptime_seconds": round(time.time() - boot_time, 2),
        }

    return app


class NodeServer:
    """Threaded/Programmatic wrapper around the FastAPI Node Server."""

    def __init__(
        self,
        node_id: str = "node-a",
        host: str = "0.0.0.0",
        port: int = 8001,
        data_dir: Optional[str] = None,
        grace_period_seconds: float = 5.0,
    ):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.data_dir = data_dir or f"/tmp/tbv_data_{node_id}"
        self.app = create_app(node_id=node_id, data_dir=self.data_dir, grace_period_seconds=grace_period_seconds)
        self.server_config = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="warning")
        self.server = uvicorn.Server(self.server_config)
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = False):
        if blocking:
            self.server.run()
        else:
            self._thread = threading.Thread(target=self.server.run, daemon=True)
            self._thread.start()
            time.sleep(0.5)

    def stop(self):
        self.server.should_exit = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)


# Default app instance for standard ASGI workers
app = create_app(
    node_id=os.environ.get("NODE_ID", "node-a"),
    data_dir=os.environ.get("DATA_DIR", "/tmp/tbv_data"),
)


if __name__ == "__main__":
    node_id = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NODE_ID", "node-a")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", "8001"))
    server_app = create_app(node_id=node_id)
    host = os.environ.get("DEMO_BIND_HOST", "0.0.0.0")
    print(f"🚀 Starting Trust-But-Verify Node [{node_id}] on http://{host}:{port}")
    uvicorn.run(server_app, host=host, port=port, log_level="warning")
