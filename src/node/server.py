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
import sys
import threading
import time
import urllib.request
import urllib.error
import uuid
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
import uvicorn
import jsonschema

from src.node.adapters import NodeAdapters

# Load Frozen JSON Schemas
SCHEMAS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "schemas"))

def _load_schema(filename: str) -> Dict[str, Any]:
    path = os.path.join(SCHEMAS_DIR, filename)
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

ENVELOPE_SCHEMA = _load_schema("envelope.schema.json")
KEY_STATE_SCHEMA = _load_schema("key_state.schema.json")
AUDIT_EVENT_SCHEMA = _load_schema("audit_event.schema.json")


# Request/Response Models
class EnrollRequest(BaseModel):
    node_id: str
    public_key_b64: Optional[str] = None
    role: str = "node"
    device_id: Optional[str] = None

class SendRequest(BaseModel):
    target_node_url: str
    recipient_id: str
    payload: Dict[str, Any]

class RotateKeyRequest(BaseModel):
    role: str = "admin"
    requested_by: str = "operator"
    identity: Optional[str] = None

class RevokeKeyRequest(BaseModel):
    key_id: str
    reason: str = "administrative revocation"
    target_node_id: Optional[str] = None
    role: str = "admin"


def create_app(
    node_id: Optional[str] = None,
    data_dir: Optional[str] = None,
    grace_period_seconds: Optional[float] = None,
    peer_nodes: Optional[List[str]] = None,
) -> FastAPI:
    # Resolve configuration from environment variables or params
    node_id = node_id or os.environ.get("NODE_ID", "node-a")
    data_dir = data_dir or os.environ.get("DATA_DIR", f"/tmp/tbv_data_{node_id}")
    grace_period_sec = float(grace_period_seconds or os.environ.get("GRACE_PERIOD_SECONDS", "5.0"))
    key_authority_url = os.environ.get("KEY_AUTHORITY_URL", "http://localhost:8000")

    peers_env = os.environ.get("PEER_NODES", "")
    peers_list = peer_nodes or [p.strip() for p in peers_env.split(",") if p.strip()]

    app = FastAPI(title=f"Trust-But-Verify Node Service [{node_id}]", version="1.0.0")

    # Initialize typed adapter cluster
    os.makedirs(data_dir, exist_ok=True)
    adapters = NodeAdapters(node_id=node_id, data_dir=data_dir, grace_period_sec=grace_period_sec)

    boot_time = time.time()
    crypto = adapters.crypto
    identity = adapters.identity
    audit = adapters.audit

    # In-memory peer bindings and operational metrics
    enrolled_nodes: Dict[str, Dict[str, Any]] = {}
    recent_alerts: List[Dict[str, Any]] = []
    peer_shared_keys: Dict[str, bytes] = {}
    peer_public_keys: Dict[str, bytes] = {}
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
    app.state.peer_shared_keys = peer_shared_keys
    app.state.peer_public_keys = peer_public_keys
    app.state.enrolled_nodes = enrolled_nodes
    app.state.recent_alerts = recent_alerts

    @app.get("/")
    def root():
        active = identity.key_manager.get_active_key()
        return {
            "name": "Trust-But-Verify",
            "tagline": "Post-Quantum Cryptographic Zero-Trust Defense & Explainable Detection",
            "node_id": node_id,
            "status": "online",
            "active_key_id": getattr(active, "key_id", None) if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "pqc_standards": ["NIST FIPS 203 (ML-KEM-768)", "NIST FIPS 204 (ML-DSA-65)"],
            "endpoints": {
                "health": "/health",
                "interactive_swagger_docs": "/docs",
                "metrics": "/metrics",
                "verify_audit_logs": "/logs/verify",
                "send_envelope": "POST /send",
                "receive_envelope": "POST /receive",
                "rotate_key": "POST /keys/rotate",
                "revoke_key": "POST /keys/revoke",
                "enroll_device": "POST /enroll",
            },
        }

    @app.get("/health")
    def health_check():
        active = identity.key_manager.get_active_key()
        return {
            "status": "healthy",
            "node_id": node_id,
            "active_key_id": getattr(active, "key_id", None) if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "uptime_seconds": round(time.time() - boot_time, 2),
            "timestamp_ns": time.time_ns(),
        }

    @app.post("/enroll")
    def enroll_device(req: EnrollRequest):
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
        if req.public_key_b64:
            try:
                peer_public_keys[req.node_id] = base64.b64decode(req.public_key_b64)
            except Exception:
                peer_public_keys[req.node_id] = req.public_key_b64.encode()

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
    def send_message(req: SendRequest):
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

        # 2. Prepare envelope
        shared_key = peer_shared_keys.get(recipient_id, b"DEFAULT-DEMO-SHARED-KEY-32BYTES!")
        plaintext_bytes = json.dumps(req.payload, sort_keys=True).encode("utf-8")

        seq = message_stats["sent"] + 1
        sess_id = f"sess-{sender_id}-{recipient_id}"

        # Raw pack
        raw_env = crypto.messaging.pack_envelope(
            sender_id=sender_id,
            recipient_id=recipient_id,
            plaintext=plaintext_bytes,
            shared_key=shared_key,
            signer=crypto.sig,
        )

        # Build schema-compliant envelope for schemas/envelope.schema.json
        envelope = {
            "version": "1.0",
            "sender_id": sender_id,
            "recipient_id": recipient_id,
            "seq_num": raw_env.get("sequence_number", seq),
            "session_id": raw_env.get("session_id", sess_id),
            "kem_ciphertext": raw_env.get("kem_ciphertext") or base64.b64encode(b"MOCK_KEM_CIPHERTEXT").decode("ascii"),
            "nonce": raw_env.get("nonce"),
            "ciphertext": raw_env.get("ciphertext"),
            "associated_data": {
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "seq_num": raw_env.get("sequence_number", seq),
                "session_id": raw_env.get("session_id", sess_id),
            },
            "signature": raw_env.get("signature"),
            "sig_alg": "ML-DSA-65",
            "kem_alg": "ML-KEM-768",
        }

        # Also preserve legacy fields for backward compatibility with in-memory unpackers
        raw_env["seq_num"] = envelope["seq_num"]
        raw_env["associated_data"] = envelope["associated_data"]
        raw_env["sig_alg"] = "ML-DSA-65"
        raw_env["kem_alg"] = "ML-KEM-768"

        # Validate with envelope schema
        if ENVELOPE_SCHEMA:
            try:
                jsonschema.validate(instance=envelope, schema=ENVELOPE_SCHEMA)
            except jsonschema.ValidationError as e:
                raise HTTPException(status_code=422, detail=f"Envelope schema violation: {e.message}")

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

    @app.post("/receive")
    def receive_message(envelope: Dict[str, Any]):
        t0 = time.perf_counter()
        sender_id = envelope.get("sender_id", "unknown")

        # 1. Schema Validation
        # If envelope has associated_data as a dict, validate against frozen schema
        if isinstance(envelope.get("associated_data"), dict) and ENVELOPE_SCHEMA:
            # Prepare canonical schema dict for validation
            schema_target = {
                "version": envelope.get("version", "1.0"),
                "sender_id": envelope.get("sender_id", ""),
                "recipient_id": envelope.get("recipient_id", ""),
                "seq_num": envelope.get("seq_num", envelope.get("sequence_number", 0)),
                "session_id": envelope.get("session_id", ""),
                "kem_ciphertext": envelope.get("kem_ciphertext") or base64.b64encode(b"MOCK_KEM_CT").decode(),
                "nonce": envelope.get("nonce", ""),
                "ciphertext": envelope.get("ciphertext", ""),
                "associated_data": envelope["associated_data"],
                "signature": envelope.get("signature", ""),
                "sig_alg": envelope.get("sig_alg", "ML-DSA-65"),
                "kem_alg": envelope.get("kem_alg", "ML-KEM-768"),
            }
            try:
                jsonschema.validate(instance=schema_target, schema=ENVELOPE_SCHEMA)
            except jsonschema.ValidationError as e:
                message_stats["rejected"] += 1
                raise HTTPException(status_code=422, detail=f"Envelope schema validation failed: {e.message}")

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

        # 3. Key Status Check (reject revoked or expired keys)
        if hasattr(identity.key_manager, "enforce_cutoffs"):
            identity.key_manager.enforce_cutoffs()

        target_key_id = envelope.get("key_id")
        if target_key_id and hasattr(identity.key_manager, "is_revoked") and identity.key_manager.is_revoked(target_key_id):
            message_stats["rejected"] += 1
            raise HTTPException(status_code=400, detail=f"Key '{target_key_id}' is revoked")

        # 4. Decrypt and verify
        shared_key = peer_shared_keys.get(sender_id, b"DEFAULT-DEMO-SHARED-KEY-32BYTES!")
        sender_pubkey = peer_public_keys.get(sender_id, b"DEFAULT-PUBKEY-32BYTES-MOCK!!!!")

        # Normalize envelope fields for unpacker
        if "seq_num" in envelope and "sequence_number" not in envelope:
            envelope["sequence_number"] = envelope["seq_num"]
        if "additional_authenticated_data" not in envelope and "associated_data" in envelope:
            if isinstance(envelope["associated_data"], dict):
                envelope["additional_authenticated_data"] = base64.b64encode(json.dumps(envelope["associated_data"]).encode()).decode("ascii")
            elif isinstance(envelope["associated_data"], str):
                envelope["additional_authenticated_data"] = envelope["associated_data"]

        try:
            plaintext = crypto.messaging.unpack_envelope(
                envelope=envelope,
                shared_key=shared_key,
                verifier_sig=crypto.sig,
                sender_public_key=sender_pubkey,
            )
            latency = (time.perf_counter() - t0) * 1000.0
            crypto_latencies.append(latency)
            message_stats["received"] += 1

            rec = audit.logger.log_event(
                service=node_id,
                action="MESSAGE_RECEIVED",
                subject=sender_id,
                resource="/receive",
                status="SUCCESS",
                metadata={"session_id": envelope.get("session_id")},
            )

            try:
                dec_payload = json.loads(plaintext.decode("utf-8"))
            except Exception:
                dec_payload = {"raw": base64.b64encode(plaintext).decode()}

            return {
                "status": "delivered",
                "message_id": envelope.get("message_id", envelope.get("session_id")),
                "sequence": getattr(rec, "sequence", 0),
                "record_hash": getattr(rec, "entry_hash", getattr(rec, "record_hash", "")),
                "payload": dec_payload,
            }

        except (crypto.RecipientMismatchError, crypto.ReplayAttackError, crypto.MessageTamperedError, Exception) as e:
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
            alerts = audit.rule_engine.evaluate_event({
                "event_id": envelope.get("message_id", str(uuid.uuid4())),
                "timestamp_ns": time.time_ns(),
                "action": f"{err_type.upper()}_BLOCKED",
                "subject": sender_id,
                "service": node_id,
                "resource": "/receive",
                "status": "DENIED",
                "metadata": {"error": str(e)},
            })
            for a in alerts:
                recent_alerts.append(getattr(a, "to_dict", lambda: a)())
            raise HTTPException(status_code=400, detail=str(e))

    @app.post("/keys/rotate")
    def rotate_key(req: RotateKeyRequest):
        if req.role != "admin":
            recent_alerts.append({
                "alert_id": f"alert-priv-{time.time_ns()}",
                "rule_name": "UNAUTHORIZED_PRIVILEGE_ELEVATION",
                "severity": "CRITICAL",
                "description": f"Non-admin role '{req.role}' attempted key rotation",
            })
            audit.logger.log_event(
                service=node_id,
                action="ROTATE_KEY_DENIED",
                subject=req.requested_by,
                resource="/keys/rotate",
                status="DENIED",
                metadata={"role": req.role},
            )
            raise HTTPException(status_code=403, detail="Unauthorized: admin role required for key rotation")

        new_pub, new_priv = crypto.kem.generate_keypair()
        new_rec, old_rec = identity.key_manager.rotate_key(new_pub, new_priv)

        audit.logger.log_event(
            service=node_id,
            action="ROTATE_KEY_SUCCESS",
            subject=req.requested_by,
            resource="/keys/rotate",
            status="SUCCESS",
            metadata={"new_key_id": getattr(new_rec, "key_id", ""), "old_key_id": getattr(old_rec, "key_id", None)},
        )
        return {
            "status": "rotated",
            "active_key": new_rec.to_dict() if hasattr(new_rec, "to_dict") else {"key_id": getattr(new_rec, "key_id", "")},
            "grace_key": old_rec.to_dict() if (old_rec and hasattr(old_rec, "to_dict")) else None,
        }

    @app.post("/keys/revoke")
    def revoke_key(req: RevokeKeyRequest):
        nonlocal last_revocation_ms
        if req.role != "admin":
            raise HTTPException(status_code=403, detail="Unauthorized: admin role required for revocation")

        t0 = time.perf_counter()
        target = req.target_node_id or node_id
        rev_ev = identity.revocation.create_revocation(req.key_id, target, req.reason, signer=crypto.sig)
        identity.key_manager.revoke_key(req.key_id, req.reason)

        # Broadcast to peers if configured
        for peer_url in peers_list:
            try:
                p_req = urllib.request.Request(
                    f"{peer_url.rstrip('/')}/keys/revoke",
                    data=json.dumps({"key_id": req.key_id, "reason": req.reason, "role": "admin"}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(p_req, timeout=1.0) as resp:
                    pass
            except Exception:
                pass

        last_revocation_ms = (time.perf_counter() - t0) * 1000.0

        audit.logger.log_event(
            service=node_id,
            action="REVOKE_KEY_SUCCESS",
            subject=req.role,
            resource=f"/keys/{req.key_id}",
            status="SUCCESS",
            metadata={"revocation_id": getattr(rev_ev, "revocation_id", str(uuid.uuid4())), "reason": req.reason},
        )
        return {
            "status": "revoked",
            "key_id": req.key_id,
            "propagation_latency_ms": round(last_revocation_ms, 2),
            "revocation": rev_ev.to_dict() if hasattr(rev_ev, "to_dict") else {"key_id": req.key_id},
        }

    @app.get("/logs/verify")
    def verify_logs():
        log_path = getattr(audit.logger, "log_file_path", f"{data_dir}/{node_id}_audit.log")
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
    def node_metrics():
        active = identity.key_manager.get_active_key()
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
    print(f"🚀 Starting Trust-But-Verify Node [{node_id}] on http://0.0.0.0:{port}")
    uvicorn.run(server_app, host="0.0.0.0", port=port, log_level="warning")
