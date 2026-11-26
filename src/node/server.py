"""FastAPI Mock Service Node exposing PQC protected endpoints, audit logging & detector integration."""

from __future__ import annotations
import base64
import json
import os
import sys
import threading
import time
import uuid
from typing import Dict, Any, Optional, List

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import BaseModel, Field
import uvicorn

# Adapters with graceful in-memory fallbacks for Persons A, B, and C
try:
    from src.crypto.pqc_kem import MLKEMKeyExchange
    from src.crypto.pqc_sig import MLDSASignature
    from src.crypto.messaging import (
        SecureMessaging,
        RecipientMismatchError,
        ReplayAttackError,
        MessageTamperedError,
    )
except ImportError:
    # In-memory Person A Crypto Stubs
    class MLKEMKeyExchange:
        algorithm_name = "MOCK-KEM-768"
        def generate_keypair(self): return b"MOCK_PUB", b"MOCK_PRIV"
        def encapsulate(self, pub): return b"MOCK_CT", b"MOCK_SECRET_32_BYTES_STUB!!!!!"
        def decapsulate(self, ct, priv=None): return b"MOCK_SECRET_32_BYTES_STUB!!!!!"
        def wipe_keys(self): pass

    class MLDSASignature:
        algorithm_name = "MOCK-DSA-65"
        def generate_keypair(self): return b"MOCK_SIG_PUB", b"MOCK_SIG_PRIV"
        def sign(self, msg, priv=None): return b"MOCK_SIGNATURE_BYTES_STUB"
        def verify(self, msg, sig, pub): return True

    class RecipientMismatchError(Exception): pass
    class ReplayAttackError(Exception): pass
    class MessageTamperedError(Exception): pass

    class SecureMessaging:
        def __init__(self, node_id: str): self.node_id = node_id
        def pack_envelope(self, sender_id, recipient_id, plaintext, shared_key, signer, **kwargs):
            return {
                "version": "1.0.0",
                "message_id": str(uuid.uuid4()),
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "seq_num": 0,
                "session_id": "sess-stub",
                "kem_ciphertext": base64.b64encode(b"ct").decode(),
                "nonce": base64.b64encode(b"nonce").decode(),
                "ciphertext": base64.b64encode(plaintext).decode(),
                "associated_data": base64.b64encode(b"aad").decode(),
                "signature": base64.b64encode(b"sig").decode(),
            }
        def unpack_envelope(self, envelope, shared_key, verifier, sender_pubkey):
            if envelope.get("recipient_id") != self.node_id:
                raise RecipientMismatchError(f"Recipient mismatch: target {envelope.get('recipient_id')}, local {self.node_id}")
            return base64.b64decode(envelope.get("ciphertext", ""))

try:
    from src.identity.key_manager import KeyManager, KeyStateEnum
    from src.identity.revocation import RevocationCoordinator
    from src.identity.recovery import WALManager
except ImportError:
    # In-memory Person B Identity Stubs
    class KeyStateEnum:
        ACTIVE = "active"
        GRACE_PERIOD = "grace"
        REVOKED = "revoked"

    class KeyRecordStub:
        def __init__(self, key_id, version=1, state="active"):
            self.key_id = key_id
            self.version = version
            self.state = state
        def to_dict(self, **kwargs):
            return {"key_id": self.key_id, "version": self.version, "status": str(self.state)}

    class KeyManager:
        def __init__(self, node_id, **kwargs):
            self.node_id = node_id
            self.active_key_id = f"key-{node_id}-v1"
            self.keys = {self.active_key_id: KeyRecordStub(self.active_key_id)}
        def enroll_initial_key(self, algo, pub, priv):
            return self.keys[self.active_key_id]
        def get_active_key(self):
            return self.keys.get(self.active_key_id)
        def rotate_key(self, new_pub, new_priv):
            old = self.keys.get(self.active_key_id)
            new_id = f"key-{self.node_id}-v{old.version + 1 if old else 1}"
            new_rec = KeyRecordStub(new_id, version=(old.version + 1 if old else 1))
            self.keys[new_id] = new_rec
            self.active_key_id = new_id
            return new_rec, old
        def revoke_key(self, key_id, reason="manual"):
            if key_id in self.keys:
                self.keys[key_id].state = "revoked"
                return True
            return False

    class RevocationCoordinator:
        def __init__(self, node_id): self.node_id = node_id
        def create_revocation(self, key_id, target_node_id, reason, **kwargs):
            class RevEventStub:
                revocation_id = f"rev-{key_id}"
                def to_dict(self): return {"revocation_id": self.revocation_id, "key_id": key_id, "reason": reason}
            return RevEventStub()

    class WALManager:
        def __init__(self, path): self.path = path
        def append_entry(self, op, payload): return time.time_ns()

try:
    from src.audit.logger import AuditLogger
    from src.audit.verifier import AuditLogVerifier
    from src.detector.rules import ContextRuleEngine
    from src.detector.graph_lateral import LateralMovementGraph
    from src.detector.metrics import compute_f1_mtta
except ImportError:
    # In-memory Person C Audit and Detector Stubs
    class AuditRecordStub:
        def __init__(self, seq, h): self.sequence = seq; self.entry_hash = h; self.record_hash = h
        def to_dict(self): return {"sequence": self.sequence, "record_hash": self.record_hash}

    class AuditLogger:
        def __init__(self, node_id, log_file_path, **kwargs):
            self.node_id = node_id
            self.log_file_path = log_file_path
            self._seq = 0
        def log_event(self, **kwargs):
            self._seq += 1
            return AuditRecordStub(self._seq, "0" * 64)

    class AuditLogVerifier:
        def verify_file(self, path):
            class VerifResStub:
                is_valid = True
                total_records = 1
                verified_checkpoints = 1
                first_error = None
                def to_dict(self): return {"is_valid": self.is_valid, "total_records": self.total_records}
            return VerifResStub()

    class ContextRuleEngine:
        def evaluate_event(self, event): return []

    class LateralMovementGraph:
        def check_call(self, src, dst, action=""): return None


# Request/Response Models
class EnrollRequest(BaseModel):
    node_id: str
    public_key_b64: str
    role: str = "node"

class SendRequest(BaseModel):
    target_node_url: str
    recipient_id: str
    payload: Dict[str, Any]

class RotateKeyRequest(BaseModel):
    role: str = "admin"
    requested_by: str = "operator"

class RevokeKeyRequest(BaseModel):
    key_id: str
    reason: str = "administrative revocation"
    target_node_id: Optional[str] = None
    role: str = "admin"


def create_app(node_id: str = "node-a", data_dir: str = "/tmp/tbv_data") -> FastAPI:
    app = FastAPI(title=f"Trust-But-Verify Node Service [{node_id}]", version="1.0.0")

    # Initialize node state
    os.makedirs(data_dir, exist_ok=True)
    kem_provider = MLKEMKeyExchange()
    sig_provider = MLDSASignature()
    sig_pub, sig_priv = sig_provider.generate_keypair()

    wal_path = os.path.join(data_dir, f"{node_id}_wal.log")
    wal = WALManager(wal_path)

    key_manager = KeyManager(node_id=node_id, wal_manager=wal)
    initial_pub, initial_priv = kem_provider.generate_keypair()
    key_manager.enroll_initial_key(getattr(kem_provider, "algorithm_name", "ML-KEM-768"), initial_pub, initial_priv)

    revocation_coord = RevocationCoordinator(node_id=node_id)
    messaging = SecureMessaging(node_id=node_id)

    audit_path = os.path.join(data_dir, f"{node_id}_audit.log")
    audit_logger = AuditLogger(node_id=node_id, log_file_path=audit_path, signer=sig_provider)

    rule_engine = ContextRuleEngine()
    lateral_graph = LateralMovementGraph()

    # In-memory state tracking
    enrolled_nodes: Dict[str, Dict[str, Any]] = {}
    recent_alerts: List[Dict[str, Any]] = []
    peer_shared_keys: Dict[str, bytes] = {}
    peer_public_keys: Dict[str, bytes] = {}
    message_stats = {"sent": 0, "received": 0, "rejected": 0}

    # Attach components for programmatic access
    app.state.node_id = node_id
    app.state.key_manager = key_manager
    app.state.audit_logger = audit_logger
    app.state.messaging = messaging
    app.state.peer_shared_keys = peer_shared_keys
    app.state.peer_public_keys = peer_public_keys
    app.state.enrolled_nodes = enrolled_nodes

    @app.get("/health")
    def health_check():
        active = key_manager.get_active_key()
        return {
            "status": "healthy",
            "node_id": node_id,
            "active_key_id": active.key_id if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "timestamp_ns": time.time_ns(),
        }

    @app.post("/enroll")
    def enroll_device(req: EnrollRequest):
        enrolled_nodes[req.node_id] = {
            "node_id": req.node_id,
            "public_key_b64": req.public_key_b64,
            "role": req.role,
            "enrolled_at": time.time_ns(),
        }
        rec = audit_logger.log_event(
            service=node_id,
            action="DEVICE_ENROLLMENT",
            subject=req.node_id,
            resource="/enroll",
            status="SUCCESS",
            metadata={"role": req.role},
        )
        return {
            "status": "enrolled",
            "node_id": req.node_id,
            "role": req.role,
            "audit_sequence": getattr(rec, "sequence", 0),
        }

    @app.post("/send")
    def send_message(req: SendRequest):
        sender_id = node_id
        recipient_id = req.recipient_id

        # Check lateral graph
        viol = lateral_graph.check_call(sender_id, recipient_id, "SEND_MESSAGE")
        if viol:
            recent_alerts.append({
                "alert_id": f"alert-lateral-{time.time_ns()}",
                "rule_name": "LATERAL_MOVEMENT_VIOLATION",
                "severity": "HIGH",
                "description": getattr(viol, "reason", "Lateral movement policy violation"),
                "evidence": getattr(viol, "to_dict", lambda: {})(),
            })
            audit_logger.log_event(
                service=node_id,
                action="LATERAL_SEND_BLOCKED",
                subject=sender_id,
                resource=f"node://{recipient_id}",
                status="DENIED",
                metadata={"reason": "unauthorized lateral path"},
            )
            raise HTTPException(status_code=403, detail="Lateral movement violation: unauthorized call path")

        # Prepare envelope
        shared_key = peer_shared_keys.get(recipient_id, b"DEFAULT-DEMO-SHARED-KEY-32BYTES!")
        plaintext_bytes = json.dumps(req.payload, sort_keys=True).encode("utf-8")

        envelope = messaging.pack_envelope(
            sender_id=sender_id,
            recipient_id=recipient_id,
            plaintext=plaintext_bytes,
            shared_key=shared_key,
            signer=sig_provider,
        )

        # Normalize envelope properties for schemas/envelope.schema.json
        if "sequence_number" in envelope and "seq_num" not in envelope:
            envelope["seq_num"] = envelope["sequence_number"]
        if "additional_authenticated_data" in envelope and "associated_data" not in envelope:
            envelope["associated_data"] = envelope["additional_authenticated_data"]

        message_stats["sent"] += 1
        audit_logger.log_event(
            service=node_id,
            action="MESSAGE_DISPATCHED",
            subject=sender_id,
            resource=f"node://{recipient_id}",
            status="SUCCESS",
            metadata={"message_id": envelope.get("message_id")},
        )

        return {"status": "dispatched", "envelope": envelope}

    @app.post("/receive")
    def receive_message(envelope: Dict[str, Any]):
        sender_id = envelope.get("sender_id", "unknown")

        # 1. Lateral movement check
        viol = lateral_graph.check_call(sender_id, node_id, "RECEIVE_MESSAGE")
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
            audit_logger.log_event(
                service=node_id,
                action="LATERAL_RECEIVE_BLOCKED",
                subject=sender_id,
                resource="/receive",
                status="DENIED",
                metadata={"error": alert_obj["description"]},
            )
            raise HTTPException(status_code=403, detail=alert_obj["description"])

        # 2. Recipient binding & signature & anti-replay verification
        shared_key = peer_shared_keys.get(sender_id, b"DEFAULT-DEMO-SHARED-KEY-32BYTES!")
        sender_pubkey = peer_public_keys.get(sender_id, b"DEFAULT-PUBKEY-32BYTES-MOCK!!!!")

        # Ensure compatibility with envelope schema fields
        if "seq_num" in envelope and "sequence_number" not in envelope:
            envelope["sequence_number"] = envelope["seq_num"]
        if "associated_data" in envelope and "additional_authenticated_data" not in envelope:
            envelope["additional_authenticated_data"] = envelope["associated_data"]

        try:
            plaintext = messaging.unpack_envelope(
                envelope=envelope,
                shared_key=shared_key,
                verifier_sig=sig_provider,
                sender_public_key=sender_pubkey,
            )
            message_stats["received"] += 1
            rec = audit_logger.log_event(
                service=node_id,
                action="MESSAGE_RECEIVED",
                subject=sender_id,
                resource="/receive",
                status="SUCCESS",
                metadata={"message_id": envelope.get("message_id")},
            )
            try:
                dec_payload = json.loads(plaintext.decode("utf-8"))
            except Exception:
                dec_payload = {"raw": base64.b64encode(plaintext).decode()}

            return {
                "status": "delivered",
                "message_id": envelope.get("message_id"),
                "sequence": getattr(rec, "sequence", 0),
                "record_hash": getattr(rec, "entry_hash", getattr(rec, "record_hash", "")),
                "payload": dec_payload,
            }

        except (RecipientMismatchError, ReplayAttackError, MessageTamperedError) as e:
            message_stats["rejected"] += 1
            err_type = type(e).__name__
            audit_logger.log_event(
                service=node_id,
                action=f"{err_type.upper()}_BLOCKED",
                subject=sender_id,
                resource="/receive",
                status="DENIED",
                metadata={"error": str(e), "envelope": envelope},
            )
            alerts = rule_engine.evaluate_event({
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
            audit_logger.log_event(
                service=node_id,
                action="ROTATE_KEY_DENIED",
                subject=req.requested_by,
                resource="/keys/rotate",
                status="DENIED",
                metadata={"role": req.role},
            )
            raise HTTPException(status_code=403, detail="Unauthorized: admin role required for key rotation")

        new_pub, new_priv = kem_provider.generate_keypair()
        new_rec, old_rec = key_manager.rotate_key(new_pub, new_priv)
        audit_logger.log_event(
            service=node_id,
            action="ROTATE_KEY_SUCCESS",
            subject=req.requested_by,
            resource="/keys/rotate",
            status="SUCCESS",
            metadata={"new_key_id": new_rec.key_id, "old_key_id": getattr(old_rec, "key_id", None)},
        )
        return {
            "status": "rotated",
            "active_key": new_rec.to_dict() if hasattr(new_rec, "to_dict") else {"key_id": new_rec.key_id},
            "grace_key": old_rec.to_dict() if (old_rec and hasattr(old_rec, "to_dict")) else None,
        }

    @app.post("/keys/revoke")
    def revoke_key(req: RevokeKeyRequest):
        if req.role != "admin":
            raise HTTPException(status_code=403, detail="Unauthorized: admin role required for revocation")

        target = req.target_node_id or node_id
        rev_ev = revocation_coord.create_revocation(req.key_id, target, req.reason, signer=sig_provider)
        key_manager.revoke_key(req.key_id, req.reason)

        audit_logger.log_event(
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
            "revocation": rev_ev.to_dict() if hasattr(rev_ev, "to_dict") else {"key_id": req.key_id},
        }

    @app.get("/logs/verify")
    def verify_logs():
        verifier = AuditLogVerifier()
        result = verifier.verify_file(audit_logger.log_file_path)
        res_dict = result.to_dict() if hasattr(result, "to_dict") else {"is_valid": getattr(result, "is_valid", False)}
        if not getattr(result, "is_valid", False):
            raise HTTPException(status_code=409, detail=res_dict)
        return res_dict

    @app.get("/metrics")
    def node_metrics():
        active = key_manager.get_active_key()
        return {
            "node_id": node_id,
            "status": "healthy",
            "active_key_id": active.key_id if active else None,
            "active_key_version": getattr(active, "version", 1) if active else 0,
            "messages": message_stats,
            "alerts_count": len(recent_alerts),
            "alerts": recent_alerts[-10:],
            "enrolled_nodes_count": len(enrolled_nodes),
            "uptime_seconds": time.monotonic(),
        }

    return app


class NodeServer:
    """Threaded/Programmatic wrapper around the FastAPI Node Server."""

    def __init__(self, node_id: str = "node-a", host: str = "0.0.0.0", port: int = 8001, data_dir: str = "/tmp/tbv_data"):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.data_dir = data_dir
        self.app = create_app(node_id=node_id, data_dir=data_dir)
        self.server_config = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="warning")
        self.server = uvicorn.Server(self.server_config)
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = False):
        if blocking:
            self.server.run()
        else:
            self._thread = threading.Thread(target=self.server.run, daemon=True)
            self._thread.start()
            # Wait briefly for socket binding
            time.sleep(0.5)

    def stop(self):
        self.server.should_exit = True
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)


# Default app instance
app = create_app(
    node_id=os.environ.get("NODE_ID", "node-a"),
    data_dir=os.environ.get("DATA_DIR", "/tmp/tbv_data")
)


if __name__ == "__main__":
    node_id = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("NODE_ID", "node-a")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else int(os.environ.get("PORT", 8001))
    server_app = create_app(node_id=node_id)
    print(f"🚀 Starting Trust-But-Verify Node [{node_id}] on http://0.0.0.0:{port}")
    uvicorn.run(server_app, host="0.0.0.0", port=port, log_level="warning")
