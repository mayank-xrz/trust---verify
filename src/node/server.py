"""Mock Service Node exposing protected endpoints with PQC verification & audit logging."""

from __future__ import annotations
import base64
import json
import os
import sys
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict, Any, Optional

from ..crypto.pqc_kem import MLKEMKeyExchange
from ..crypto.pqc_sig import MLDSASignature
from ..crypto.messaging import SecureMessaging, RecipientMismatchError, ReplayAttackError, MessageTamperedError
from ..identity.key_manager import KeyManager
from ..identity.revocation import RevocationCoordinator
from ..identity.recovery import WALManager
from ..audit.logger import AuditLogger
from ..audit.verifier import AuditLogVerifier
from ..detector.clock_sync import ClockSyncBuffer
from ..detector.rules import ContextRuleEngine
from ..detector.graph_lateral import LateralMovementGraph


class NodeServerRequestHandler(BaseHTTPRequestHandler):
    server: "NodeServer"  # type hint

    def do_GET(self):
        if self.path == "/health":
            active_key = self.server.key_manager.get_active_key()
            self._send_json(200, {
                "status": "healthy",
                "node_id": self.server.node_id,
                "active_key_id": active_key.key_id if active_key else None,
                "active_key_version": active_key.version if active_key else 0,
                "timestamp_ns": time.time_ns(),
            })
        elif self.path == "/api/v1/alerts":
            alerts = [a.to_dict() for a in self.server.recent_alerts]
            self._send_json(200, {"alerts": alerts, "count": len(alerts)})
        elif self.path == "/api/v1/log/verify":
            verifier = AuditLogVerifier()
            res = verifier.verify_file(self.server.audit_logger.log_file_path)
            self._send_json(200 if res.is_valid else 409, res.to_dict())
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body_bytes = self.rfile.read(content_len) if content_len > 0 else b"{}"

        try:
            payload = json.loads(body_bytes.decode("utf-8"))
        except Exception as e:
            self._send_json(400, {"error": f"Invalid JSON payload: {e}"})
            return

        if self.path == "/api/v1/message":
            self._handle_secure_message(payload)
        elif self.path == "/api/v1/keys/rotate":
            self._handle_key_rotate(payload)
        elif self.path == "/api/v1/keys/revoke":
            self._handle_key_revoke(payload)
        else:
            self._send_json(404, {"error": "Endpoint not found"})

    def _handle_secure_message(self, envelope: Dict[str, Any]):
        sender_id = envelope.get("sender_id", "unknown")
        action = "RECEIVE_SECURE_MESSAGE"

        try:
            # Check service-to-service graph violation
            viol = self.server.lateral_graph.check_call(sender_id, self.server.node_id, action)
            if viol:
                alert = {
                    "alert_id": f"alert-lateral-{time.time_ns()}",
                    "rule_name": "LATERAL_MOVEMENT_VIOLATION",
                    "severity": "HIGH",
                    "timestamp_ns": time.time_ns(),
                    "subject": sender_id,
                    "service": self.server.node_id,
                    "resource": "/api/v1/message",
                    "description": viol.reason,
                    "evidence": viol.to_dict(),
                }
                self.server.audit_logger.log_event(
                    service=self.server.node_id,
                    action="LATERAL_HOP_BLOCKED",
                    subject=sender_id,
                    resource="/api/v1/message",
                    status="DENIED",
                    metadata={"violation": viol.to_dict()},
                    client_ip=self.client_address[0],
                )
                self._send_json(403, {"error": viol.reason})
                return

            # Lookup peer public key & shared key
            shared_key = self.server.peer_shared_keys.get(sender_id)
            sender_pubkey = self.server.peer_public_keys.get(sender_id)

            if not shared_key or not sender_pubkey:
                # Mock default if not pre-shared for demo
                shared_key = b"DEFAULT-DEMO-SHARED-KEY-32BYTES!"
                sender_pubkey = b"DEFAULT-PUBKEY-32BYTES-MOCK!!!!"

            # Verify envelope & anti-replay
            plaintext = self.server.secure_messaging.unpack_envelope(
                envelope=envelope,
                shared_key=shared_key,
                verifier_sig=self.server.sig_provider,
                sender_public_key=sender_pubkey,
            )

            # Log success in tamper-evident chain
            rec = self.server.audit_logger.log_event(
                service=self.server.node_id,
                action=action,
                subject=sender_id,
                resource="/api/v1/message",
                status="SUCCESS",
                metadata={"message_id": envelope.get("message_id"), "seq": envelope.get("sequence_number")},
                client_ip=self.client_address[0],
            )

            self._send_json(200, {
                "status": "delivered",
                "message_id": envelope.get("message_id"),
                "sequence": rec.sequence,
                "entry_hash": rec.entry_hash,
            })

        except (RecipientMismatchError, ReplayAttackError, MessageTamperedError) as e:
            err_type = type(e).__name__
            self.server.audit_logger.log_event(
                service=self.server.node_id,
                action=f"{err_type.upper()}_BLOCKED",
                subject=sender_id,
                resource="/api/v1/message",
                status="DENIED",
                metadata={"error": str(e), "envelope": envelope},
                client_ip=self.client_address[0],
            )
            # Pass to detector engine
            alerts = self.server.rule_engine.evaluate_event({
                "event_id": envelope.get("message_id", ""),
                "timestamp_ns": time.time_ns(),
                "subject": sender_id,
                "service": self.server.node_id,
                "resource": "/api/v1/message",
                "status": "DENIED",
                "metadata": {"error": str(e)},
            })
            self.server.recent_alerts.extend(alerts)
            self._send_json(400, {"error": str(e), "type": err_type})

        except Exception as e:
            self._send_json(500, {"error": f"Internal node error: {e}"})

    def _handle_key_rotate(self, payload: Dict[str, Any]):
        role = payload.get("role", "user")
        if role != "admin":
            event = {
                "event_id": f"evt-{time.time_ns()}",
                "timestamp_ns": time.time_ns(),
                "subject": payload.get("requested_by", "anonymous"),
                "service": self.server.node_id,
                "resource": "/api/v1/keys/rotate",
                "action": "ROTATE_KEY",
                "status": "DENIED",
                "metadata": {"role": role},
            }
            alerts = self.server.rule_engine.evaluate_event(event)
            self.server.recent_alerts.extend(alerts)
            self.server.audit_logger.log_event(
                service=self.server.node_id,
                action="ROTATE_KEY_ATTEMPT_DENIED",
                subject=payload.get("requested_by", "anonymous"),
                resource="/api/v1/keys/rotate",
                status="DENIED",
                metadata={"reason": "unauthorized", "role": role},
            )
            self._send_json(403, {"error": "Unauthorized: admin role required"})
            return

        new_pub, new_priv = self.server.kem_provider.generate_keypair()
        new_rec, old_rec = self.server.key_manager.rotate_key(new_pub, new_priv)
        self.server.audit_logger.log_event(
            service=self.server.node_id,
            action="ROTATE_KEY_SUCCESS",
            subject=payload.get("requested_by", "admin"),
            resource="/api/v1/keys/rotate",
            status="SUCCESS",
            metadata={"new_key_id": new_rec.key_id, "old_key_id": old_rec.key_id if old_rec else None},
        )
        self._send_json(200, {
            "status": "key_rotated",
            "active_key": new_rec.to_dict(),
            "grace_period_key": old_rec.to_dict() if old_rec else None,
        })

    def _handle_key_revoke(self, payload: Dict[str, Any]):
        key_id = payload.get("key_id", "")
        reason = payload.get("reason", "manual revocation")
        target_node = payload.get("target_node_id", self.server.node_id)

        rev_event = self.server.revocation_coord.create_revocation(
            key_id=key_id,
            target_node_id=target_node,
            reason=reason,
            signer=self.server.sig_provider,
        )
        self.server.key_manager.revoke_key(key_id, reason)

        self.server.audit_logger.log_event(
            service=self.server.node_id,
            action="REVOKE_KEY",
            subject=payload.get("requested_by", "operator"),
            resource=f"/keys/{key_id}",
            status="SUCCESS",
            metadata={"revocation_id": rev_event.revocation_id, "reason": reason},
        )

        self._send_json(200, {
            "status": "revoked",
            "revocation": rev_event.to_dict(),
        })

    def _send_json(self, status_code: int, data: Dict[str, Any]):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Suppress noisy default HTTP server console logging
        pass


class NodeServer:
    """Multi-node capable service node instance."""

    def __init__(
        self,
        node_id: str,
        host: str = "127.0.0.1",
        port: int = 8080,
        data_dir: str = "/tmp/tbv_data",
    ):
        self.node_id = node_id
        self.host = host
        self.port = port
        self.data_dir = data_dir
        os.makedirs(data_dir, exist_ok=True)

        # Components
        self.kem_provider = MLKEMKeyExchange()
        self.sig_provider = MLDSASignature()
        self.sig_pub, self.sig_priv = self.sig_provider.generate_keypair()

        wal_path = os.path.join(data_dir, f"{node_id}_wal.log")
        self.wal_manager = WALManager(wal_path)

        self.key_manager = KeyManager(node_id=node_id, wal_manager=self.wal_manager)
        kem_pub, kem_priv = self.kem_provider.generate_keypair()
        self.key_manager.enroll_initial_key(self.kem_provider.algorithm_name, kem_pub, kem_priv)

        self.revocation_coord = RevocationCoordinator(node_id=node_id)
        self.secure_messaging = SecureMessaging(node_id=node_id)

        audit_path = os.path.join(data_dir, f"{node_id}_audit.log")
        self.audit_logger = AuditLogger(node_id=node_id, log_file_path=audit_path, signer=self.sig_provider)

        self.clock_buffer = ClockSyncBuffer()
        self.rule_engine = ContextRuleEngine()
        self.lateral_graph = LateralMovementGraph()

        self.peer_shared_keys: Dict[str, bytes] = {}
        self.peer_public_keys: Dict[str, bytes] = {}
        self.recent_alerts = []

        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self, blocking: bool = False):
        """Starts node HTTP server."""
        self._httpd = HTTPServer((self.host, self.port), NodeServerRequestHandler)
        # Bind reference to self on the server handler
        self._httpd.node_id = self.node_id
        NodeServerRequestHandler.server = self

        if blocking:
            self._httpd.serve_forever()
        else:
            self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
            self._thread.start()

    def stop(self):
        """Stops node HTTP server."""
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


if __name__ == "__main__":
    node_id = sys.argv[1] if len(sys.argv) > 1 else "node-1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    server = NodeServer(node_id=node_id, port=port)
    print(f"Starting Node {node_id} on http://127.0.0.1:{port}...")
    server.start(blocking=True)
