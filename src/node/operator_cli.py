"""Operator Dashboard & CLI for Alerts, Health, Key Verification, and Lateral Movement."""

from __future__ import annotations
import argparse
import json
import sys
import urllib.request
import urllib.error


def fetch_url(url: str, method: str = "GET", data: dict = None):
    try:
        req = urllib.request.Request(url, method=method)
        req.add_header("Content-Type", "application/json")
        body = json.dumps(data).encode("utf-8") if data else None
        with urllib.request.urlopen(req, data=body, timeout=5) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 500, {"error": str(e)}


class OperatorCLI:
    """Programmatic and command-line Operator Interface."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8001):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"

    def status(self) -> dict:
        code, data = fetch_url(f"{self.base_url}/health")
        if code == 200:
            print(f"🟢 [Node Online] ID: {data.get('node_id')} | Active Key: {data.get('active_key_id')} (v{data.get('active_key_version')})")
            m_code, m_data = fetch_url(f"{self.base_url}/metrics")
            if m_code == 200:
                msgs = m_data.get("messages", {})
                print(f"   Messages: {msgs.get('received', 0)} received, {msgs.get('sent', 0)} sent, {msgs.get('rejected', 0)} rejected")
                print(f"   Alerts: {m_data.get('alerts_count', 0)} recorded | Enrolled peers: {m_data.get('enrolled_nodes_count', 0)}")
                return {**data, "metrics": m_data}
            return data
        else:
            print(f"🔴 [Node Offline or Error] HTTP {code}: {data}")
            return {"error": data, "code": code}

    def keys(self) -> dict:
        code, data = fetch_url(f"{self.base_url}/metrics")
        if code == 200:
            print(f"🔑 Key State for Node '{data.get('node_id')}':")
            print(f"   Active Key ID: {data.get('active_key_id')} (Version {data.get('active_key_version')})")
            return data
        else:
            print(f"❌ Failed to fetch key state: HTTP {code}")
            return {"error": data, "code": code}

    def alerts(self) -> list:
        code, data = fetch_url(f"{self.base_url}/metrics")
        alerts = data.get("alerts", [])
        print(f"📋 Explainable Security Alerts ({len(alerts)}):")
        if not alerts:
            print("   (No security alerts recorded. System clean.)")
        for a in alerts:
            print(f"  - [{a.get('severity', 'HIGH')}] {a.get('rule_name')}: {a.get('description')}")
            if a.get("evidence"):
                print(f"    Evidence: {json.dumps(a.get('evidence'))}")
        return alerts

    def verify_log(self) -> dict:
        code, data = fetch_url(f"{self.base_url}/logs/verify")
        if code == 200 and data.get("is_valid"):
            print(f"✅ Audit Log Valid! Total records: {data.get('total_records')} (Checkpoints: {data.get('verified_checkpoints', 0)})")
        else:
            print(f"❌ Verification Failed! Error: {data.get('first_error', data.get('detail'))}")
        return data

    def rotate(self, role: str = "admin") -> dict:
        payload = {"role": role, "requested_by": "operator_cli"}
        code, data = fetch_url(f"{self.base_url}/keys/rotate", method="POST", data=payload)
        if code == 200:
            print(f"🔄 Key Rotated! New Active Key: {data.get('active_key', {}).get('key_id')}")
            if data.get("grace_key"):
                print(f"   Previous key moved to grace period: {data.get('grace_key', {}).get('key_id')}")
        else:
            print(f"❌ Rotation Failed (HTTP {code}): {data.get('detail', data.get('error'))}")
        return data

    def revoke(self, key_id: str, reason: str = "Manual administrative revocation", role: str = "admin") -> dict:
        payload = {"key_id": key_id, "reason": reason, "role": role}
        code, data = fetch_url(f"{self.base_url}/keys/revoke", method="POST", data=payload)
        if code == 200:
            print(f"🚫 Key Revoked! Key ID: {key_id} | Reason: {reason}")
        else:
            print(f"❌ Revocation Failed (HTTP {code}): {data.get('detail', data.get('error'))}")
        return data


def main():
    parser = argparse.ArgumentParser(description="Trust-But-Verify Operator CLI")
    parser.add_argument("--host", default="127.0.0.1", help="Node hostname (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8001, help="Node port (default: 8001)")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Inspect node health and metrics")
    subparsers.add_parser("keys", help="Inspect active and revoked keys")
    subparsers.add_parser("alerts", help="Print explainable lateral-movement and security alerts")
    subparsers.add_parser("verify-log", help="Verify node hash-chained audit log")

    p_rotate = subparsers.add_parser("rotate", help="Trigger atomic key rotation with grace period")
    p_rotate.add_argument("--role", default="admin", help="Role for authorization (admin/user)")

    p_revoke = subparsers.add_parser("revoke", help="Broadcast key revocation across cluster")
    p_revoke.add_argument("key_id", help="ID of key to revoke")
    p_revoke.add_argument("--reason", default="Manual administrative revocation", help="Revocation reason")
    p_revoke.add_argument("--role", default="admin", help="Role for authorization (admin/user)")

    args = parser.parse_args()
    cli = OperatorCLI(host=args.host, port=args.port)

    if args.command == "status":
        cli.status()
    elif args.command == "keys":
        cli.keys()
    elif args.command == "alerts":
        cli.alerts()
    elif args.command == "verify-log":
        cli.verify_log()
    elif args.command == "rotate":
        cli.rotate(role=args.role)
    elif args.command == "revoke":
        cli.revoke(key_id=args.key_id, reason=args.reason, role=args.role)


if __name__ == "__main__":
    main()
