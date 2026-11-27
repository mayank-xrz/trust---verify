"""Operator Dashboard & CLI for Multi-Node Health, Key Lifecycle, Audit, and Alerts (P4-10).

Interacts with running sandbox nodes (node-a, node-b, node-c, detector).

Commands:
- status: inspects health, active key versions, and metrics across all nodes.
- rotate --identity <id>: initiates atomic rotation with grace period.
- revoke --key-id <id>: initiates cross-node revocation broadcast and measures latency.
- verify-logs: verifies cryptographic log hash chains on all nodes.
- alerts: fetches explainable detection alerts from detector/nodes.
"""

from __future__ import annotations

import argparse
import json
import os
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

DEFAULT_NODES = {
    "node-a": "http://localhost:8001",
    "node-b": "http://localhost:8002",
    "node-c": "http://localhost:8003",
    "detector": "http://localhost:8005",
}


def http_request(
    url: str, method: str = "GET", payload: Optional[dict] = None, timeout: float = 3.0,
    *, token: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    try:
        data_bytes = json.dumps(payload).encode("utf-8") if payload else None
        req = urllib.request.Request(
            url,
            data=data_bytes,
            headers={"Content-Type": "application/json"},
            method=method,
        )
        if token:
            req.add_unredirected_header("Authorization", f"Bearer {token}")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"error": str(e)}
    except Exception as e:
        return 503, {"error": str(e), "offline": True}


class OperatorCLI:
    """Operator CLI implementation."""

    def __init__(self, nodes: Optional[Dict[str, str]] = None):
        self.nodes = nodes or DEFAULT_NODES

    def status(self) -> Dict[str, Any]:
        print("=" * 70)
        print("🖥️  TRUST-BUT-VERIFY CLUSTER STATUS")
        print("=" * 70)
        results = {}

        for nid, base_url in self.nodes.items():
            code, data = http_request(f"{base_url}/health")
            if code == 200:
                print(f"🟢 [{nid}] Online | Key: {data.get('active_key_id', 'N/A')} (v{data.get('active_key_version', 1)}) | Uptime: {data.get('uptime_seconds', 0)}s")
                results[nid] = {"online": True, **data}
            else:
                print(f"🔴 [{nid}] Offline or Error ({base_url}) - HTTP {code}")
                results[nid] = {"online": False, "status": "offline", "error": data}

        print("=" * 70)
        return results

    def rotate(self, identity: str = "node-a") -> Dict[str, Any]:
        base_url = self.nodes.get(identity)
        if base_url is None:
            print(f"Unknown node '{identity}'")
            return {"error": "Unknown node"}
        print(f"🔄 Triggering atomic key rotation on '{identity}' ({base_url})...")

        code, data = http_request(
            f"{base_url}/keys/rotate",
            method="POST",
            token=os.environ.get("DEMO_OPERATOR_TOKEN"),
        )

        if code == 200:
            active = data.get("active_key", {})
            grace = data.get("grace_key", {})
            print("✅ Key Rotated Successfully!")
            print(f"   Active Key ID: {active.get('key_id')} (v{active.get('version', 'N/A')})")
            if grace:
                print(f"   Grace Key ID:  {grace.get('key_id')} | Cutoff: {grace.get('grace_cutoff', 'N/A')}")
            return data
        else:
            print(f"❌ Key Rotation Failed (HTTP {code}): {data.get('detail', data)}")
            return {"error": data, "code": code}

    def revoke(
        self, key_id: str, reason: str = "Manual compromise revocation", identity: Optional[str] = None,
    ) -> Dict[str, Any]:
        print(f"🚫 Initiating cross-node key revocation for '{key_id}'...")
        # Broadcast via primary authority / node-a
        identity = identity or ("key-authority" if "key-authority" in self.nodes else "node-a")
        base_url = self.nodes.get(identity)
        if base_url is None:
            print(f"Unknown node '{identity}'")
            return {"error": "Unknown node"}

        code, data = http_request(
            f"{base_url}/keys/revoke",
            method="POST",
            payload={"key_id": key_id, "reason": reason},
            token=os.environ.get("DEMO_OPERATOR_TOKEN"),
        )

        if code == 200:
            print(f"✅ Key '{key_id}' Revoked!")
            print(f"   Propagation Latency: {data.get('propagation_latency_ms', 0)} ms")
            return data
        else:
            print(f"❌ Revocation Failed (HTTP {code}): {data.get('detail', data)}")
            return {"error": data, "code": code}

    def verify_logs(self) -> Dict[str, Any]:
        print("=" * 70)
        print("🔍 VERIFYING AUDIT LOG HASH CHAINS ACROSS CLUSTER")
        print("=" * 70)
        results = {}

        for nid, base_url in self.nodes.items():
            if nid == "detector":
                continue
            code, data = http_request(f"{base_url}/logs/verify", token=os.environ.get("DEMO_OPERATOR_TOKEN"))
            if code == 200 and data.get("is_valid"):
                print(f"✅ [{nid}] Log Chain VALID ({data.get('total_records', 0)} records verified)")
                results[nid] = {"valid": True, **data}
            else:
                err = data.get("first_error") or data.get("detail", "Unknown failure")
                idx = data.get("tampered_index", "N/A")
                print(f"❌ [{nid}] Log Tampering Detected! Error: {err} (Tampered Index: {idx})")
                results[nid] = {"valid": False, "error": err, "tampered_index": idx}

        print("=" * 70)
        return results

    def alerts(self) -> List[Dict[str, Any]]:
        print("=" * 70)
        print("🚨 EXPLAINABLE DETECTION & PRIVILEGE ALERTS")
        print("=" * 70)
        all_alerts = []

        # Check detector and nodes for explainable alerts
        for nid, base_url in self.nodes.items():
            code, data = http_request(f"{base_url}/metrics", token=os.environ.get("DEMO_OPERATOR_TOKEN"))
            if code == 200:
                alerts = data.get("alerts", [])
                for a in alerts:
                    all_alerts.append({"node": nid, **a})

        if not all_alerts:
            print("  (Zero security alerts recorded. Cluster state clean.)")
        else:
            for a in all_alerts:
                sev = a.get("severity", "HIGH")
                rule = a.get("rule_name", "UNKNOWN_RULE")
                desc = a.get("description", "")
                src_node = a.get("node", "cluster")
                print(f"  • [{sev}] on {src_node} -> {rule}")
                print(f"    Details: {desc}")
                if a.get("subject"):
                    print(f"    Subject: {a['subject']}")
                if a.get("service"):
                    print(f"    Service: {a['service']}")
                if a.get("evidence"):
                    print(f"    Evidence: {json.dumps(a.get('evidence'))}")

        print("=" * 70)
        return all_alerts


def main():
    parser = argparse.ArgumentParser(description="Trust-But-Verify Operator CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # status
    subparsers.add_parser("status", help="Inspect health & key versions across all nodes")

    # rotate
    rotate_parser = subparsers.add_parser("rotate", help="Trigger key rotation on an identity node")
    rotate_parser.add_argument("--identity", default="node-a", help="Target node identity (default: node-a)")

    # revoke
    revoke_parser = subparsers.add_parser("revoke", help="Trigger cross-node revocation broadcast")
    revoke_parser.add_argument("--key-id", required=True, help="Key ID to revoke")
    revoke_parser.add_argument("--reason", default="Manual administrative revocation", help="Revocation reason")
    revoke_parser.add_argument("--identity", help="Node that owns the key (default: key authority or node-a)")

    # verify-logs
    subparsers.add_parser("verify-logs", help="Verify audit log hash chains across nodes")

    # alerts
    subparsers.add_parser("alerts", help="Fetch explainable detector alerts")

    args = parser.parse_args()
    cli = OperatorCLI()

    if args.command == "status":
        cli.status()
    elif args.command == "rotate":
        return int("error" in cli.rotate(identity=args.identity))
    elif args.command == "revoke":
        return int("error" in cli.revoke(key_id=args.key_id, reason=args.reason, identity=args.identity))
    elif args.command == "verify-logs":
        cli.verify_logs()
    elif args.command == "alerts":
        cli.alerts()


if __name__ == "__main__":
    raise SystemExit(main())
