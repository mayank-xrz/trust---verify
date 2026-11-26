"""Operator Dashboard & CLI for Alerts, Health, and Key Verification."""

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
        return e.code, json.loads(e.read().decode("utf-8"))
    except Exception as e:
        return 500, {"error": str(e)}


def cmd_status(args):
    code, data = fetch_url(f"http://{args.host}:{args.port}/health")
    if code == 200:
        print(f"🟢 [Node Online] ID: {data.get('node_id')} | Key: {data.get('active_key_id')} (v{data.get('active_key_version')})")
    else:
        print(f"🔴 [Node Offline or Error] HTTP {code}: {data}")


def cmd_alerts(args):
    code, data = fetch_url(f"http://{args.host}:{args.port}/api/v1/alerts")
    alerts = data.get("alerts", [])
    print(f"📋 Security Alerts ({len(alerts)}):")
    for a in alerts:
        print(f"  - [{a.get('severity')}] {a.get('rule_name')}: {a.get('description')}")


def cmd_verify_log(args):
    code, data = fetch_url(f"http://{args.host}:{args.port}/api/v1/log/verify")
    if code == 200 and data.get("is_valid"):
        print(f"✅ Audit Log Valid! Total records: {data.get('total_records')} (Checkpoints: {data.get('verified_checkpoints')})")
    else:
        print(f"❌ Verification Failed! Error: {data.get('first_error')}")


def cmd_rotate(args):
    payload = {"role": args.role, "requested_by": "operator"}
    code, data = fetch_url(f"http://{args.host}:{args.port}/api/v1/keys/rotate", method="POST", data=payload)
    if code == 200:
        print(f"🔄 Key Rotated! New Active Key: {data.get('active_key', {}).get('key_id')}")
    else:
        print(f"❌ Rotation Failed (HTTP {code}): {data.get('error')}")


def main():
    parser = argparse.ArgumentParser(description="Trust-But-Verify Operator CLI")
    parser.add_argument("--host", default="127.0.0.1", help="Node hostname")
    parser.add_argument("--port", type=int, default=8080, help="Node port")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser("status", help="Check node status")
    subparsers.add_parser("alerts", help="Fetch security alerts")
    subparsers.add_parser("verify-log", help="Verify node audit log chain")

    p_rotate = subparsers.add_parser("rotate-key", help="Rotate active cryptographic key")
    p_rotate.add_argument("--role", default="admin", help="Role for authorization (admin/user)")

    args = parser.parse_args()

    if args.command == "status":
        cmd_status(args)
    elif args.command == "alerts":
        cmd_alerts(args)
    elif args.command == "verify-log":
        cmd_verify_log(args)
    elif args.command == "rotate-key":
        cmd_rotate(args)


if __name__ == "__main__":
    main()
