#!/usr/bin/env bash
# ==============================================================================
# Trust-But-Verify: Deterministic 5-Minute End-to-End Walkthrough for Judges (P4-15)
#
# Steps:
# 1. Boot 3-node sandbox & check operator_cli status
# 2. Enroll identities & send authenticated PQC envelope
# 3. Trigger atomic key rotation: prove grace period & post-cutoff rejection
# 4. Revoke a recipient key, confirm another node stays reachable, and replace it
# 5. Demonstrate crash recovery (WAL) & damaged backup rejection
# 6. Verify audit log hash chains & inspect explainable detector alerts
# ==============================================================================

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
requested_python="${PYTHON:-python3}"
if ! demo_python="$(command -v -- "$requested_python")" || [ ! -x "$demo_python" ]; then
    echo "ERROR: Python interpreter '$requested_python' not found." >&2
    exit 1
fi
export DEMO_SANDBOX_ENABLED=1
export PYTHONPATH="$REPO_ROOT:${PYTHONPATH:-}"
export DEMO_GRACE_SECONDS="${DEMO_GRACE_SECONDS:-2}"
if [[ ! "$DEMO_GRACE_SECONDS" =~ ^([2-9]|[1-9][0-9]|[12][0-9][0-9]|300)$ ]]; then
    echo "DEMO_GRACE_SECONDS must be an integer from 2 through 300." >&2
    exit 2
fi
for credential in DEMO_PEER_ENROLL_TOKEN DEMO_OPERATOR_TOKEN DEMO_REVOCATION_SYNC_TOKEN DEMO_RECIPIENT_TOKEN_a DEMO_RECIPIENT_TOKEN_b DEMO_RECIPIENT_TOKEN_c; do
    value="$("$demo_python" -c 'import secrets; print(secrets.token_urlsafe(32))')"
    export "$credential=$value"
done

TEMP_DATA_DIR="$(mktemp -d -t tbv_demo_XXXXXX)"
PIDS=()

cleanup() {
    echo ""
    echo "🧹 Cleaning up background node processes and demo temporary state..."
    for pid in "${PIDS[@]:-}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill -TERM "$pid" 2>/dev/null || true
        fi
    done
    wait 2>/dev/null || true
    rm -rf "$TEMP_DATA_DIR"
    echo "✅ Demo cleanup complete."
}
trap cleanup EXIT INT TERM

echo "======================================================================"
echo "🛡️  TRUST-BUT-VERIFY: ZERO-TRUST POST-QUANTUM DEFENSE & DETECTOR DEMO"
echo "======================================================================"
echo "📁 Sandbox Data Directory: $TEMP_DATA_DIR"

# ------------------------------------------------------------------------------
# STEP 1: Boot Sandbox Nodes & Check Operator Status
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "▶ STEP 1: Booting 3-Node Sandbox Cluster & Checking Status"
echo "======================================================================"

# Spin up node-a, node-b, node-c, and detector locally
for spec in "node-a:8001" "node-b:8002" "node-c:8003" "detector:8005"; do
    nid="${spec%%:*}"
    port="${spec##*:}"
    recipient_credential="DEMO_RECIPIENT_TOKEN_${nid#node-}"
    peers=""
    if [[ "$nid" == node-b ]]; then
        peers="http://127.0.0.1:8001,http://127.0.0.1:8003"
    fi
    DEMO_BIND_HOST=127.0.0.1 NODE_ID="$nid" PORT="$port" DATA_DIR="$TEMP_DATA_DIR/$nid" GRACE_PERIOD_SECONDS="$DEMO_GRACE_SECONDS" PEER_NODES="$peers" \
        DEMO_RECIPIENT_TOKEN="${!recipient_credential:-}" \
        "$demo_python" -m demo.node.server "$nid" "$port" > "$TEMP_DATA_DIR/${nid}.log" 2>&1 &
    pid=$!
    PIDS+=("$pid")
    echo "  🚀 Starting $nid on http://127.0.0.1:$port (pid: $pid)..."
done

# Wait for all nodes to become healthy
echo "  ⏳ Waiting for sandbox cluster to report healthy..."
for port in 8001 8002 8003 8005; do
    for attempt in {1..50}; do
        if curl --fail --silent --max-time 1 "http://127.0.0.1:${port}/health" >/dev/null; then
            break
        fi
        if [[ "$attempt" -eq 50 ]]; then
            echo "Node on port $port did not become healthy." >&2
            exit 1
        fi
        sleep 0.2
    done
done
echo "  ✅ All sandbox nodes online and responding."

# Operator CLI Status
echo ""
"$demo_python" -m demo.node.operator_cli status

# Steps 2-4 exercise the same protected transport before, during, and after key changes.
"$demo_python" - "$TEMP_DATA_DIR" <<'PYTHON'
import json
import sys
from pathlib import Path
import os
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

NODES = {f"node-{name}": f"http://127.0.0.1:{port}" for name, port in zip("abc", (8001, 8002, 8003))}
PEER_ENROLLMENT = {"Authorization": f"Bearer {os.environ['DEMO_PEER_ENROLL_TOKEN']}"}
OPERATOR = {"Authorization": f"Bearer {os.environ['DEMO_OPERATOR_TOKEN']}"}


def call(node, path, body=None, headers=None):
    request = Request(
        NODES[node] + path,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urlopen(request, timeout=5) as response:
        return json.load(response)


def enroll(local_node, peer):
    bundle = call(peer, "/keys/public")
    call(local_node, "/peers", bundle, PEER_ENROLLMENT)
    return bundle


def send(recipient, payload, sender="node-a"):
    return call(sender, "/send", {
        "target_node_url": NODES[recipient],
        "recipient_id": recipient,
        "payload": payload,
    }, OPERATOR)["envelope"]


def expect_delivery(recipient, envelope, payload):
    receipt = call(recipient, "/receive", envelope)
    if "payload" in receipt or receipt["status"] != "delivered":
        raise RuntimeError(f"Unexpected delivery receipt from {recipient}")
    token = os.environ[f"DEMO_RECIPIENT_TOKEN_{recipient[-1]}"]
    result = call(recipient, f"/inbox/{receipt['receipt_id']}", headers={"Authorization": f"Bearer {token}"})
    if result["payload"] != payload:
        raise RuntimeError(f"Unexpected payload delivered on {recipient}")


def expect_denial(recipient, envelope, reason):
    try:
        call(recipient, "/receive", envelope)
    except HTTPError as exc:
        detail = json.load(exc).get("detail")
        if exc.code == 400 and detail == reason:
            return
        raise RuntimeError(f"{recipient} returned {exc.code}: {detail}") from exc
    raise RuntimeError(f"{recipient} accepted a message that should have been denied")


print("\n▶ STEP 2: Enroll peer public keys and deliver protected messages")
for peer in ("node-b", "node-c"):
    enroll("node-a", peer)
    enroll(peer, "node-a")
    payload = {"action": "TRANSFER", "recipient": peer, "amount": 100}
    expect_delivery(peer, send(peer, payload), payload)
    print(f"  {peer} accepted its authenticated message.")

print("\n▶ STEP 3: Rotate node-b's recipient key and verify grace and hard cutoff")
grace_payload = {"message": "In flight before rotation"}
grace = send("node-b", grace_payload)
late = send("node-b", {"message": "First delivery after cutoff"})
rotation = call("node-b", "/keys/rotate", {}, OPERATOR)
grace_key = rotation["grace_key"]
assert grace_key["key_id"] == grace["key_id"]
# The API truncates the server's cutoff to whole Unix seconds.
cutoff_check = grace_key["grace_period_cutoff"] + 1
expect_delivery("node-b", grace, grace_payload)
bundle = enroll("node-a", "node-b")
assert bundle["kem_key_id"] != grace["key_id"]
current = {"message": "Delivered with the new key"}
expect_delivery("node-b", send("node-b", current), current)
while (remaining := cutoff_check - time.time()) > 0:
    time.sleep(remaining)
expect_denial("node-b", late, "Recipient key is expired")
print(f"  Old key accepted during {os.environ['DEMO_GRACE_SECONDS']} s grace and rejected after cutoff. New key delivered during grace.")

print("\n▶ STEP 4: Verify receiver denial, durable peer application, and unaffected traffic")
enroll("node-c", "node-b")
in_flight = send("node-b", {"message": "First delivery after revocation"})
started = time.perf_counter()
result = call("node-b", "/keys/revoke", {"key_id": in_flight["key_id"]}, OPERATOR)
receipts = {receipt["node_id"]: receipt for receipt in result["peer_receipts"]}
assert result["peer_failures"] == 0 and set(receipts) == {"node-a", "node-c"}, result
expect_denial("node-b", in_flight, "Recipient key is revoked")
elapsed = (time.perf_counter() - started) * 1000
print(f"  node-b denied first delivery under the revoked key (observed after {elapsed:.2f} ms).")
print(f"  Operator request to peer acknowledgements: {result['propagation_latency_ms']:.2f} ms.")
for peer, receipt in sorted(receipts.items()):
    try:
        send("node-b", {"message": "New send after revocation"}, sender=peer)
    except HTTPError as exc:
        assert exc.code == 409 and json.load(exc)["detail"] == "Peer recipient key is revoked"
    else:
        raise RuntimeError(f"{peer} sealed a message under the revoked key")
    path = Path(sys.argv[1]) / peer / f"{peer}_audit.log"
    events = [json.loads(line) for line in path.read_text().splitlines() if not line.startswith("#")]
    record = next(event for event in events if event["sequence"] == receipt["audit_sequence"])
    assert record["action"] == "PEER_REVOCATION_APPLIED"
    assert record["metadata"]["revocation_id"] == result["revocation"]["revocation_id"]
    print(f"  {peer} blocked a fresh send. Verified peer application audit sequence {record['sequence']}.")

unaffected = {"message": "Unaffected recipient"}
expect_delivery("node-c", send("node-c", unaffected), unaffected)
call("node-b", "/keys/rotate", {}, OPERATOR)
enroll("node-a", "node-b")
replacement = {"message": "Delivered with the replacement key"}
expect_delivery("node-b", send("node-b", replacement), replacement)
print("  node-c delivered unaffected traffic. node-b delivered with its replacement key.")
for node in NODES:
    assert call(node, "/logs/verify", headers=OPERATOR)["is_valid"], f"Invalid audit chain on {node}"

PYTHON

# ------------------------------------------------------------------------------
# STEP 5: Crash Recovery (WAL) & Damaged Backup Rejection
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "▶ STEP 5: Demonstrating Crash Recovery (WAL) & Damaged Backup Rejection"
echo "======================================================================"

"$demo_python" - << 'EOF'
import os, tempfile, json, secrets
from src.identity.key_manager import KeyManager, KeyStateEnum
from src.identity.recovery import WALManager
from src.identity.backup import BackupManager, BackupIntegrityError

tmpdir = tempfile.mkdtemp()
wal_file = os.path.join(tmpdir, "demo_wal.log")
wal = WALManager(wal_file)
km = KeyManager("demo-node", wal_manager=wal)

# 1. Enroll and simulate partial write mid-rotation
km.enroll_initial_key("ML-KEM-768", b"PUB_1", b"PRIV_1")
v1_id = km.active_key_id

with open(wal_file, "a") as f:
    f.write("corrupted_hash {\"op\": \"TORN_APPEND_MID_CRASH\n")

recovered_wal = WALManager(wal_file)
valid_entries = recovered_wal.read_valid_entries()
assert all(e["op"] != "TORN_APPEND_MID_CRASH" for e in valid_entries)
print(f"  ✅ WAL Crash Recovery: Torn write discarded, consistent state recovered for {v1_id}")

# 2. Backup Tampering Rejection
backup_file = os.path.join(tmpdir, "backup.tbv.json")
bm = BackupManager(secrets.token_bytes(32))
bm.create_backup({"node_id": "demo-node", "keys": [v1_id]}, backup_file)

# Corrupt 1 byte in backup payload
with open(backup_file, "r") as f:
    b_data = json.load(f)
b_data["payload_b64"] = b_data["payload_b64"][:-2] + "XX"
with open(backup_file, "w") as f:
    json.dump(b_data, f)

try:
    bm.verify_and_restore(backup_file)
except BackupIntegrityError as e:
    print(f"  🛡️ Damaged Backup Blocked: {e}")
else:
    raise RuntimeError("Corrupted backup was accepted")
EOF

# ------------------------------------------------------------------------------
# STEP 6: Verify Hash Chains & Inspect Explainable Detection Alerts
# ------------------------------------------------------------------------------
echo ""
echo "======================================================================"
echo "▶ STEP 6: Cryptographic Log Chain Verification & Explainable Alerts"
echo "======================================================================"

# Check that local policy denials produce the expected explainable alerts.
"$demo_python" - << 'EOF'
import json
import os
from urllib.error import HTTPError
from urllib.request import Request, urlopen

base = "http://127.0.0.1:8001"
operator = {"Authorization": f"Bearer {os.environ['DEMO_OPERATOR_TOKEN']}"}
for path, payload, status in (
    ("/send", {"recipient_id": "key-store", "payload": {"message": "policy check"}}, 403),
    ("/keys/rotate", {}, 401),
):
    request = Request(
        base + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(operator if path == "/send" else {})},
    )
    try:
        urlopen(request, timeout=5).close()
    except HTTPError as exc:
        if exc.code != status:
            raise
    else:
        raise RuntimeError(f"{path} should have returned HTTP {status}")

with urlopen(Request(base + "/metrics", headers=operator), timeout=5) as response:
    alerts = json.load(response)["alerts"]
rules = {alert["rule_name"] for alert in alerts}
expected = {"LATERAL_MOVEMENT_VIOLATION", "UNAUTHORIZED_KEY_ADMINISTRATION"}
if not expected <= rules:
    raise RuntimeError(f"Missing policy alerts: {expected - rules}")
for port in (8001, 8002, 8003):
    with urlopen(Request(f"http://127.0.0.1:{port}/logs/verify", headers=operator), timeout=5) as response:
        if not json.load(response)["is_valid"]:
            raise RuntimeError(f"Audit chain verification failed on port {port}")
EOF

# Operator CLI: Verify Audit Log Hash Chains
"$demo_python" -m demo.node.operator_cli verify-logs

# Operator CLI: View Explainable Alerts
echo ""
"$demo_python" -m demo.node.operator_cli alerts

echo ""
echo "======================================================================"
"$demo_python" -m scripts.demo_device_security
"$demo_python" -m scripts.track4_checklist
echo "🎉 WALKTHROUGH DEMO COMPLETED SUCCESSFULLY"
echo "======================================================================"
