#!/usr/bin/env bash
set -euo pipefail

# Compose-free local mode: starts node-a, node-b, node-c via uvicorn against DATABASE_URL
mkdir -p /tmp/tbv_pids
alembic upgrade head

for spec in "node-a:8101" "node-b:8102" "node-c:8103"; do
  NODE_ID="${spec%%:*}"
  NODE_PORT="${spec##*:}"
  NODE_ID="$NODE_ID" NODE_PORT="$NODE_PORT" WRAP_KEY_REF="local-wrap-key-$NODE_ID" \
    uvicorn src.identity_keys.api:app --host 127.0.0.1 --port "$NODE_PORT" &
  echo $! > "/tmp/tbv_pids/${NODE_ID}.pid"
  echo "Started $NODE_ID on port $NODE_PORT (pid $!)"
done
wait
