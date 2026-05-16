#!/usr/bin/env bash
set -euo pipefail

URL="${1:-http://localhost:8091/healthz}"
TIMEOUT="${2:-30}"

echo "Waiting for ${URL} (timeout ${TIMEOUT}s)..."
for i in $(seq 1 "$TIMEOUT"); do
  if curl -sf -o /dev/null "$URL"; then
    echo "Ready after ${i}s"
    exit 0
  fi
  sleep 1
done

echo "ERROR: timed out waiting for ${URL} after ${TIMEOUT}s"
exit 1
