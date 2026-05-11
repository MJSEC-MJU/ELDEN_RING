#!/usr/bin/env bash
# ============================================================
# /diagnostics watcher — appends one JSON line per second.
#
# Each sample is wrapped with a wall-clock timestamp so the verifier
# can correlate against timeline.log (loadtest/chaos events). Stops
# gracefully on SIGINT/SIGTERM.
#
# Env:
#   TARGET=http://localhost:18080
#   INTERVAL=1            # seconds between samples
#   RUN_DIR=scripts/loadtest/results/latest
#   DURATION=0            # 0 = run until killed
# ============================================================
set -euo pipefail

TARGET="${TARGET:-http://localhost:18080}"
INTERVAL="${INTERVAL:-1}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DIR="${RUN_DIR:-${REPO_ROOT}/loadtest/results/latest}"
RUN_DIR="$(cd "${RUN_DIR}" && pwd -P)"
DURATION="${DURATION:-0}"

OUT="${RUN_DIR}/diagnostics.ndjson"
mkdir -p "${RUN_DIR}"
: > "${OUT}"

STOP=0
trap 'STOP=1' INT TERM

start_epoch=$(date -u +%s)
echo "[watch] $TARGET/diagnostics every ${INTERVAL}s -> $OUT"

while [[ $STOP -eq 0 ]]; do
  ts=$(date -u +%FT%TZ)
  # Compose: {"ts":"...","status":<code>,"body":<diagnostics-json>}
  body=$(curl -sS -m 3 -o - -w '\nHTTP_STATUS:%{http_code}\n' "${TARGET}/diagnostics" 2>/dev/null || echo "HTTP_STATUS:000")
  status=$(echo "$body" | awk -F: '/HTTP_STATUS:/{print $2; exit}')
  payload=$(echo "$body" | sed '/HTTP_STATUS:/d')
  if [[ -z "$payload" ]] || ! echo "$payload" | python3 -c 'import json,sys; json.load(sys.stdin)' >/dev/null 2>&1; then
    payload='null'
  fi
  # Strip leading zeros so the int is valid JSON (000 -> 0). bash arithmetic
  # rejects bare zeros otherwise, so the conditional handles both shapes.
  status="${status:-0}"
  status=$((10#$status))
  printf '{"ts":"%s","status":%d,"body":%s}\n' "$ts" "$status" "$payload" >> "$OUT"

  if [[ "$DURATION" -ne 0 ]]; then
    now=$(date -u +%s)
    if (( now - start_epoch >= DURATION )); then break; fi
  fi
  sleep "${INTERVAL}"
done

echo "[watch] done — $(wc -l < "$OUT") samples"
