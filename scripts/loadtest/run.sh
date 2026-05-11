#!/usr/bin/env bash
# ============================================================
# Phase 1 reliability load test driver.
#
# Spawns two concurrent vegeta attacks:
#   - normal traffic @ 200 RPS for $DURATION
#   - SQLi traffic   @  50 RPS for $DURATION
# Targets Phase 1 directly via /api/v1/modsec-events (auth disabled in
# docker-compose.loadtest.yaml). Stores raw .bin + parsed JSON per stream
# under results/<ts>/.
#
# Env overrides:
#   DURATION=5m  NORMAL_RPS=200  SQLI_RPS=50  TARGET=http://localhost:18080
# ============================================================
set -euo pipefail

cd "$(dirname "$0")"

DURATION="${DURATION:-5m}"
NORMAL_RPS="${NORMAL_RPS:-200}"
SQLI_RPS="${SQLI_RPS:-50}"
TARGET="${TARGET:-http://localhost:18080}"
TS="${TS:-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="results/${TS}"

mkdir -p "$OUT"
# Create the "latest" symlink up front so concurrent watcher/chaos scripts
# can resolve results/latest before vegeta finishes.
rm -f results/latest
ln -s "${TS}" results/latest

if ! command -v vegeta >/dev/null 2>&1; then
  echo "vegeta not found. Install: brew install vegeta" >&2
  exit 127
fi

# Targets reference @payloads/*.json with paths relative to the working dir.
# We run vegeta from this directory so the @path resolves correctly.

echo "[loadtest] target=$TARGET duration=$DURATION normal=$NORMAL_RPS sqli=$SQLI_RPS"
echo "[loadtest] writing to $OUT/"

# Replace the host in target files at run time (in case TARGET overridden).
sed "s|http://localhost:18080|${TARGET}|g" normal.targets > "$OUT/normal.targets"
sed "s|http://localhost:18080|${TARGET}|g" sqli.targets   > "$OUT/sqli.targets"

# Quick reachability check so we don't waste 5 minutes on a typo.
if ! curl -fsS -o /dev/null "${TARGET}/healthz"; then
  echo "[loadtest] target ${TARGET}/healthz unreachable" >&2
  exit 2
fi

echo "[loadtest] starting at $(date -u +%FT%TZ)"
echo "$(date -u +%FT%TZ) loadtest_start" >> "$OUT/timeline.log"

# vegeta attacks both run in background; we wait for both.
vegeta attack \
  -targets="$OUT/normal.targets" \
  -rate="${NORMAL_RPS}/1s" \
  -duration="${DURATION}" \
  -timeout=5s \
  -name=normal \
  > "$OUT/normal.bin" 2> "$OUT/normal.err" &
NORMAL_PID=$!

vegeta attack \
  -targets="$OUT/sqli.targets" \
  -rate="${SQLI_RPS}/1s" \
  -duration="${DURATION}" \
  -timeout=5s \
  -name=sqli \
  > "$OUT/sqli.bin" 2> "$OUT/sqli.err" &
SQLI_PID=$!

wait $NORMAL_PID
wait $SQLI_PID

echo "$(date -u +%FT%TZ) loadtest_end" >> "$OUT/timeline.log"
echo "[loadtest] attacks complete; parsing"

vegeta report -type=json < "$OUT/normal.bin" > "$OUT/normal.report.json"
vegeta report -type=json < "$OUT/sqli.bin"   > "$OUT/sqli.report.json"
vegeta report -type=text < "$OUT/normal.bin" > "$OUT/normal.report.txt"
vegeta report -type=text < "$OUT/sqli.bin"   > "$OUT/sqli.report.txt"

echo "[loadtest] done -> $OUT/"
