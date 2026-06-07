#!/usr/bin/env bash
# ============================================================
# Phase 1 reliability chaos: Redis outage injection.
#
# Waits DELAY seconds, then `docker stop`s the Redis container,
# sleeps OUTAGE seconds, and starts it back up. All transitions are
# stamped (UTC ISO8601) into the run's timeline.log so the verifier
# can compute drain duration from "redis up again" to "queue length 0".
#
# Env overrides:
#   DELAY=60               # seconds after script start before stopping redis
#   OUTAGE=60              # seconds redis stays down
#   CONTAINER=elden-loadtest-redis
#   RUN_DIR=scripts/loadtest/results/latest
# ============================================================
set -euo pipefail

DELAY="${DELAY:-60}"
OUTAGE="${OUTAGE:-60}"
CONTAINER="${CONTAINER:-elden-loadtest-redis}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RUN_DIR="${RUN_DIR:-${REPO_ROOT}/loadtest/results/latest}"

# Resolve symlinks so `latest` works regardless of CWD.
RUN_DIR="$(cd "${RUN_DIR}" && pwd -P)"
TIMELINE="${RUN_DIR}/timeline.log"

mkdir -p "${RUN_DIR}"
touch "${TIMELINE}"

stamp() { date -u +%FT%TZ; }
log()   { echo "$(stamp) $*" | tee -a "${TIMELINE}" >&2; }

if ! docker inspect "${CONTAINER}" >/dev/null 2>&1; then
  echo "container ${CONTAINER} not found; is docker-compose up?" >&2
  exit 1
fi

log "chaos_arm delay=${DELAY}s outage=${OUTAGE}s container=${CONTAINER}"
sleep "${DELAY}"

log "redis_stop_begin"
docker stop "${CONTAINER}" >/dev/null
log "redis_stopped"

sleep "${OUTAGE}"

log "redis_start_begin"
docker start "${CONTAINER}" >/dev/null
# Wait for redis to actually accept commands again — gives the verifier
# a clean "redis healthy at T" anchor rather than just "docker start returned".
for i in $(seq 1 30); do
  if docker exec "${CONTAINER}" redis-cli ping 2>/dev/null | grep -q PONG; then
    log "redis_healthy"
    break
  fi
  sleep 1
done
log "chaos_done"
