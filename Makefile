# ============================================================
# ELDEN RING — Phase 1 reliability automation
#
# Three entry points used by the 11-주차 중간 발표 신뢰성 섹션:
#   make loadtest   load only (no chaos)
#   make chaos      load + redis outage (full 회의록 시나리오)
#   make report     re-generate PNGs + REPORT.md for results/latest
#
# Implicit env:
#   COMPOSE=docker compose -f scripts/loadtest/docker-compose.loadtest.yaml
#   RUN_DIR resolved per-run via TS env var
# ============================================================
SHELL := bash
COMPOSE := docker compose -f scripts/loadtest/docker-compose.loadtest.yaml
LOADTEST_DIR := scripts/loadtest
RESULTS_DIR := $(LOADTEST_DIR)/results
TS := $(shell date -u +%Y%m%dT%H%M%SZ)
RUN_DIR := $(RESULTS_DIR)/$(TS)

.PHONY: loadtest chaos report up down logs verify plots clean

up:
	$(COMPOSE) up -d --build
	@echo "[make] waiting for runtime-defense readyz..."
	@for i in $$(seq 1 30); do \
	  curl -fsS http://localhost:18080/readyz >/dev/null 2>&1 && exit 0; \
	  sleep 2; \
	done; echo "[make] runtime-defense did not become ready" >&2; exit 1

down:
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs --tail=200 -f runtime-defense

loadtest: up
	@mkdir -p $(RUN_DIR)
	@rm -f $(RESULTS_DIR)/latest && cd $(RESULTS_DIR) && ln -s $(TS) latest
	@echo "[make] run dir: $(RUN_DIR)"
	@RUN_DIR="$(PWD)/$(RUN_DIR)" bash scripts/observe/watch_diagnostics.sh & \
	  WATCHER=$$!; \
	  TS=$(TS) bash $(LOADTEST_DIR)/run.sh; \
	  sleep 30; \
	  kill $$WATCHER 2>/dev/null || true; \
	  wait $$WATCHER 2>/dev/null || true
	$(MAKE) report
	$(MAKE) down

chaos: up
	@mkdir -p $(RUN_DIR)
	@rm -f $(RESULTS_DIR)/latest && cd $(RESULTS_DIR) && ln -s $(TS) latest
	@echo "[make] run dir: $(RUN_DIR) (chaos scenario)"
	@RUN_DIR="$(PWD)/$(RUN_DIR)" bash scripts/observe/watch_diagnostics.sh & \
	  WATCHER=$$!; \
	  RUN_DIR="$(PWD)/$(RUN_DIR)" bash scripts/chaos/redis_outage.sh & \
	  CHAOS=$$!; \
	  TS=$(TS) bash $(LOADTEST_DIR)/run.sh; \
	  wait $$CHAOS; \
	  sleep 30; \
	  kill $$WATCHER 2>/dev/null || true; \
	  wait $$WATCHER 2>/dev/null || true
	$(MAKE) logs-dump
	$(MAKE) verify SCENARIO=chaos
	$(MAKE) plots
	$(MAKE) down

# Persist container logs to the run dir BEFORE `make down` deletes them.
# Without this we lose every signal of what Phase 1 was actually doing
# during the run when investigating after-the-fact.
logs-dump:
	@$(COMPOSE) logs --no-color --timestamps runtime-defense > $(RESULTS_DIR)/latest/runtime-defense.log 2>&1 || true
	@$(COMPOSE) logs --no-color --timestamps redis           > $(RESULTS_DIR)/latest/redis.log           2>&1 || true
	@echo "[make] saved container logs to $(RESULTS_DIR)/latest/"

# Re-render plots + REPORT.md from the most recent run.
report: plots verify

plots:
	@python3 scripts/observe/plot_results.py --run-dir $(RESULTS_DIR)/latest

verify:
	@python3 scripts/observe/verify.py \
	    --run-dir $(RESULTS_DIR)/latest \
	    --scenario $${SCENARIO:-chaos}

clean:
	rm -rf $(RESULTS_DIR)
