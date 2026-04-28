# feat(phase4): governance Prometheus 메트릭 + Grafana 대시보드

## 요약

Phase 4 governance-controller 에 5개 커스텀 Prometheus 메트릭을 추가하고, 이를 시각화하는 Grafana 대시보드(10 patches)를 새로 작성한다. 기존 동작에는 영향 없음(메트릭 호출은 orchestrator/promotion_gate 의 결정 지점에 추가).

## 변경 파일

**신규**
- `services/governance/src/metrics.py` — 메트릭 정의
- `services/governance/tests/test_metrics.py` — 6개 단위 테스트
- `kubernetes/monitoring/grafana/governance-promotion.json` — Grafana 대시보드 (10 panels)

**수정**
- `services/governance/src/orchestrator.py` — 메트릭 측정 지점 추가
- `services/governance/src/promotion_gate.py` — abort 시 rollback 메트릭 분류
- `kubernetes/monitoring/grafana/README.md` — 신규 메트릭 + 적용 가이드

## 추가된 메트릭

| 메트릭 | 타입 | 라벨 | 설명 |
|---|---|---|---|
| `governance_incidents_total` | Counter | stage, risk | 누적 incident (단계 × 위험도) |
| `governance_active_incidents` | Gauge | risk | 진행 중 incident |
| `governance_policy_violations_total` | Counter | policy | Kyverno 정책 위반 |
| `governance_rollbacks_total` | Counter | reason (slo_breach/manual) | 롤아웃 abort 누적 |
| `governance_promotion_decisions_total` | Counter | decision (auto/manual_pause/rejected) | 승격 게이트 결정 |

## 대시보드 panels (10개)

1. Active incidents (stat by risk)
2. Promotion decisions 24h (stat by decision)
3. Rollbacks 24h (stat by reason, 3+ → red)
4. Policy violations 24h (stat)
5. Incidents by stage (5m rate, stacked bars)
6. Risk class distribution (pie, 1h)
7. Policy violations by policy (timeseries)
8. Rollouts canary phase (timeseries, `rollout_phase`)
9. Orchestrator HTTP latency p95 (FastAPI histogram)
10. Active incidents table (instant query)

## 검증

- pytest: **20/20 PASS** (기존 14 + 신규 6)
- JSON 구문: 10 panels, schemaVersion 39
- Python 컴파일: orchestrator/promotion_gate/metrics 모두 OK
- 메트릭 측정 지점이 호출되는지 — `test_metrics_registered_in_default_registry` 가 검증

## 적용 방법 (리뷰어 참고)

```bash
# 1. governance-controller 이미지 재빌드 + 로드 (메트릭 추가됨)
docker build -t ghcr.io/mjsec-mju/elden-governance:dev services/governance
kind load docker-image ghcr.io/mjsec-mju/elden-governance:dev --name elden-gov-test

# 2. Prometheus PodMonitor 설정 (README 의 예시 참고)

# 3. Grafana 에 대시보드 import
kubectl create configmap grafana-dashboard-governance-promotion \
  --from-file=governance-promotion.json=kubernetes/monitoring/grafana/governance-promotion.json \
  -n elden-monitoring \
  --dry-run=client -o yaml | \
  kubectl label --local -f - grafana_dashboard=1 --dry-run=client -o yaml | \
  kubectl apply -f -
```

## Test plan

- [ ] CI pr-validation.yaml 통과
- [ ] pytest 20/20 PASS (로컬 재실행)
- [ ] Grafana 에 대시보드 import 후 panel 모두 query 정상 (메트릭 0이라도 panel 자체는 렌더링)
- [ ] (선택) 클러스터에 governance-controller 신 이미지 배포 후 envelope 1건 흘려보내고 `governance_incidents_total` 카운터 증가 확인
