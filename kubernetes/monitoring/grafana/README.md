# Grafana Custom Dashboards - 이종윤

> 이 디렉토리에 Grafana 대시보드 JSON 파일을 추가하세요.

## 필요한 대시보드

| 파일명 | 내용 | 상태 |
|---|---|---|
| `elden-ring-overview.json` | 전체 시스템 현황 (4 Plane 상태 한눈에) | 미작성 |
| `runtime-defense.json` | 공격 탐지/방어 현황, Falco 이벤트 | 미작성 |
| `recovery-assurance.json` | 검증 결과 (exploit/regression/SLO) | 미작성 |
| `governance-promotion.json` | 승격 이력, 정책 위반, 롤백, Canary 상태 | **작성됨** |

## 적용 방법 (governance-promotion.json)

Grafana 가 elden-monitoring 네임스페이스에서 동작 중이라고 가정.

```bash
# 1. 대시보드 ConfigMap 으로 import
kubectl create configmap grafana-dashboard-governance-promotion \
  --from-file=governance-promotion.json=kubernetes/monitoring/grafana/governance-promotion.json \
  -n elden-monitoring \
  --dry-run=client -o yaml | \
  kubectl label --local -f - grafana_dashboard=1 --dry-run=client -o yaml | \
  kubectl apply -f -

# 또는 Grafana UI에서 Dashboards -> Import -> JSON 파일 업로드
```

Phase 4 governance-controller 가 `/metrics` 엔드포인트로 노출하는 커스텀 메트릭은 다음과 같다 (Prometheus scrape 설정 필요):

```yaml
# prometheus PodMonitor 예시
apiVersion: monitoring.coreos.com/v1
kind: PodMonitor
metadata:
  name: governance-controller
  namespace: elden-governance
spec:
  selector:
    matchLabels: { app: governance-controller }
  podMetricsEndpoints:
    - port: http
      path: /metrics
      interval: 30s
```

## 사용 가능한 Prometheus 메트릭

### Phase 4 Governance 커스텀 메트릭 (services/governance/src/metrics.py)

```promql
# 누적 incident 수 (stage × risk)
governance_incidents_total{stage,risk}

# 진행 중 incident (게이지)
governance_active_incidents{risk}

# 정책 위반 누적 (Kyverno PolicyReport 기반)
governance_policy_violations_total{policy}

# 롤백 누적 (slo_breach / manual)
governance_rollbacks_total{reason}

# 승격 게이트 결정 (auto / manual_pause / rejected)
governance_promotion_decisions_total{decision}
```

### 인프라 표준 메트릭

```promql
# HTTP 트래픽 (Istio)
istio_requests_total{destination_service_namespace=~"elden-.*"}
istio_request_duration_milliseconds_bucket{destination_service_namespace=~"elden-.*"}

# 에러율
sum(rate(istio_requests_total{response_code=~"5.."}[5m])) by (destination_service_namespace)

# P99 레이턴시
histogram_quantile(0.99, sum(rate(istio_request_duration_milliseconds_bucket[5m])) by (le))

# Falco 보안 이벤트
falco_events_total{namespace=~"elden-.*"}

# Argo Rollouts (rollout_phase: 0 Healthy / 1 Progressing / 2 Paused / 3 Degraded / 4 Aborted)
rollout_phase{namespace=~"elden-canary|elden-production"}

# Pod 상태
kube_deployment_status_replicas{namespace=~"elden-.*"}
kube_deployment_status_replicas_unavailable{namespace=~"elden-.*"}
kube_pod_container_status_restarts_total{namespace=~"elden-.*"}
```

## 대시보드 만드는 법

1. Grafana UI에서 대시보드 만들기 (`localhost:3000`)
2. 완성되면 Share → Export → Save to file
3. JSON 파일을 이 디렉토리에 저장
4. PR → dev → main 순으로 반영
