# Grafana Custom Dashboards - 이윤태

> 이 디렉토리에 Grafana 대시보드 JSON 파일을 추가하세요.

## 필요한 대시보드

| 파일명 | 내용 |
|---|---|
| `elden-ring-overview.json` | 전체 시스템 현황 (4 Plane 상태 한눈에) |
| `runtime-defense.json` | 공격 탐지/방어 현황, Falco 이벤트 |
| `recovery-assurance.json` | 검증 결과 (exploit/regression/SLO) |
| `governance-promotion.json` | 승격 이력, Canary 트래픽 비율, 롤백 이력 |

## 사용 가능한 Prometheus 메트릭

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
