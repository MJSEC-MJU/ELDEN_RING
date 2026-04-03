# Governance Plane - 이종윤

> 담당: 정책 검증, GitOps 반영, Canary 승격, 자동 롤백, 모니터링/대시보드

---

## 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-governance` |
| ServiceAccount | `governance-sa` |
| CPU 제한 | requests 2 / limits 4 |
| Memory 제한 | requests 4Gi / limits 8Gi |
| 최대 Pod | 15 |
| 권한 범위 | **ClusterRole** - 모든 `elden-*` 네임스페이스 접근 가능 |

## 이 폴더에 올릴 것

이 디렉토리에 Kubernetes 매니페스트 파일(`.yaml`)을 작성하면 됩니다.

### 필요한 컴포넌트

1. **Governance 컨트롤러** (Deployment)
   - 정책 검증, 승격 게이트 로직
   - Staging 검증 결과(ConfigMap) 확인 → 승격 여부 판단
   - Canary 배포 트래픽 비율 조절

2. **GitOps 연동**
   - Git 저장소 변경 감지 → 자동 배포 트리거
   - ArgoCD 또는 자체 구현

3. **대시보드** (Grafana 커스텀 대시보드)
   - `kubernetes/monitoring/grafana/` 에 JSON 대시보드 추가
   - 공격 탐지 현황, 방어 상태, 패치 후보, 검증 결과, 승격 이력

4. **자동 롤백 컨트롤러**
   - Production 에러율 임계치 초과 시 자동 롤백

### 매니페스트 작성 예시

```yaml
# governance-controller.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: governance-controller
  namespace: elden-governance
  labels:
    app: governance-controller
    elden-ring/plane: governance
spec:
  replicas: 1
  selector:
    matchLabels:
      app: governance-controller
  template:
    metadata:
      labels:
        app: governance-controller
        elden-ring/plane: governance
    spec:
      serviceAccountName: governance-sa
      containers:
        - name: controller
          image: eldenring/governance-controller:latest
          ports:
            - containerPort: 8080
              name: http
            - containerPort: 9090
              name: metrics
          env:
            - name: PROMETHEUS_URL
              value: "http://prometheus-kube-prometheus-prometheus.elden-monitoring:9090"
            - name: GRAFANA_URL
              value: "http://prometheus-grafana.elden-monitoring:80"
            - name: CANARY_THRESHOLD_ERROR_RATE
              value: "5"
            - name: CANARY_THRESHOLD_LATENCY_P99
              value: "1000"
          resources:
            requests:
              cpu: 100m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: governance-controller
  namespace: elden-governance
spec:
  selector:
    app: governance-controller
  ports:
    - port: 8080
      targetPort: 8080
      name: http
    - port: 9090
      targetPort: 9090
      name: metrics
```

```yaml
# promotion-policy.yaml (정책 ConfigMap 예시)
apiVersion: v1
kind: ConfigMap
metadata:
  name: promotion-policy
  namespace: elden-governance
data:
  policy.yaml: |
    promotion:
      staging_to_canary:
        required_checks:
          - exploit_replay: PASSED
          - regression_test: PASSED
          - slo_check: PASSED
        auto_promote: false
      canary_to_production:
        canary_duration: 5m
        error_rate_threshold: 5
        latency_p99_threshold: 1000
        traffic_steps: [10, 30, 50, 100]
        auto_rollback: true
```

## Grafana 대시보드 추가 방법

`kubernetes/monitoring/grafana/` 디렉토리에 JSON 파일을 추가하면 됩니다.

```
kubernetes/monitoring/grafana/
├── elden-ring-overview.json       # 전체 시스템 현황
├── runtime-defense-dashboard.json # 공격 탐지/방어 현황
├── recovery-assurance.json        # 검증 결과 대시보드
└── governance-promotion.json      # 승격 이력 대시보드
```

Prometheus에서 이미 수집 중인 메트릭:
- `istio_requests_total` - HTTP 요청 수 (상태코드별)
- `istio_request_duration_milliseconds` - 응답 시간
- `falco_events_total` - 보안 이벤트 수
- `kube_deployment_status_*` - Pod/Deployment 상태

## 네트워크 접근 범위

```
허용되는 통신:
  Ingress:
    - 모든 elden-* 네임스페이스에서 수신 가능
  Egress:
    - 모든 elden-* 네임스페이스로 전송 가능
    - DNS (53)
    - HTTPS (443) ← Git API, Harness API
  
이 Plane은 ClusterRole을 가지고 있어서
모든 elden-* 네임스페이스의 Deployment, Service, ConfigMap 등을 
조회/수정할 수 있습니다.
```

## 작업 흐름

```
1. feature/governance-xxx 브랜치 생성
2. 이 폴더에 매니페스트 작성
3. 대시보드는 kubernetes/monitoring/grafana/ 에 JSON 추가
4. PR → dev 브랜치 (자동 검증)
5. 리뷰 후 dev 머지 → Staging 반영
6. dev → main 머지 → Production 반영
```

## 다른 Plane과의 연동 포인트

| 연동 대상 | 방향 | 내용 |
|---|---|---|
| Secure Coding | → 트리거 | 패치 생성 작업 시작 요청 |
| Recovery Assurance (Staging) | ← 수신 | 검증 결과 ConfigMap 읽기 (`ra-exploit-results`, `ra-regression-results`, `ra-slo-results`) |
| Runtime Defense (Production) | → 제어 | Canary 트래픽 비율 조절, 롤백 실행 |
| Monitoring | ← 수신 | Prometheus 메트릭 조회, Grafana 대시보드 관리 |

## Recovery Assurance 검증 결과 읽는 방법

검증 결과는 `elden-staging` 네임스페이스의 ConfigMap에 저장됩니다.

```bash
# 공격 재현 테스트 결과
kubectl get configmap ra-exploit-results -n elden-staging -o jsonpath='{.data.status}'

# 회귀 테스트 결과
kubectl get configmap ra-regression-results -n elden-staging -o jsonpath='{.data.status}'

# SLO 성능 검증 결과
kubectl get configmap ra-slo-results -n elden-staging -o jsonpath='{.data.status}'
```

3개 모두 `PASSED`일 때만 Production 승격을 허용하면 됩니다.
