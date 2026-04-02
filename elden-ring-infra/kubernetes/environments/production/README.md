# Runtime Defense Plane - 이주오

> 담당: 위협 탐지, 이벤트 정규화, CWE 매핑, 소스코드 매핑, 컨텍스트 패키지 생성

---

## 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-production` |
| ServiceAccount | `runtime-defense-sa` |
| CPU 제한 | requests 4 / limits 8 |
| Memory 제한 | requests 8Gi / limits 16Gi |
| 최대 Pod | 30 |
| Istio | injection **enabled** (mTLS STRICT) |

## 이 폴더의 기존 파일

- `deployment.yaml` - 보호 대상 서비스 (target-app) + HPA + ConfigMap

## 추가로 올릴 것

### 필요한 컴포넌트

1. **Runtime Defense 컨트롤러** (Deployment)
   - Falco 이벤트 수신 → 자동 대응 액션 실행
   - 비정상 트래픽 제어, 긴급 정책 적용, 세션 격리

2. **동적 NetworkPolicy 관리자**
   - 공격 감지 시 실시간 NetworkPolicy 생성/수정
   - 의심 IP/Pod 격리

3. **Degrade Mode 컨트롤러**
   - 공격 시 핵심 기능만 유지하는 축소 운영 모드 전환

### 매니페스트 작성 예시

```yaml
# runtime-defense-controller.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: runtime-defense-controller
  namespace: elden-production
  labels:
    app: runtime-defense-controller
    elden-ring/plane: runtime-defense
spec:
  replicas: 2
  selector:
    matchLabels:
      app: runtime-defense-controller
  template:
    metadata:
      labels:
        app: runtime-defense-controller
        elden-ring/plane: runtime-defense
    spec:
      serviceAccountName: runtime-defense-sa
      containers:
        - name: controller
          image: eldenring/runtime-defense:latest
          ports:
            - containerPort: 8080
              name: http
          env:
            - name: FALCO_WEBHOOK_PATH
              value: "/api/v1/falco-events"
            - name: AUTO_ISOLATE_ENABLED
              value: "true"
            - name: DEGRADE_MODE_THRESHOLD
              value: "10"
          resources:
            requests:
              cpu: 200m
              memory: 256Mi
            limits:
              cpu: 500m
              memory: 512Mi
---
apiVersion: v1
kind: Service
metadata:
  name: runtime-defense-controller
  namespace: elden-production
spec:
  selector:
    app: runtime-defense-controller
  ports:
    - port: 8080
      targetPort: 8080
      name: http
```

## Falco 이벤트 수신

Falco Sidekick이 아래 주소로 보안 이벤트를 전달하도록 이미 설정되어 있음:

```
http://runtime-defense-controller.elden-production:8080/api/v1/falco-events
```

수신되는 이벤트 종류:
- Shell 실행 (CRITICAL)
- 의심 네트워크 연결 (WARNING)
- 파일 시스템 변조 (ERROR)
- 권한 상승 시도 (CRITICAL)
- SQL Injection 패턴 (CRITICAL)

## 네트워크 접근 범위

```
허용되는 통신:
  Ingress:
    - istio-system      (외부 트래픽, Ingress Gateway 경유)
    - elden-monitoring   (Prometheus 스크래핑)
  Egress:
    - DNS (53)
    - 내부 Pod 간 통신
    - istio-system (control plane)
  
차단됨:
    - elden-secure-coding 직접 접근 불가
    - 외부 인터넷 직접 접근 불가 (Istio 경유만 가능)
```

## Istio 보안 정책

이미 설정된 것:
- `PeerAuthentication`: mTLS STRICT (모든 통신 암호화)
- `AuthorizationPolicy`: deny-all 기본 + Ingress Gateway/Governance/Monitoring만 허용
- `DestinationRule`: outlier detection (연속 5xx 5회 시 Pod 제외)

Runtime Defense 컨트롤러에서 동적으로 추가할 수 있는 정책:
```yaml
# 예: 의심 소스 차단
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: block-suspicious-source
  namespace: elden-production
spec:
  action: DENY
  rules:
    - from:
        - source:
            ipBlocks: ["x.x.x.x/32"]
```
