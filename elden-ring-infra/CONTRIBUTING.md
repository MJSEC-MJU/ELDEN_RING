# ELDEN RING - 팀원 작업 안내서

각 Phase 담당자가 어디에, 어떻게 작업하면 되는지 안내합니다.

---

## 작업 흐름 (공통)

```
1. feature 브랜치 생성    git checkout -b feature/phase2-patch-generator
2. 자기 폴더에 작업       kubernetes/environments/<내 Phase 폴더>/
3. PR 올리기             dev 브랜치로 PR
4. 자동 검증 통과         GitHub Actions가 lint/scan/build 검증
5. 리뷰 후 머지           dev에 머지 → Staging 자동 배포
6. Production 반영       dev → main 머지 시 인프라 동기화
```

### Git 브랜치 규칙

```
feature/*  →  dev  →  main
  (개발)       (통합)    (운영)
```

- PR은 **dev 브랜치로만** 올린다
- main에 직접 PR 금지
- dev에서 충분히 테스트 후 main으로 머지

---

## Phase 1: Runtime Defense Plane

> **담당**: 이종윤
> **작업 폴더**: `kubernetes/environments/production/`

### 개요

외부 보안 솔루션(WAF, IDS 등)의 탐지 이벤트를 수신하여 구조화된 컨텍스트 패키지를 만들고 Phase 2에 전달한다.

### 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-production` |
| ServiceAccount | `runtime-defense-sa` |
| CPU | requests 4 / limits 8 |
| Memory | requests 8Gi / limits 16Gi |
| Istio | enabled (mTLS STRICT) |

### 만들어야 할 것

| 컴포넌트 | 설명 | K8s 리소스 |
|---|---|---|
| Event Receiver | WAF/IDS 이벤트 수신 | Deployment + Service |
| Event Normalizer | 다양한 포맷 → 통일 스키마 변환 | 위 Deployment 내부 로직 |
| CWE Mapper | 공격 유형 → CWE ID 확정 매핑 (Rule Table) | ConfigMap + 로직 |
| Source Mapper | 엔드포인트 → 소스코드 파일:함수:라인 매핑 | ConfigMap + 로직 |
| Context Builder | 구조화 컨텍스트 패키지 생성 → Phase 2 전달 | 로직 |

### Phase 2로 전달하는 데이터 형식

```json
{
  "event_id": "evt-20260321-001",
  "timestamp": "2026-03-21T14:30:00Z",
  "source": "modsecurity",
  "attack_category": "SQL Injection",
  "cwe": { "id": "CWE-89", "name": "..." },
  "target_endpoint": { "method": "POST", "path": "/api/login" },
  "source_location": { "file": "src/auth/login.py", "function": "login_handler", "line": 42 },
  "payload_sample": "username=admin' OR 1=1--"
}
```

### 이미 설정된 인프라

- Falco → `runtime-defense-controller:8080/api/v1/falco-events` 로 이벤트 전달
- Istio AuthorizationPolicy: Ingress Gateway + Governance + Monitoring만 접근 허용
- Istio PeerAuthentication: mTLS STRICT

### 배포 방법

```bash
kubectl apply -f kubernetes/environments/production/<내 매니페스트>.yaml
```

---

## Phase 2: Secure Coding Plane

> **담당**: 이주오
> **작업 폴더**: `kubernetes/environments/secure-coding/`

### 개요

Phase 1이 전달한 컨텍스트를 바탕으로 취약 코드를 분석하고, LLM으로 패치를 생성하여 후보 이미지를 빌드한다.

### 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-secure-coding` |
| ServiceAccount | `secure-coding-sa` |
| CPU | requests 2 / limits 4 |
| Memory | requests 4Gi / limits 8Gi |
| 최대 Job | 10 |

### 만들어야 할 것

| 컴포넌트 | 설명 | K8s 리소스 |
|---|---|---|
| Context Receiver | Phase 1에서 컨텍스트 수신 | Deployment + Service |
| Code Analyzer | Semgrep/AST 정적 분석 | Job 또는 위 Deployment 내부 |
| Patch Generator | LLM 패치 생성 + 정적 재검사 | Job |
| Image Builder | 후보 이미지 빌드 (Docker) | Job |

### Phase 1에서 받는 데이터

```json
{ "event_id": "...", "cwe": {...}, "source_location": {...}, "payload_sample": "..." }
```

### Phase 3으로 전달하는 데이터

```json
{
  "event_id": "evt-20260321-001",
  "patch_id": "patch-001",
  "candidate_image": "registry.local/app/target-app:candidate-evt-20260321-001-v1",
  "change_summary": { "files_changed": 1, "functions_changed": ["login_handler"] },
  "status": "ready_for_validation"
}
```

### 네트워크 규칙

```
허용:
  - Governance(elden-governance)에서 작업 트리거 수신
  - Harness(elden-harness)에서 배포
  - HTTPS(443) 외부 → LLM API 호출용
  - DNS(53)
차단:
  - elden-production 직접 접근 불가
  - elden-staging 직접 접근 불가
```

### 배포 방법

```bash
kubectl apply -f kubernetes/environments/secure-coding/<내 매니페스트>.yaml
```

---

## Phase 3: Recovery Assurance Plane

> **담당**: 이주오
> **작업 폴더**: `kubernetes/environments/staging/`

### 개요

Phase 2의 후보 이미지를 격리된 환경에 배포하고 4단계 검증을 수행한다. 모든 검증 통과한 이미지만 Phase 4로 전달한다.

### 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-staging` |
| ServiceAccount | `recovery-assurance-sa` |
| CPU | requests 4 / limits 8 |
| Memory | requests 8Gi / limits 16Gi |
| Istio | enabled |

### 만들어야 할 것

| 컴포넌트 | 설명 | K8s 리소스 |
|---|---|---|
| Validation Controller | 검증 흐름 오케스트레이션 | Deployment |
| Startup Checker | 기동 검증 (readiness/liveness) | Job |
| Regression Tester | 핵심 기능/API 회귀 테스트 | Job |
| Exploit Replayer | 탐지된 공격 payload 재실행 | Job |
| SLO Checker | latency, error rate, resource usage | Job |

### 4단계 검증 순서

```
기동 검증 → 회귀 테스트 → 공격 재현 → SLO 검증
   ↓ 하나라도 실패 시 → Phase 2에 재수정 요청
   ↓ 모두 통과 시 → Phase 4로 전달
```

### Phase 2에서 받는 데이터

```json
{ "patch_id": "...", "candidate_image": "registry.local/...:candidate-...", "change_summary": {...} }
```

### Phase 4로 전달하는 데이터

```json
{
  "event_id": "evt-20260321-001",
  "selected_patch_id": "patch-001",
  "validated_image": "registry.local/app/target-app:candidate-evt-20260321-001-v1",
  "validation_result": {
    "startup_check": "pass",
    "regression_test": "pass",
    "security_replay": "pass",
    "slo_check": "pass"
  },
  "decision": "promote",
  "status": "ready_for_governance"
}
```

### 배포 방법

```bash
kubectl apply -f kubernetes/environments/staging/<내 매니페스트>.yaml
```

---

## Phase 4: Governance Plane

> **담당**: 이윤태
> **작업 폴더**: `kubernetes/environments/governance/`
> **대시보드**: `kubernetes/monitoring/grafana/`

### 개요

Phase 3에서 검증 완료된 이미지 hash를 받아 정책 검증 → GitOps 반영 → Canary 배포 → Production 승격을 수행한다.

### 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-governance` |
| ServiceAccount | `governance-sa` |
| CPU | requests 2 / limits 4 |
| Memory | requests 4Gi / limits 8Gi |
| 권한 | **ClusterRole** - 모든 `elden-*` NS 접근 가능 |

### 만들어야 할 것

| 컴포넌트 | 설명 | K8s 리소스 |
|---|---|---|
| Governance Controller | Phase 3 결과 수신 → 승격 판단 | Deployment + Service |
| Policy Validator | OPA/Kyverno 기반 정책 검증 | Deployment 또는 Job |
| GitOps Manager | Git defense branch/PR 생성, 상태 동기화 | Deployment |
| Deploy Controller | Canary 배포 + 트래픽 조절 + 롤백 | Deployment |
| Dashboard | Grafana JSON 대시보드 | `monitoring/grafana/` |

### Phase 3에서 받는 데이터

```json
{
  "validated_image": "registry.local/app/target-app:candidate-...",
  "validation_result": { "startup_check": "pass", ... },
  "decision": "promote",
  "risk_assessment": { "severity": "high", "auto_approve_eligible": false },
  "deployment_strategy": { "type": "canary", "initial_traffic_percent": 10 },
  "gitops_target": { "repo": "...", "path": "...", "image_field": "..." }
}
```

### 승격 흐름

```
정책 검증 → Git defense branch/PR 생성 → Canary 10% 배포
  → 모니터링 (에러율/레이턴시) → 문제 없으면 점진 승격 (30% → 50% → 100%)
  → 문제 발생 시 자동 롤백
```

### 자동 vs 수동 승인

| 조건 | 승인 방식 |
|---|---|
| 저위험 (단일 함수, 설정 변경) | 자동 승격 |
| 고위험 (권한 변경, 다중 파일) | 수동 승인 필요 |

### Grafana 대시보드

`kubernetes/monitoring/grafana/` 에 JSON 파일 추가:

| 대시보드 | 내용 |
|---|---|
| `elden-ring-overview.json` | 전체 시스템 현황 |
| `runtime-defense.json` | 공격 탐지/방어 현황 |
| `recovery-assurance.json` | 검증 결과 |
| `governance-promotion.json` | 승격 이력, Canary 상태 |

### 사용 가능한 Prometheus 메트릭

```promql
istio_requests_total{destination_service_namespace=~"elden-.*"}
istio_request_duration_milliseconds_bucket{...}
falco_events_total{namespace=~"elden-.*"}
kube_deployment_status_replicas{namespace=~"elden-.*"}
```

### 배포 방법

```bash
kubectl apply -f kubernetes/environments/governance/<내 매니페스트>.yaml
```

---

## 네임스페이스 간 통신 규칙

```
elden-production ◀──── istio-system (외부 트래픽)
                 ◀──── elden-monitoring (스크래핑)
                 ────▶ istio-system (control plane)

elden-secure-coding ◀──── elden-governance (작업 트리거)
                    ◀──── elden-harness (배포)
                    ────▶ HTTPS 443 (LLM API)

elden-staging ◀──── elden-governance (검증 요청)
              ◀──── elden-harness (배포)
              ◀──── elden-monitoring (스크래핑)

elden-governance ◀───▶ 모든 elden-* (ClusterRole)
                 ────▶ HTTPS 443 (Git API)
```

---

## 각 Phase 폴더의 README

각 폴더에 더 상세한 안내가 있습니다:

| Phase | 폴더 | README |
|---|---|---|
| Phase 1 | `kubernetes/environments/production/` | 매니페스트 예시, Falco 연동, Istio 정책 |
| Phase 2 | `kubernetes/environments/secure-coding/` | 매니페스트 예시, 네트워크 범위, 연동 포인트 |
| Phase 3 | `kubernetes/environments/staging/` | 검증 Job 예시, ConfigMap 규약 |
| Phase 4 | `kubernetes/environments/governance/` | 컨트롤러 예시, 정책 ConfigMap, 대시보드 가이드 |
| 대시보드 | `kubernetes/monitoring/grafana/` | Grafana JSON 추가 방법, Prometheus 메트릭 |
