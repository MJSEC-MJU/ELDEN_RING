# ELDEN RING - Kubernetes Infrastructure

> **Kubernetes 기반 AI 대 AI 능동 방어 및 시큐어코딩 시스템**
>
> K8s + Istio + Falco + Prometheus/Grafana/Loki + Harness + GitHub Actions

---

## 프로젝트 개요

운영 서비스에 대한 공격을 탐지하고, AI가 자동으로 패치를 생성/검증한 뒤, 검증된 이미지만 운영에 승격하는 **4 Phase 자동화 파이프라인** 시스템입니다.

이 저장소는 4 Phase가 올라갈 **Kubernetes 인프라 계층**을 담당합니다.

---

## 4 Phase 흐름

```
  Phase 1                    Phase 2                    Phase 3                    Phase 4
┌──────────────┐          ┌──────────────┐          ┌──────────────┐          ┌──────────────┐
│   Runtime    │  context │   Secure     │  image   │  Recovery    │  hash    │  Governance  │
│   Defense    │─────────▶│   Coding     │─────────▶│  Assurance   │─────────▶│              │
│   Plane      │  (JSON)  │   Plane      │          │  Plane       │  (JSON)  │   Plane      │
├──────────────┤          ├──────────────┤          ├──────────────┤          ├──────────────┤
│ 위협 탐지     │          │ 패치 생성     │          │ 패치 검증     │          │ 운영 승격     │
│ 이벤트 정규화  │          │ 정적 분석     │          │ 기동 검증     │          │ 정책 검증     │
│ CWE 매핑      │          │ LLM 패치     │          │ 회귀 테스트   │          │ GitOps 반영   │
│ 소스코드 매핑  │          │ 이미지 빌드   │          │ 공격 재현     │          │ Canary 배포   │
│              │          │              │          │ SLO 검증     │          │ 자동 롤백     │
└──────────────┘          └──────────────┘          └──────────────┘          └──────────────┘
  elden-production          elden-secure-coding        elden-staging             elden-governance
```

### Phase 간 데이터 흐름 (Redis)

```
접속 주소:  redis-master.elden-monitoring:6379
인증:      없음 (NetworkPolicy로 elden-* NS만 접근 가능)

Phase 1 → Phase 2:  PUBLISH elden:phase2:context  (event_id, CWE, source_location, payload)
Phase 2 → Phase 3:  PUBLISH elden:phase3:validate (patch_id, candidate_image, change_summary)
Phase 3 → Phase 4:  PUBLISH elden:phase4:promote  (validated_image hash, validation_result, risk)
Phase 3 → Phase 2:  PUBLISH elden:phase2:retry    (검증 실패 시 재수정 요청)
```

---

## 디렉토리 구조

```

├── services/                    # 앱 코드 (Phase별)
│   ├── runtime-defense/             # Phase 1 (이주오) - src/, tests/, Dockerfile
│   ├── secure-coding/               # Phase 2 (이윤태)
│   ├── recovery-assurance/          # Phase 3 (이윤태)
│   └── governance/                  # Phase 4 (이종윤)
├── kubernetes/                  # K8s 매니페스트
│   ├── base/                        # 네임스페이스, RBAC, NetworkPolicy, ResourceQuota
│   ├── environments/                # Phase별 Deployment/Service YAML
│   │   ├── production/                  # Phase 1 매니페스트 + target-app
│   │   ├── secure-coding/               # Phase 2 매니페스트
│   │   ├── staging/                     # Phase 3 매니페스트 + target-app staging
│   │   ├── governance/                  # Phase 4 매니페스트
│   │   └── canary/                      # Canary 승격용
│   ├── messaging/                   # Redis (Phase 간 메시지 브로커)
│   ├── monitoring/                  # Prometheus + Grafana, Loki
│   ├── security/                    # Falco 런타임 탐지
│   └── service-mesh/                # Istio (mTLS, 트래픽 제어)
├── .github/workflows/           # GitHub Actions CI/CD
│   ├── pr-validation.yaml           # PR → dev 시 lint/scan/build/test
│   ├── dev-ci.yaml                  # dev 머지 → 변경된 Phase만 빌드/배포
│   └── main-promote.yaml            # main 머지 → Production 인프라 동기화
├── .harness/                    # Harness 배포 설정
└── scripts/                     # 셋업 스크립트
```

---

## Phase ↔ 네임스페이스 ↔ 담당자

| Phase | Namespace | 담당 | 역할 |
|---|---|---|---|
| **Phase 1** | `elden-production` | 이주오 | 위협 탐지, 이벤트 정규화, CWE 매핑, 컨텍스트 생성 |
| **Phase 2** | `elden-secure-coding` | 이윤태 | 정적 분석, LLM 패치 생성, 후보 이미지 빌드 |
| **Phase 3** | `elden-staging` | 이윤태 | 기동/회귀/공격재현/SLO 검증, 통과 이미지 선택 |
| **Phase 4** | `elden-governance` | 이종윤 | 정책 검증, GitOps 반영, Canary 승격, 롤백 |
| System | `elden-canary` | 이종윤 | Canary 트래픽 분할 테스트 |
| System | `elden-monitoring` | 이종윤 | Prometheus, Grafana, Loki, Falco |
| System | `elden-harness` | 이종윤 | Harness Delegate |

> 각 Phase별 상세 작업 안내는 [CONTRIBUTING.md](CONTRIBUTING.md)를 참고하세요.

---

## 기술 스택

| 구분 | 도구 | 역할 |
|---|---|---|
| Orchestration | **Kubernetes** (kind / EKS / GKE) | 컨테이너 오케스트레이션 |
| CI/CD | **GitHub Actions** + **Harness** | 코드 검증 + 인프라 배포 |
| Service Mesh | **Istio** | mTLS, 트래픽 분할, AuthorizationPolicy |
| Monitoring | **Prometheus + Grafana** | 메트릭 수집, 대시보드, 알림 |
| Logging | **Loki + Promtail** | 로그 수집 및 검색 |
| Security | **Falco** | 런타임 이상행위 탐지 |
| Messaging | **Redis** | Phase 간 컨텍스트 전달 (Pub/Sub + Queue) |

---

## 빠른 시작

### 사전 요구사항

- `kubectl` (v1.28+)
- `helm` (v3.12+)
- `kind` (로컬 개발 시)
- `istioctl` (선택, 없으면 helm으로 대체 설치)

### 1. 로컬 개발 환경 (kind)

```bash
chmod +x scripts/setup-cluster.sh
./scripts/setup-cluster.sh --dev
```

### 2. 기존 클러스터에 배포

```bash
./scripts/setup-cluster.sh --prod
```

### 3. Harness Delegate 설치

```bash
./scripts/install-harness-delegate.sh
```

### 4. 설치 확인

```bash
kubectl get ns -l app.kubernetes.io/part-of=elden-ring
kubectl get pods -A -l elden-ring/plane

# Grafana: http://localhost:3000 (admin / elden-ring-admin)
kubectl port-forward svc/prometheus-grafana -n elden-monitoring 3000:80

# Prometheus: http://localhost:9090
kubectl port-forward svc/prometheus-kube-prometheus-prometheus -n elden-monitoring 9090:9090
```

---

## GitHub Actions (팀원 코드 CI)

| Workflow | 트리거 | 하는 일 |
|---|---|---|
| `pr-validation.yaml` | PR → `dev` | YAML lint, kubeval, Trivy 스캔, 빌드/테스트 |
| `dev-ci.yaml` | `dev` push | 이미지 빌드 + Staging 배포 |
| `main-promote.yaml` | `main` push | Production 인프라 동기화 |

```
feature/* → PR to dev → 자동 검증 → dev 머지 → Staging 배포 → main 머지 → Prod 인프라 동기화
```

> 보안 패치의 Production 승격은 GitHub Actions가 아니라 **Governance Plane(Phase 4)**이 담당합니다.

### GitHub Secrets 설정

| Secret | 설명 |
|---|---|
| `DOCKER_USERNAME` | Docker Hub 사용자명 |
| `DOCKER_TOKEN` | Docker Hub 액세스 토큰 |
| `KUBECONFIG` | K8s kubeconfig (base64 인코딩) |

---

## 보안 설계

- **Namespace 격리**: Phase별 전용 네임스페이스, default-deny NetworkPolicy
- **RBAC**: 최소 권한 원칙, Phase별 전용 ServiceAccount + Role
- **mTLS**: Istio PeerAuthentication STRICT 모드
- **Runtime 탐지**: Falco (Shell, 파일 변조, 권한 상승, 의심 네트워크)
- **ResourceQuota**: Phase별 CPU/Memory 제한

---

## 팀 구성

| 이름 | 역할 | 담당 Phase |
|---|---|---|
| 이종윤 (팀장) | 아키텍처 / 인프라 / 통제 | K8s 환경 + Phase 4 (Governance) + 모니터링/대시보드/GitOps |
| 이주오 | 탐지 / 방어 | Phase 1 (Runtime Defense) |
| 이윤태 | AI / 검증 | Phase 2 (Secure Coding) + Phase 3 (Recovery Assurance) |
