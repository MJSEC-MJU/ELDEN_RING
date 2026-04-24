# 주차별 진행 보고 — Phase 4 Governance Plane 스캐폴딩

- **담당:** 이종윤 (ialleejy)
- **기간:** ~ 2026-04-12
- **브랜치:** `feature/phase4-governance-scaffold`
- **상위 목표:** AI 자동 방어 파이프라인의 운영 승격 계층(Phase 4) 구축

---

## 1. 이번 주 목표

Phase 1~3 (탐지 → 패치 생성 → 검증) 은 이미 dev에 머지된 상태. 본 주차는 마지막 단계인 **Governance Plane** 의 3계층 아키텍처 설계 + 코드/매니페스트 스캐폴딩.

요구사항(요약):

1. **정책 검증** — AI 가 생성한 패치/정책 후보의 권한 상승·스키마·기존 서비스 충돌 여부 검사
2. **GitOps 관리** — 검증된 변경을 Git 단일 진실원에 저장, shadow → prod 승격 이력 추적
3. **배포 통제** — canary 비율 제어, 자동/수동 승인 분기, SLO 위반 시 자동 롤백

---

## 2. 설계 원칙 (의도적 3계층 분리)

각 계층이 **한 가지 관심사만** 처리하도록 의도적으로 분리. 후속 유지보수/책임 범위를 명확히 하기 위함.

| 계층 | 역할 | 도구 | 통제 범위 |
|---|---|---|---|
| **A. 정책 검증** | 정책/권한/구성 적합성 | Kyverno | admission-time 검사, fail-closed |
| **B. GitOps**    | 선언적 상태 + 승격 이력 | ArgoCD | shadow/prod 브랜치 기반 동기화 |
| **C. 배포 통제** | 승격 게이트 + canary + rollback | Argo Rollouts | 트래픽 비율, 수동 승인 |

**원칙:** 정책 엔진이 Rollout 상태를 건드리지 않고, Rollout 컨트롤러가 Git 을 조회하지 않는다. Git 은 항상 단일 진실원.

---

## 3. 산출물 요약

### 3.1 Kubernetes 매니페스트 (총 22개 YAML)

```
kubernetes/governance/
├── a-policy-validation/         (Kyverno + 5 ClusterPolicy + 1 PolicyException)
├── b-gitops/                    (ArgoCD + AppProject + ApplicationSet + 2 App + RBAC)
└── c-deployment-control/        (Argo Rollouts + AnalysisTemplate + Rollout + Istio + Policy CM + RBAC)
kubernetes/environments/governance/
└── governance-controller.yaml   (오케스트레이터 Deployment/Service/Secret)
```

주요 ClusterPolicy:

- `elden-no-privilege-escalation` — `privileged`, `allowPrivilegeEscalation`, `hostPID/hostNetwork/hostIPC` 차단
- `elden-image-signature-required` — 승인 레지스트리만 허용 + cosign keyless 서명 검증
- `elden-networkpolicy-schema` — `podSelector` 필수, prod/canary 에서 전체 허용 금지
- `elden-no-conflict-with-existing` — 운영 core Service selector/port, VirtualService host 보호
- `elden-rbac-escalation-guard` — wildcard verb, secrets write, anonymous 바인딩 차단

Argo Rollouts 카나리 스텝: `10% → 분석 → 30% → 분석 → 50% → [수동pause] → 100%`
Prometheus 분석 기준: `error_rate < 5%`, `p99 latency < 1000ms`, `exploit_replay_pass == 1`

### 3.2 Governance Orchestrator 서비스 (Python/FastAPI)

```
services/governance/src/
├── main.py              (FastAPI endpoints)
├── config.py            (GOV_* env 설정)
├── models.py            (RiskClass, Phase3Result, PromotionRequest)
├── orchestrator.py      (A→B→C 상태머신)
├── risk_classifier.py   (low/medium/high fail-closed)
├── git_writer.py        (defense/inc-<id> 브랜치 + PR 자동 생성)
├── policy_gate.py       (Kyverno PolicyReport 집계)
├── promotion_gate.py    (Rollout pause/resume/abort)
├── rollback_watcher.py  (Prometheus SLO 감시 → auto abort)
└── k8s_client.py        (CoreV1 + CustomObjectsApi 래퍼)
```

API endpoint:

| Method | Path | Purpose |
|---|---|---|
| GET  | `/healthz`, `/readyz`, `/metrics` | liveness / readiness / Prometheus |
| GET  | `/incidents` | 진행중 승격 리스트 |
| POST | `/incidents/{id}/approve` | 고위험 변경 수동 승인 |
| POST | `/incidents/{id}/rollback` | 강제 롤백 |

### 3.3 문서

- `docs/phase4-governance-guide.md` — 설치 순서, 흐름도, API 명세, Phase 3 → 4 데이터 계약
- `kubernetes/governance/README.md` — 3계층 인덱스

---

## 4. 엔드투엔드 데이터 흐름

```
Phase 3 PASSED ─ Redis(elden:phase4:promote) ──▶ orchestrator
                                                      │
                              ┌───────────────────────┼──────────────────────┐
                              ▼                       ▼                      ▼
                    risk_classifier          git_writer(B)          policy_gate(A)
                    (low/med/high)           defense/inc-<id>       Kyverno Reports
                                             + PR label             집계
                                                      │                      │
                                                      ▼                      ▼
                                             ArgoCD ApplicationSet  pass/fail
                                             sync → elden-canary           │
                                                      │                     │
                                                      ▼                     ▼
                                              Argo Rollouts(C)       fail → publish
                                              canary steps +         elden:phase2:retry
                                              AnalysisTemplate
                                                      │
                                                      ▼
                                         low/med: auto-resume
                                         high   : 수동 /approve 대기
                                                      │
                                                      ▼
                                         dev→main 머지 → elden-prod App sync
                                                      │
                                                      ▼
                                   rollback_watcher: Prometheus SLO 감시,
                                   2회 연속 breach 시 abort
```

---

## 5. 검증 결과

| 항목 | 결과 |
|---|---|
| YAML 구문 검사 (24개) | **24/24 PASS** |
| Kustomization resource 경로 (21개) | **21/21 OK** |
| Python 모듈 컴파일 (10개) | **all PASS** |
| risk_classifier 분류 테스트 (7 케이스) | **7/7 PASS** |
| kubectl 서버 스키마 검증 | 로컬 클러스터 미기동, CI `pr-validation.yaml` 에서 수행 예정 |

분류 테스트 커버리지:
- RBAC → HIGH
- Deployment(image change) → HIGH
- Deployment(config-only) → MEDIUM
- VirtualService → MEDIUM
- WAF ConfigMap (modsecurity/rate-limit/waf-*) → LOW
- NetworkPolicy, EnvoyFilter → LOW
- 알 수 없는 kind → HIGH (fail-closed)

---

## 6. Git 이력

브랜치 `feature/phase4-governance-scaffold` 에 4개 커밋으로 계층별 분리:

```
fa85060  feat(phase4): add governance orchestrator service + deployment + guide
c6c3cb9  feat(phase4-C): add Argo Rollouts deployment-control layer
aa2d662  feat(phase4-B): add ArgoCD GitOps layer
92648eb  feat(phase4-A): add Kyverno policy-validation layer
```

---

## 7. 다음 주차 계획

1. **PR 분할 전략 확정** — 2-PR 옵션(인프라 통합 / 오케스트레이터) vs 4-PR 순차 중 팀 리뷰 후 결정
2. **클러스터 실배포 smoke** — kind 에 A/B/C 순차 설치 후 dummy Phase 3 ConfigMap 으로 end-to-end 트리거
3. **GitHub Token Secret 주입** — ArgoCD ApplicationSet `github-token` secret 생성 절차 (Harness Secret Manager 연동)
4. **CI 통합** — `.github/workflows/pr-validation.yaml` 에 kubeval + Kyverno 정책 lint 단계 추가
5. **Grafana 대시보드** — `governance-promotion.json` 작성 (승격 이력, 활성 incident, rollback 카운트)
6. **고위험 승인 UX** — 현재 API endpoint 만 있음. Slack 승인 봇은 MVP 범위 밖으로 확정했지만, 대체로 GitHub PR review UX 정교화 필요

---

## 8. 확정된 의사결정

- **정책 엔진:** Kyverno (YAML 기반, 팀 러닝커브 낮음). OPA/Gatekeeper 미도입.
- **브랜치 전략:** `defense/inc-<id>` → `dev` PR (`defense-candidate` label) → `main` merge 시 prod 승격
- **수동 승인 채널:** GitHub PR review (Slack 봇 범위 밖, 추후 검토)
- **위험도 분류 기본값:** fail-closed (알 수 없는 리소스 → HIGH)
- **롤백 트리거:** error_rate > 5% 또는 p99 > 1000ms 2회 연속 시 자동 abort

---

## 9. 리스크 / 남은 이슈

- ArgoCD ApplicationSet 의 `github-token` Secret 은 아직 미생성 — B 계층 실배포 전 필수
- 기존 `elden-governance` ClusterRole (`base/rbac.yaml`) 이 `elden-staging` ConfigMap 읽기 권한을 포함하지 않음 — 별도 확장 필요 (수정 PR 따로 낼지, B 계층 PR 에 포함할지 결정 대기)
- Argo Rollouts 도입 시 기존 `elden-production` 의 target-app Deployment 를 Rollout 으로 마이그레이션 필요 — 운영 중단 리스크, 별도 스크립트 준비 필요
- Kyverno `verifyImages` 규칙이 현재 빈 레지스트리 (`ghcr.io/mjsec-mju/*`) 를 가정 — 실제 서명 워크플로우 (`.github/workflows/` 의 cosign 단계) 미구현 상태
