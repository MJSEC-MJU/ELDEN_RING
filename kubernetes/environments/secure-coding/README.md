# Secure Coding Plane - 이윤태

> 담당: 정적 분석, LLM 패치 생성, 후보 이미지 빌드, 검증 시나리오 자동화

---

## 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-secure-coding` |
| ServiceAccount | `secure-coding-sa` |
| CPU 제한 | requests 2 / limits 4 |
| Memory 제한 | requests 4Gi / limits 8Gi |
| 최대 Pod | 15 |
| 최대 Job | 10 |

## 현재 배포 구성

`secure-coding.yaml`은 Phase 2 API와 Redis worker를 같은 Pod에 배포합니다.

| 컴포넌트 | 설명 | K8s 리소스 |
|---|---|---|
| API | 수동/관리 API, health check | Deployment container + Service |
| Redis worker | Phase 1 context 수신, Phase 3 validation 발행, Phase 3 retry 수신 | Deployment sidecar container |

기본 배포값은 시연 안정성을 위해 `SECURE_CODING_LLM_PROVIDER=mock`, `SECURE_CODING_BUILD_MODE=simulate`입니다. 실제 LLM/이미지 빌드를 쓰려면 컨테이너에 CLI/인증/빌드 권한을 넣고 환경변수를 `codex`/`command`로 바꿔야 합니다.

## Phase 1에서 받는 데이터

```json
{
  "event_id": "evt-20260321-001",
  "cwe": { "id": "CWE-89", "name": "..." },
  "source_location": { "file": "src/auth/login.py", "function": "login_handler", "line": 42 },
  "payload_sample": "username=admin' OR 1=1--"
}
```

## Phase 3으로 전달하는 데이터

```json
{
  "event_id": "evt-20260321-001",
  "patch_id": "patch-001",
  "candidate_image": "ghcr.io/mjsec-mju/elden-target-app:candidate-evt-20260321-001-patch-001",
  "change_summary": { "files_changed": 1, "functions_changed": ["login_handler"] },
  "patch_status": "READY_FOR_VALIDATION"
}
```

## 네트워크 접근 범위

```
허용:
  - elden-governance에서 작업 트리거 수신
  - elden-harness에서 배포
  - HTTPS(443) → 외부 LLM API 호출용
  - DNS(53)
차단:
  - elden-production 직접 접근 불가
  - elden-staging 직접 접근 불가
```

## 배포 방법

```bash
kubectl apply -f kubernetes/environments/secure-coding/
```
