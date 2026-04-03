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

## 이 폴더에 올릴 것

### 필요한 컴포넌트

| 컴포넌트 | 설명 | K8s 리소스 |
|---|---|---|
| Context Receiver | Phase 1에서 컨텍스트 수신 | Deployment + Service |
| Code Analyzer | Semgrep/AST 정적 분석 | Job |
| Patch Generator | LLM 패치 생성 + 정적 재검사 | Job |
| Image Builder | 후보 이미지 빌드 | Job |

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
  "candidate_image": "registry.local/app/target-app:candidate-evt-20260321-001-v1",
  "change_summary": { "files_changed": 1, "functions_changed": ["login_handler"] },
  "status": "ready_for_validation"
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
kubectl apply -f kubernetes/environments/secure-coding/<매니페스트>.yaml
```
