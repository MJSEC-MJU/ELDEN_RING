# Phase 1 Cross-Team Handoffs

Phase 1 작업 중 다른 담당자(시스템/Phase 2/3/4) 영역과 맞물리는 작업을 모아둔 파일.
Phase 1 단독 PR에는 포함하지 않고, 해당 담당자에게 별도로 전달한다.

---

## H-001: Falco Sidekick 웹훅 인증 헤더 추가 필요

**대상**: 이종윤 (System / `kubernetes/security/falco/values.yaml`)
**연관 Phase 1 작업**: B1-① 웹훅 엔드포인트 인증 추가

### 배경

Phase 1 의 `/api/v1/falco-events` 엔드포인트에 Bearer 토큰 인증을
추가했다. `runtime-defense-secrets` Secret 의 `webhook-auth-token`
값과 일치하는 `Authorization: Bearer <token>` 헤더를 가진 요청만
수락한다.

토큰이 비어 있으면 인증은 비활성화 모드로 동작하므로 현재 dev/staging
배포는 즉시 깨지지 않는다. **그러나 프로덕션에서 Secret 의 토큰을
실제 값으로 회전한 시점부터 Falco 이벤트 수신이 401 로 실패한다.**

### 요청 사항

`kubernetes/security/falco/values.yaml` 의 `falcosidekick.config.webhook`
블록에 customheaders 를 추가하고, runtime-defense-secrets 와 동일한
토큰을 동기화해 주세요.

```yaml
falcosidekick:
  config:
    webhook:
      address: "http://runtime-defense-controller.elden-production:8080/api/v1/falco-events"
      customheaders: "Authorization:Bearer <RUNTIME_DEFENSE_WEBHOOK_TOKEN>"
```

### 토큰 회전 시 동기화 절차

1. `kubectl create secret generic runtime-defense-secrets --from-literal=webhook-auth-token=<NEW>` (`elden-production`)
2. `kubernetes/security/falco/values.yaml` 의 customheaders 갱신
3. `helm upgrade falco falcosecurity/falco -n falco -f .../values.yaml`
4. `kubectl rollout restart deployment/runtime-defense-controller -n elden-production`

토큰이 두 곳(K8s Secret + Falco Helm values)에서 분리 관리되는
점은 향후 ExternalSecrets 또는 SealedSecrets 도입 시 일원화 검토.

### 우선순위

| 환경 | 우선순위 |
|------|----------|
| dev / kind | Low (토큰 미설정 시 인증 비활성, 동작 무영향) |
| staging | Medium (토큰 활성화 직전까지) |
| production | **High** (토큰 회전 시점에 동기화 필수) |

---

## H-002: trace_id Phase 2/3/4 전파 합의 필요

**대상**: 이윤태(Phase 2 / Phase 3), 이종윤(Phase 4)
**연관 Phase 1 작업**: B3-⑤ 구조화된 JSON 로깅

### 배경

Phase 1 의 `run_pipeline` 진입 시점에 12자리 hex `trace_id`를 생성하여:

1. 모든 로그 라인에 `trace_id` 필드로 노출 (구조화 로깅)
2. Redis 로 발행되는 컨텍스트 패키지의 `metadata.trace_id` 에 포함

각 단계에서 같은 trace_id 로 로그를 검색하면 Phase 1→2→3→4 전체
요청 경로를 한번에 추적할 수 있다. 단, **현재 Phase 1 만 채워 보내고
하류 Phase 들은 사용/전파하지 않는다**.

### 요청 사항

각 Phase 가 수신한 컨텍스트의 `metadata.trace_id` 를:

1. 자기 Phase 의 모든 로그 라인에 동일 필드로 포함시켜 발행
2. 다음 Phase 로 보내는 메시지에 그대로 propagate

```python
# 예시: Phase 2 worker 의 로그 설정
trace_id = context["metadata"].get("trace_id", "")
logger = logger.bind(trace_id=trace_id)  # structlog
# 또는
logging.LoggerAdapter(logger, {"trace_id": trace_id})
```

### 인터페이스 호환성

- 추가형 변경 (additive) — Phase 2 가 무시해도 동작 무영향
- 필드 누락 시 빈 문자열 fallback. 깨질 일 없음

### 우선순위

| 항목 | 우선순위 |
|------|----------|
| 즉시 적용 | Low (현재 Phase 1 단독 추적만 가능, 합의 후 전파해도 늦지 않음) |
| 운영 사고 시 추적성 | **Medium** — 사고 RCA 가속을 위해 합의 권장 |
