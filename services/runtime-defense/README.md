# Phase 1: Runtime Defense - 이주오

> 위협 탐지, 이벤트 정규화, CWE 매핑, 소스코드 매핑, 컨텍스트 패키지 생성

## 구조

```
services/runtime-defense/
├── src/                  # 애플리케이션 코드
│   └── main.py
├── tests/                # 테스트
├── Dockerfile
├── requirements.txt
└── README.md
```

## 개발

```bash
cd services/runtime-defense
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8080
```

## 빌드

```bash
docker build -t eldenring/runtime-defense:dev .
```

## K8s 매니페스트

K8s 매니페스트는 `kubernetes/environments/production/` 에 작성:
- `runtime-defense.yaml` (Deployment + Service)

## 보안

### 웹훅 인증 (Bearer 토큰)

이벤트 주입 엔드포인트(`/api/v1/modsec-events`, `/api/v1/falco-events`,
`/api/v1/events/manual`)는 Bearer 토큰 인증이 필요합니다.

토큰은 `WEBHOOK_AUTH_TOKEN` 환경변수로 주입되며, 프로덕션에서는
`runtime-defense-secrets` K8s Secret 의 `webhook-auth-token` 키를 통해 참조합니다.
`WEBHOOK_AUTH_TOKEN`이 비어 있으면 인증이 **비활성화**되며 시작 시 경고가
로깅됩니다 (로컬 개발용).

```
Authorization: Bearer <token>
```

### 토큰 회전

```bash
NEW_TOKEN=$(openssl rand -hex 32)

# 1) Secret 갱신
kubectl create secret generic runtime-defense-secrets \
  --namespace=elden-production \
  --from-literal=webhook-auth-token="$NEW_TOKEN" \
  --dry-run=client -o yaml | kubectl apply -f -

# 2) Pod 재시작 (Secret 변경 반영)
kubectl rollout restart deployment/runtime-defense-controller -n elden-production

# 3) Falco Sidekick customheaders 동기화
#    kubernetes/security/falco/values.yaml 의 customheaders 값을 수정 후:
helm upgrade falco falcosecurity/falco -n falco -f kubernetes/security/falco/values.yaml
```

### 컨테이너 격리

- 비루트 실행 (UID/GID 1000)
- `readOnlyRootFilesystem: true`
- 모든 Linux capability drop, `seccompProfile: RuntimeDefault`
- `/tmp`, `/home/app/.kube` 만 emptyDir로 쓰기 허용

## 신뢰성

### Redis 메모리 백업 + 자동 드레인

Redis 일시 장애 시 컨텍스트는 in-memory deque(상한 1000개, FIFO,
초과 시 가장 오래된 항목 폐기)에 백업된다. 백그라운드 드레인 태스크가
30초마다 Redis 연결을 확인하고 백업을 다시 전송한다.

진단:

```bash
curl -s http://localhost:8080/diagnostics | jq .redis
# {
#   "connected": true,
#   "backup_pending": 0,
#   "backup_dropped_total": 0
# }
```

### Readiness 정책

`/readyz`는 어댑터/route-map 로드 여부만 확인하고 항상 200을 반환한다.
Redis 다운으로 readiness 를 실패시키면 Pod 이 Service 에서 빠져
Falco/ModSec 웹훅 자체를 잃기 때문에, **Redis 장애에도 readiness 는
유지하고 메모리 백업으로 흡수**하는 것이 더 안전하다. Redis 상태는
`/diagnostics` 에서 확인.

### 가용성

- `replicas: 2` + `maxUnavailable: 0` 롤링 → 항상 최소 1대 가용
- HPA(`runtime-defense-hpa.yaml`): CPU 70% / Mem 80% 임계, 2~5대
- 스케일다운은 5분 안정화 (메모리 백업 큐 유실 방지)

## 관측성

### 구조화된 JSON 로깅

모든 로그 라인은 stdout 으로 JSON 한 줄씩 출력 (Loki 파싱 친화).
필드: `timestamp`, `level`, `name`, `message`, `trace_id`, 그리고
`extra=` 로 전달한 임의 필드. Phase 1 진입 시 12자리 hex trace_id
를 발급해 같은 요청에서 발생한 모든 로그가 같은 trace_id 를 갖는다.

### 비즈니스 메트릭 (`/metrics`)

| 메트릭 | 타입 | 라벨 | 설명 |
|---|---|---|---|
| `runtime_defense_events_total` | Counter | source, attack_category, severity | 이벤트 수신/정규화 카운트 |
| `runtime_defense_actions_total` | Counter | action | 실행된 능동 방어 조치 |
| `runtime_defense_pipeline_duration_seconds` | Histogram | source | 파이프라인 E2E 시간 |
| `runtime_defense_redis_publish_seconds` | Histogram | - | Redis publish 시간 |
| `runtime_defense_redis_backup_pending` | Gauge | - | 메모리 백업 대기 큐 크기 |
| `runtime_defense_redis_backup_dropped_total` | Counter | - | 백업 큐 가득 차서 폐기된 수 |

prometheus-fastapi-instrumentator 의 기본 HTTP 메트릭과 함께 노출.

### 비차단 Redis 발행

`redis_pub.publish_context` 는 `asyncio.to_thread` 로 워커 스레드에서
실행 → Redis I/O 가 이벤트 루프를 막지 않음. 여러 요청을 동시에
처리해도 Redis 연결 1개의 LPUSH+PUBLISH 가 직렬화되지 않는다.

## CI 자동화

`services/runtime-defense/**` 변경 시 자동 빌드/배포됨 (dev 브랜치 push)
