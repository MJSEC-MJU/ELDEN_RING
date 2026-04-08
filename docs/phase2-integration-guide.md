# Phase 2 연동 가이드 (Phase 1 → Phase 2 인터페이스)

> **작성일:** 2026-04-08
>
> **대상:** Phase 2 (Secure Coding Plane) 담당자
>
> **Phase 1 버전:** 2.0.0

---

## 1. 개요

Phase 1 (Runtime Defense)은 보안 이벤트를 탐지·정규화·매핑한 후 **컨텍스트 패키지**를 Redis를 통해 Phase 2로 전달합니다. 이 문서는 Phase 2가 Phase 1의 결과물을 수신하고 활용하는 방법을 설명합니다.

### 데이터 흐름

```
ModSecurity WAF (1차 차단)
       │ audit log
       ▼
Phase 1: runtime-defense-controller
  ├─ 이벤트 정규화 (ModSecurity/Falco 어댑터)
  ├─ CWE 확정 매핑
  ├─ 소스코드 위치 매핑
  └─ 컨텍스트 패키지 조립
       │
       ▼
Redis (이중 전달)
  ├─ Pub/Sub: elden:phase2:context (실시간 알림)
  └─ List:    elden:phase2:context:queue (영속 큐)
       │
       ▼
Phase 2: 수신 → AI 패치 생성 → ...
```

---

## 2. Redis 연결 정보

| 항목 | 값 |
|---|---|
| Host | `redis-master.elden-monitoring` |
| Port | `6379` |
| Pub/Sub 채널 | `elden:phase2:context` |
| List 큐 키 | `elden:phase2:context:queue` |

클러스터 내부에서 접근 시:
```
redis-master.elden-monitoring.svc.cluster.local:6379
```

---

## 3. 수신 방법

### 3.1 권장: BRPOP (큐 기반, 메시지 유실 없음)

```python
import redis
import json

r = redis.Redis(
    host="redis-master.elden-monitoring",
    port=6379,
    decode_responses=True,
)

while True:
    # 블로킹 대기 (timeout=0이면 무한 대기)
    result = r.brpop("elden:phase2:context:queue", timeout=30)
    if result:
        _, payload = result
        context = json.loads(payload)
        print(f"Received: {context['context_id']}")
        # Phase 2 처리 로직
        process_context(context)
```

**장점**: Phase 2가 다운되어 있어도 큐에 쌓여 유실 없음. 1:1 소비 보장.

### 3.2 보조: SUBSCRIBE (실시간 알림)

```python
import redis
import json

r = redis.Redis(
    host="redis-master.elden-monitoring",
    port=6379,
    decode_responses=True,
)

pubsub = r.pubsub()
pubsub.subscribe("elden:phase2:context")

for message in pubsub.listen():
    if message["type"] == "message":
        context = json.loads(message["data"])
        print(f"Real-time alert: {context['context_id']}")
```

**주의**: Pub/Sub은 구독자가 없으면 메시지가 유실됩니다. 반드시 BRPOP과 함께 사용하세요.

### 3.3 권장 아키텍처

```python
import threading

def queue_consumer():
    """주 수신: 큐에서 하나씩 꺼내서 처리"""
    r = redis.Redis(host="redis-master.elden-monitoring", port=6379, decode_responses=True)
    while True:
        result = r.brpop("elden:phase2:context:queue", timeout=30)
        if result:
            _, payload = result
            context = json.loads(payload)
            process_context(context)

def realtime_listener():
    """보조: Pub/Sub으로 즉시 알림 수신 (대시보드 업데이트 등)"""
    r = redis.Redis(host="redis-master.elden-monitoring", port=6379, decode_responses=True)
    pubsub = r.pubsub()
    pubsub.subscribe("elden:phase2:context")
    for message in pubsub.listen():
        if message["type"] == "message":
            context = json.loads(message["data"])
            update_dashboard(context)

# 두 스레드 동시 실행
threading.Thread(target=queue_consumer, daemon=True).start()
threading.Thread(target=realtime_listener, daemon=True).start()
```

---

## 4. 컨텍스트 패키지 스키마

Phase 1이 전달하는 JSON 구조:

```json
{
  "context_id": "ctx-evt-20260408143000-a1b2c3d4",
  "event_id": "evt-20260408143000-a1b2c3d4",
  "timestamp": "2026-04-08T14:30:00+00:00",

  "attack_info": {
    "category": "SQL Injection",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
    "owasp_category": "A03:2021",
    "payload_sample": "username=admin' OR 1=1--&password=test",
    "source_ip": "192.168.1.100",
    "blocked": true
  },

  "target": {
    "endpoint": {
      "method": "POST",
      "path": "/api/login"
    },
    "source_mapping": {
      "file": "app.py",
      "function": "login_handler",
      "line_start": 28,
      "line_end": 42
    }
  },

  "metadata": {
    "severity": "CRITICAL",
    "pipeline_version": "2.0.0",
    "detection_source": "modsecurity",
    "defense_action_taken": "rate_limit+ip_blocked+endpoint_disabled",
    "requires_patch": true
  }
}
```

### 필드 설명

| 필드 | 타입 | 설명 |
|---|---|---|
| `context_id` | string | 컨텍스트 고유 ID (`ctx-` 접두사) |
| `event_id` | string | 원본 이벤트 ID (`evt-` 접두사) |
| `timestamp` | ISO 8601 | 이벤트 발생 시각 |
| `attack_info.category` | string | 공격 유형 (아래 표 참조) |
| `attack_info.cwe_id` | string | CWE 식별자 (예: `CWE-89`) 또는 `UNKNOWN` |
| `attack_info.cwe_name` | string | CWE 전체 명칭 |
| `attack_info.owasp_category` | string | OWASP Top 10 카테고리 (예: `A03:2021`) |
| `attack_info.payload_sample` | string | 공격 페이로드 샘플 (최대 500자) |
| `attack_info.source_ip` | string \| null | 공격 소스 IP |
| `attack_info.blocked` | boolean | WAF에서 차단 여부 |
| `target.endpoint.method` | string | HTTP 메서드 (또는 Falco의 경우 `SYSCALL`) |
| `target.endpoint.path` | string | 공격 대상 경로 |
| `target.source_mapping` | object \| null | 소스코드 위치. null이면 Phase 2가 풀스캔 |
| `target.source_mapping.file` | string | 소스 파일명 |
| `target.source_mapping.function` | string | 함수명 |
| `target.source_mapping.line_start` | int | 시작 라인 |
| `target.source_mapping.line_end` | int | 종료 라인 |
| `metadata.severity` | string | `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` |
| `metadata.pipeline_version` | string | Phase 1 파이프라인 버전 |
| `metadata.detection_source` | string | `modsecurity` / `falco` / `manual` |
| `metadata.defense_action_taken` | string \| null | Phase 1이 실행한 능동 대응 |
| `metadata.requires_patch` | boolean | CWE가 매핑된 경우 true → 패치 필요 |

### attack_info.category 가능한 값

| category | cwe_id | detection_source | 설명 |
|---|---|---|---|
| `SQL Injection` | CWE-89 | modsecurity | SQL 삽입 공격 |
| `Cross-Site Scripting` | CWE-79 | modsecurity | 반사형 XSS |
| `Path Traversal` | CWE-22 | modsecurity | 경로 탐색 공격 |
| `Shell Execution` | CWE-78 | falco | 컨테이너 내 쉘 실행 |
| `Privilege Escalation` | CWE-269 | falco | 권한 상승 |
| `File Tampering` | CWE-284 | falco | 파일 변조 |
| `Suspicious Network` | CWE-918 | falco | 비정상 네트워크 연결 |

---

## 5. Phase 2 활용 가이드

### 5.1 `source_mapping`이 있는 경우

Phase 1이 정확한 소스코드 위치를 제공합니다. Phase 2는 이 정보로 바로 해당 코드를 분석하고 패치를 생성하면 됩니다:

```python
def process_context(ctx):
    mapping = ctx["target"]["source_mapping"]
    if mapping:
        # 정확한 위치에서 바로 패치 생성 가능
        file_path = mapping["file"]      # "app.py"
        function = mapping["function"]    # "login_handler"
        start = mapping["line_start"]     # 28
        end = mapping["line_end"]         # 42
        
        vulnerable_code = read_source(file_path, start, end)
        patch = generate_patch(
            code=vulnerable_code,
            cwe_id=ctx["attack_info"]["cwe_id"],
            attack_category=ctx["attack_info"]["category"],
        )
```

### 5.2 `source_mapping`이 null인 경우

Falco 이벤트 등 소스코드 매핑이 불가능한 경우입니다. Phase 2가 전체 소스코드를 스캔하여 관련 취약점을 찾아야 합니다.

### 5.3 `requires_patch`가 false인 경우

CWE 매핑이 실패한(`UNKNOWN`) 경우입니다. Phase 2가 자체적으로 공격 유형을 판단해야 합니다.

---

## 6. Phase 1 API (직접 조회용)

Phase 2가 Redis 외에 직접 Phase 1 API를 호출할 수도 있습니다:

| 엔드포인트 | Method | 설명 |
|---|---|---|
| `/api/v1/contexts/latest?limit=20` | GET | 최근 컨텍스트 목록 |
| `/api/v1/contexts/{context_id}` | GET | 특정 컨텍스트 조회 |
| `/api/v1/defense/actions?limit=50` | GET | 능동 대응 이력 |
| `/api/v1/defense/stats` | GET | IP별/엔드포인트별 공격 횟수 |
| `/api/v1/events/stats` | GET | 이벤트 통계 |

클러스터 내부 접근:
```
http://runtime-defense-controller.elden-production.svc.cluster.local:8080
```

---

## 7. 테스트 방법

### 7.1 수동 이벤트 주입으로 Phase 1 → Phase 2 파이프라인 테스트

```bash
# 1. Phase 1에 수동 이벤트 주입
curl -X POST http://runtime-defense-controller:8080/api/v1/events/manual \
  -H "Content-Type: application/json" \
  -d '{
    "source": "manual",
    "attack_category": "SQL Injection",
    "target_endpoint": {"method": "POST", "path": "/api/login"},
    "payload_sample": "username=admin'\'' OR 1=1--",
    "source_ip": "192.168.1.100",
    "severity": "CRITICAL"
  }'

# 2. Redis 큐에서 컨텍스트 수신 확인
redis-cli -h redis-master.elden-monitoring BRPOP elden:phase2:context:queue 5
```

### 7.2 실제 공격 시뮬레이션

```bash
# SQL Injection (ModSecurity가 차단 → Phase 1 수신 → Redis 전달)
curl -X POST http://target-app.elden.local/api/login \
  -d "username=admin' OR 1=1--&password=test"

# XSS
curl "http://target-app.elden.local/api/search?q=<script>alert(1)</script>"

# Path Traversal
curl "http://target-app.elden.local/api/file?name=../../etc/passwd"
```

---

## 8. 주의사항

1. **Redis 큐는 BRPOP으로 소비**: `RPOP`을 루프에서 돌리면 busy-wait가 됩니다. `BRPOP`(블로킹)을 사용하세요.
2. **메시지 순서**: List 큐는 FIFO(LPUSH + BRPOP)로 동작합니다. 이벤트 순서가 보장됩니다.
3. **중복 처리**: Phase 1은 이벤트마다 고유한 `context_id`를 부여합니다. 중복 체크가 필요하면 이 ID를 사용하세요.
4. **source_mapping null 처리**: 반드시 null 체크를 하세요. Falco 이벤트는 소스 매핑이 없습니다.
5. **pipeline_version 호환성**: `metadata.pipeline_version`으로 스키마 버전을 확인하세요. 현재 `2.0.0`입니다.
