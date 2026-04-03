# Phase 1: Runtime Defense Plane - 개발 계획서

> **최종 수정:** 2026-04-03
>
> **상태:** 인프라 이슈 해결 완료, 개발 착수 가능

---

## 1. 최종 결과물

`elden-production` 네임스페이스에서 동작하는 `runtime-defense-controller` 서비스.

```
Falco 이벤트 수신 → 정규화 → CWE 매핑 → 소스코드 매핑 → 컨텍스트 패키지 생성 → Phase 2 전달
                                                                          (동시에) → 긴급 대응 실행
```

### 핵심 기능

| 기능 | 설명 |
|---|---|
| 이벤트 수신 | Falco Sidekick webhook 수신 + 범용 이벤트 수신 + 시연용 수동 주입 |
| 이벤트 정규화 | 어댑터 패턴으로 다양한 보안 솔루션 로그를 통일 스키마로 변환 |
| CWE 확정 매핑 | Rule Table 기반 100% 확정 매핑 (임베딩/유사도 아님) |
| 소스코드 매핑 | 공격 대상 URL 엔드포인트 → 소스코드 file:function:line 매핑 |
| 컨텍스트 패키지 | 위 결과를 구조화된 JSON으로 조립하여 Phase 2에 전달 |
| 긴급 대응 | severity 기반 Lv.1~3 단계적 대응 (NetworkPolicy, Rate Limit, Degrade Mode) |

### 설계 결정 사항

| 항목 | 결정 | 이유 |
|---|---|---|
| Phase 2 전달 경로 | Redis Pub/Sub 경유 | 인프라에 Redis 메시지 브로커 추가됨 (`redis-master.elden-monitoring:6379`). Phase 1이 `elden:phase2:context` 채널에 PUBLISH → Phase 2가 SUBSCRIBE. NetworkPolicy에 Redis 통신 허용 완료 |
| 이벤트 소스 | Falco 우선 | 인프라에 Falco Sidekick → webhook 연동이 이미 구성됨. 어댑터 패턴으로 향후 ModSecurity/Snort 확장 가능 |
| 저장소 | 인메모리 (MVP) | 인프라에 PostgreSQL 미구성. CWE 9개 행은 Python dict, 이벤트 이력은 인메모리 리스트로 시연 범위에 충분. 필요 시 후속 추가 |
| 소스코드 접근 | ConfigMap + 로컬 파서 이원화 | K8s 내에서 Git clone은 Egress 차단. 로컬에서 AST 파싱 후 결과를 ConfigMap으로 주입 |
| API 경로 | `/api/v1/falco-events` + `/api/v1/events/ingest` 병행 | Falco Sidekick에 전자가 하드코딩됨. 후자는 범용/확장용 |

---

## 2. 인프라 환경 연동

Phase 1은 모노레포 최상위의 `kubernetes/` 디렉토리에 구성된 K8s 인프라 위에서 동작합니다. (기존 `elden-ring-infra` 레포의 내용이 최상위로 통합됨) 아래는 인프라에서 이미 제공하는 것과 Phase 1이 추가로 만들어야 하는 것의 구분입니다.

### 인프라에서 이미 제공되는 것

| 항목 | 파일 | 내용 |
|---|---|---|
| 네임스페이스 | `kubernetes/base/namespaces.yaml` | `elden-production` (istio-injection: enabled) |
| RBAC | `kubernetes/base/rbac.yaml` | `runtime-defense-sa` + NetworkPolicy/Istio CRUD 권한 |
| NetworkPolicy | `kubernetes/base/network-policies.yaml` | default-deny + 허용 규칙 |
| ResourceQuota | `kubernetes/base/resource-quotas.yaml` | CPU 8, Memory 16Gi, Pod 30개 |
| LimitRange | `kubernetes/base/resource-quotas.yaml` | 컨테이너당 기본 CPU 500m, Memory 512Mi |
| Falco 규칙 | `kubernetes/security/falco/values.yaml` | Shell, 네트워크, 파일변조, 권한상승, SQLi 탐지 |
| Falco Sidekick | `kubernetes/security/falco/values.yaml` | → `runtime-defense-controller:8080/api/v1/falco-events` webhook |
| Istio | `kubernetes/service-mesh/istio/` | mTLS STRICT, AuthorizationPolicy |
| Redis | `kubernetes/messaging/redis/values.yaml` | Phase 간 메시지 브로커 (`redis-master.elden-monitoring:6379`) |
| 보호 대상 서비스 | `kubernetes/environments/production/deployment.yaml` | target-app (3 replicas + HPA) |

### Phase 1이 추가로 만드는 것

| 항목 | 위치 | 설명 |
|---|---|---|
| 애플리케이션 코드 | `services/runtime-defense/` | FastAPI 서버 (Python) |
| K8s 매니페스트 | `kubernetes/environments/production/runtime-defense.yaml` | Deployment + Service |
| 라우트맵 ConfigMap | `kubernetes/environments/production/route-map-configmap.yaml` | 엔드포인트 → 소스코드 매핑 데이터 |

### K8s 매니페스트 작성 시 준수사항

```yaml
# 필수 설정
namespace: elden-production
serviceAccountName: runtime-defense-sa
labels:
  elden-ring/plane: runtime-defense

# 리소스 (LimitRange 기본값 이내 또는 명시 지정)
resources:
  requests:
    cpu: 200m
    memory: 256Mi
  limits:
    cpu: 500m
    memory: 512Mi

# Prometheus 메트릭 수집용 annotation
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8080"
  prometheus.io/path: "/metrics"
```

---

## 3. 디렉토리 구조

앱 코드와 K8s 매니페스트가 분리된 구조. CI(`dev-ci.yaml`)에서 Phase 1의 빌드 설정:
- 변경 감지: `services/runtime-defense/**`
- 빌드 컨텍스트: `services/runtime-defense/`
- Docker 이미지: `eldenring/runtime-defense:dev-<sha>`

### 앱 코드 (`services/runtime-defense/`)

```
services/runtime-defense/
├── src/
│   ├── __init__.py
│   ├── main.py                     # FastAPI 진입점
│   ├── config.py                   # 환경변수 기반 설정
│   ├── models.py                   # Pydantic 스키마
│   ├── adapters/
│   │   ├── __init__.py
│   │   ├── base.py                 # SecurityEventAdapter 인터페이스
│   │   └── falco.py                # Falco 어댑터
│   ├── normalizer.py               # 이벤트 정규화
│   ├── cwe_mapping.py              # CWE Rule Table
│   ├── route_parser.py             # Flask/Express/Spring AST 파서
│   ├── context_builder.py          # 컨텍스트 패키지 생성
│   ├── redis_publisher.py          # Redis Pub/Sub 전달 클라이언트
│   └── defense/
│       ├── __init__.py
│       ├── manager.py              # 긴급 대응 오케스트레이션
│       ├── network_policy.py       # Lv.1 세션 격리
│       ├── rate_limiter.py         # Lv.2 IP 차단
│       └── degrade_mode.py         # Lv.3 축소 운영
├── tests/
│   ├── __init__.py
│   ├── test_normalizer.py
│   ├── test_cwe_mapping.py
│   ├── test_route_parser.py
│   ├── test_context_builder.py
│   └── test_defense.py
├── Dockerfile
├── requirements.txt
└── README.md
```

### K8s 매니페스트 (`kubernetes/environments/production/`)

```
kubernetes/environments/production/
├── deployment.yaml                 # (기존) target-app
├── README.md                       # (기존)
├── runtime-defense.yaml            # (추가) Phase 1 Deployment + Service
└── route-map-configmap.yaml        # (추가) 라우트맵 데이터
```

---

## 4. 파이프라인 상세 설계

### 4.1 전체 처리 흐름

```
Falco Sidekick (webhook)
       │
       ▼
┌─────────────────┐
│  Step 1          │
│  이벤트 수신      │  → /api/v1/falco-events 로 JSON 수신
│  + 정규화         │  → Falco 어댑터가 NormalizedEvent로 변환
└────────┬────────┘
         │                    ┌─────────────────┐
         ├───────────────────▶│  긴급 대응        │  (병렬 실행)
         │                    │  severity 판단    │  → Lv.1/2/3 대응
         ▼                    └─────────────────┘
┌─────────────────┐
│  Step 2          │
│  CWE 확정 매핑   │  → Rule Table 조회, 100% 확정
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Step 3          │
│  소스코드 매핑    │  → ConfigMap의 라우트맵 조회
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Step 4          │
│  컨텍스트 패키지  │  → JSON 조립 → Redis PUBLISH
│  생성 & 전달     │  → elden:phase2:context 채널
└─────────────────┘
```

### 4.2 Step 1: Falco 이벤트 수신 + 정규화

#### Falco Sidekick이 보내는 JSON 형식

Falco Sidekick은 아래 형식으로 webhook을 보냅니다:

```json
{
  "uuid": "5c7e5c30-8b4a-4e5a-9b2f-1a2b3c4d5e6f",
  "output": "Shell spawned in production (user=root container=target-app namespace=elden-production pod=target-app-7d8f9 command=bash)",
  "priority": "Critical",
  "rule": "ELDEN Shell Spawned in Production",
  "time": "2026-03-21T14:30:00.000000000Z",
  "output_fields": {
    "user.name": "root",
    "container.name": "target-app",
    "k8s.ns.name": "elden-production",
    "k8s.pod.name": "target-app-7d8f9",
    "proc.cmdline": "bash",
    "proc.name": "bash",
    "fd.name": "",
    "fd.sport": ""
  },
  "tags": ["runtime-defense", "shell"]
}
```

Falco 규칙별 탐지 대상 (`kubernetes/security/falco/values.yaml`):

| Falco 규칙 | priority | tags | 매핑할 attack_category |
|---|---|---|---|
| ELDEN Shell Spawned in Production | CRITICAL | shell | Shell Execution |
| ELDEN Unexpected Outbound Connection | WARNING | network | Suspicious Network |
| ELDEN Filesystem Modification in Production | ERROR | filesystem | File Tampering |
| ELDEN Privilege Escalation Attempt | CRITICAL | privilege-escalation | Privilege Escalation |
| ELDEN SQL Injection Pattern | CRITICAL | sqli | SQL Injection |

#### 어댑터 인터페이스

```python
# adapters/base.py
from abc import ABC, abstractmethod
from models import NormalizedEvent

class SecurityEventAdapter(ABC):
    @abstractmethod
    def can_handle(self, raw_log: dict) -> bool:
        """이 어댑터가 처리할 수 있는 로그인지 판별"""
        pass

    @abstractmethod
    def parse(self, raw_log: dict) -> NormalizedEvent:
        """솔루션별 로그를 정규화 스키마로 변환"""
        pass
```

#### Falco 어댑터 구현

```python
# adapters/falco.py
FALCO_CATEGORY_MAP = {
    "shell": "Shell Execution",
    "network": "Suspicious Network",
    "filesystem": "File Tampering",
    "privilege-escalation": "Privilege Escalation",
    "sqli": "SQL Injection",
}

class FalcoAdapter(SecurityEventAdapter):
    def can_handle(self, raw_log: dict) -> bool:
        return "rule" in raw_log and "output_fields" in raw_log

    def parse(self, raw_log: dict) -> NormalizedEvent:
        tags = raw_log.get("tags", [])
        category = "Unknown"
        for tag in tags:
            if tag in FALCO_CATEGORY_MAP:
                category = FALCO_CATEGORY_MAP[tag]
                break

        return NormalizedEvent(
            event_id=generate_event_id(),
            timestamp=raw_log["time"],
            source="falco",
            attack_category=category,
            target_endpoint=self._extract_endpoint(raw_log),
            payload_sample=raw_log.get("output", ""),
            source_ip=self._extract_ip(raw_log),
            blocked=False,
            severity=self._map_priority(raw_log["priority"]),
            raw_rule_id=raw_log["rule"],
        )

    def _map_priority(self, priority: str) -> str:
        mapping = {"Critical": "CRITICAL", "Error": "HIGH", "Warning": "MEDIUM"}
        return mapping.get(priority, "LOW")
```

#### 정규화 스키마 (Pydantic)

```python
# models.py
from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class TargetEndpoint(BaseModel):
    method: str = "UNKNOWN"
    path: str = "UNKNOWN"

class NormalizedEvent(BaseModel):
    event_id: str
    timestamp: datetime
    source: str                    # "falco", "modsecurity", "snort"
    attack_category: str           # "SQL Injection", "Shell Execution" 등
    target_endpoint: TargetEndpoint
    payload_sample: str
    source_ip: Optional[str] = None
    blocked: bool = False
    severity: str                  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    raw_rule_id: Optional[str] = None
```

#### 수동 이벤트 주입 (시연용)

시연 시 Falco 없이도 파이프라인을 테스트할 수 있도록 직접 NormalizedEvent 형식으로 주입:

```json
POST /api/v1/events/manual
{
  "source": "manual",
  "attack_category": "SQL Injection",
  "target_endpoint": { "method": "POST", "path": "/api/login" },
  "payload_sample": "username=admin' OR 1=1--",
  "source_ip": "192.168.1.100",
  "severity": "CRITICAL"
}
```

### 4.3 Step 2: CWE 확정 매핑

Rule Table 기반. 임베딩/벡터 DB를 쓰지 않는 이유:

| 기준 | 임베딩 + 벡터 DB | Rule Table |
|---|---|---|
| 정확도 | 유사 CWE 혼동 가능 (fuzzy) | 100% 확정 매핑 |
| 대상 규모 | 웹 관련 CWE ~50개 미만 | 테이블 1개로 충분 |
| 오탐 리스크 | 유사 CWE → 잘못된 패치 유발 | 없음 |
| 인프라 비용 | 벡터 DB + 모델 필요 | 추가 인프라 없음 |

```python
# cwe_mapping.py
CWE_MAP = {
    "SQL Injection":        {"cwe_id": "CWE-89",  "cwe_name": "SQL Injection", "owasp": "A03:2021"},
    "XSS":                  {"cwe_id": "CWE-79",  "cwe_name": "Cross-site Scripting", "owasp": "A03:2021"},
    "Path Traversal":       {"cwe_id": "CWE-22",  "cwe_name": "Path Traversal", "owasp": "A01:2021"},
    "SSRF":                 {"cwe_id": "CWE-918", "cwe_name": "Server-Side Request Forgery", "owasp": "A10:2021"},
    "Command Injection":    {"cwe_id": "CWE-78",  "cwe_name": "OS Command Injection", "owasp": "A03:2021"},
    "Shell Execution":      {"cwe_id": "CWE-78",  "cwe_name": "OS Command Injection", "owasp": "A03:2021"},
    "Privilege Escalation":  {"cwe_id": "CWE-269", "cwe_name": "Improper Privilege Management", "owasp": "A04:2021"},
    "File Tampering":       {"cwe_id": "CWE-284", "cwe_name": "Improper Access Control", "owasp": "A01:2021"},
}

def map_to_cwe(attack_category: str) -> dict:
    normalized = attack_category.strip().lower()
    for key, value in CWE_MAP.items():
        if key.lower() in normalized:
            return value
    return {"cwe_id": "UNKNOWN", "cwe_name": "Unmapped Attack Type", "owasp": "UNKNOWN"}
```

### 4.4 Step 3: 소스코드 매핑

공격 대상 URL 엔드포인트를 소스코드의 file:function:line에 매핑합니다. 이 매핑이 있으면 Phase 2가 전체 코드를 스캔할 필요 없이 해당 함수만 분석하면 됩니다.

#### K8s 환경에서의 동작

라우트맵은 사전에 AST 파싱한 결과를 ConfigMap으로 마운트:

```yaml
# route-map-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: route-map
  namespace: elden-production
data:
  routes.json: |
    {
      "POST /api/login": {
        "file": "routes/auth.py",
        "function": "login_handler",
        "line_start": 42,
        "line_end": 58
      },
      "POST /api/feedback": {
        "file": "routes/feedback.py",
        "function": "submit_feedback",
        "line_start": 15,
        "line_end": 30
      }
    }
```

#### 로컬에서의 AST 파서 (Flask 기준)

라우트맵 ConfigMap을 생성하기 위한 파서. 로컬 또는 CI에서 실행:

```python
# route_parser.py
import ast, os, json

class FlaskRouteParser(ast.NodeVisitor):
    def __init__(self):
        self.routes = {}

    def visit_FunctionDef(self, node):
        for decorator in node.decorator_list:
            if isinstance(decorator, ast.Call):
                func = decorator.func
                if isinstance(func, ast.Attribute) and func.attr in ('route', 'get', 'post', 'put', 'delete'):
                    path = self._extract_path(decorator)
                    methods = self._extract_methods(decorator, func.attr)
                    for method in methods:
                        self.routes[f"{method} {path}"] = {
                            "function": node.name,
                            "line_start": node.lineno,
                            "line_end": node.end_lineno,
                        }
        self.generic_visit(node)

    def _extract_path(self, decorator) -> str:
        if decorator.args:
            return decorator.args[0].value
        return "UNKNOWN"

    def _extract_methods(self, decorator, attr) -> list:
        if attr in ('get', 'post', 'put', 'delete'):
            return [attr.upper()]
        for kw in decorator.keywords:
            if kw.arg == 'methods':
                return [elt.value.upper() for elt in kw.value.elts]
        return ["GET"]
```

매핑 실패 시(라우트맵에 없는 엔드포인트): `source_mapping`을 `null`로 설정하여 Phase 2에서 풀스캔하도록 유도.

### 4.5 Step 4: 컨텍스트 패키지 생성 & Redis 전달

Step 1~3의 결과를 조립하여 JSON으로 만들고 Redis에 PUBLISH:

```python
# context_builder.py
def build_context(event: NormalizedEvent, cwe: dict, source_map: dict | None) -> dict:
    return {
        "context_id": f"ctx-{event.event_id}",
        "event_id": event.event_id,
        "timestamp": event.timestamp.isoformat(),
        "attack_info": {
            "category": event.attack_category,
            "cwe_id": cwe["cwe_id"],
            "cwe_name": cwe["cwe_name"],
            "owasp_category": cwe.get("owasp", "UNKNOWN"),
            "payload_sample": event.payload_sample,
            "source_ip": event.source_ip,
            "blocked": event.blocked,
        },
        "target": {
            "endpoint": event.target_endpoint.model_dump(),
            "source_mapping": source_map,  # None이면 Phase 2가 풀스캔
        },
        "metadata": {
            "severity": event.severity,
            "pipeline_version": "1.0.0",
            "defense_action_taken": None,  # 긴급 대응 후 업데이트
            "requires_patch": cwe["cwe_id"] != "UNKNOWN",
        },
    }
```

```python
# redis_publisher.py
import redis, json

class RedisPublisher:
    def __init__(self, host="redis-master.elden-monitoring", port=6379):
        self.client = redis.Redis(host=host, port=port, decode_responses=True)

    def publish_context(self, context: dict):
        """Phase 2에 컨텍스트 패키지 전달"""
        self.client.publish("elden:phase2:context", json.dumps(context))

    def push_to_queue(self, context: dict):
        """백업: 전달 실패 시 큐에 저장하여 재시도"""
        self.client.lpush("elden:phase2:context:queue", json.dumps(context))
```

Redis 채널/큐 규약:

| 채널/키 | 용도 | 방식 |
|---|---|---|
| `elden:phase2:context` | 실시간 전달 | Pub/Sub (PUBLISH) |
| `elden:phase2:context:queue` | 실패 시 백업 | List (LPUSH/BRPOP) |

### 4.6 긴급 대응 상세

이벤트 수신과 동시에 severity 기반으로 대응 레벨을 판단하여 병렬 실행:

```python
# defense/manager.py
async def handle_defense(event: NormalizedEvent):
    if event.severity == "CRITICAL":
        await isolate_session(event)          # Lv.1
        await block_source_ip(event)          # Lv.2
        if is_mass_attack(event):
            await activate_degrade_mode()     # Lv.3
    elif event.severity == "HIGH":
        await isolate_session(event)          # Lv.1
        await block_source_ip(event)          # Lv.2
    elif event.severity == "MEDIUM":
        await isolate_session(event)          # Lv.1
```

#### Lv.1: 세션 격리 (동적 NetworkPolicy)

```python
# defense/network_policy.py
from kubernetes import client

def create_isolation_policy(source_ip: str, namespace: str = "elden-production"):
    """의심 소스 IP에서 오는 트래픽을 차단하는 NetworkPolicy 동적 생성"""
    policy = client.V1NetworkPolicy(
        metadata=client.V1ObjectMeta(
            name=f"isolate-{source_ip.replace('.', '-')}",
            namespace=namespace,
        ),
        spec=client.V1NetworkPolicySpec(
            pod_selector=client.V1LabelSelector(match_labels={"app": "target-app"}),
            policy_types=["Ingress"],
            ingress=[]  # 빈 리스트 = 해당 Pod으로의 모든 Ingress 차단
        ),
    )
    api = client.NetworkingV1Api()
    api.create_namespaced_network_policy(namespace=namespace, body=policy)
```

#### Lv.2: IP 차단 (Istio AuthorizationPolicy)

```python
# defense/rate_limiter.py
from kubernetes import client

def block_ip_via_istio(source_ip: str, namespace: str = "elden-production"):
    """Istio AuthorizationPolicy로 특정 IP 차단"""
    policy = {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"block-{source_ip.replace('.', '-')}",
            "namespace": namespace,
        },
        "spec": {
            "action": "DENY",
            "rules": [{"from": [{"source": {"ipBlocks": [f"{source_ip}/32"]}}]}],
        },
    }
    api = client.CustomObjectsApi()
    api.create_namespaced_custom_object(
        group="security.istio.io", version="v1beta1",
        namespace=namespace, plural="authorizationpolicies", body=policy,
    )
```

#### Lv.3: Degrade Mode

```python
# defense/degrade_mode.py
from kubernetes import client

NON_CRITICAL_DEPLOYMENTS = ["feedback-service", "search-service", "recommendation-service"]

def activate_degrade_mode(namespace: str = "elden-production"):
    """비핵심 서비스를 scale 0으로 축소"""
    api = client.AppsV1Api()
    for deploy_name in NON_CRITICAL_DEPLOYMENTS:
        api.patch_namespaced_deployment_scale(
            name=deploy_name, namespace=namespace,
            body={"spec": {"replicas": 0}},
        )
```

### 4.7 에러 처리

| 상황 | 처리 |
|---|---|
| Falco JSON 파싱 실패 | raw 로그를 인메모리에 저장, 로그 출력. 파이프라인 중단하지 않음 |
| CWE 매핑 실패 (UNKNOWN) | `cwe_id: "UNKNOWN"`으로 컨텍스트 생성. Phase 2에서 판단 |
| 라우트맵에 없는 엔드포인트 | `source_mapping: null`. Phase 2가 풀스캔 |
| Redis 연결 실패 | 백업 큐(`elden:phase2:context:queue`)에 LPUSH. 연결 복구 시 큐에서 재전달 |
| K8s API 호출 실패 (긴급 대응) | 로그 출력 후 계속 진행. 컨텍스트 생성이 더 중요 |

---

## 5. 시연 시나리오 상세

### 시나리오 1: SQL Injection (sqlmap)

```
도구: sqlmap
대상: Juice Shop /api/login
명령: sqlmap -u "http://<target>/api/login" --data="username=admin&password=test" --batch

1. sqlmap이 SQL Injection payload 전송
2. Falco 규칙 "ELDEN SQL Injection Pattern" 탐지 → Sidekick → Phase 1
3. Phase 1 파이프라인:
   - Falco 어댑터: tags=["sqli"] → attack_category="SQL Injection"
   - CWE 매핑: CWE-89
   - 소스코드 매핑: POST /api/login → routes/auth.py:login_handler (L42-58)
   - 컨텍스트 패키지 생성 → Redis PUBLISH
4. 긴급 대응 (병렬): Lv.1 세션 격리 + Lv.2 IP 차단
```

### 시나리오 2: XSS (수동)

```
도구: curl 또는 브라우저
대상: Juice Shop 게시판
명령: curl -X POST http://<target>/api/feedback -d '{"comment":"<script>alert(1)</script>"}'

1. XSS payload가 저장됨
2. 수동 이벤트 주입 (Falco는 XSS를 직접 탐지하지 못하므로):
   POST /api/v1/events/manual
   {"attack_category": "XSS", "target_endpoint": {"method": "POST", "path": "/api/feedback"}, ...}
3. Phase 1 파이프라인:
   - CWE 매핑: CWE-79
   - 소스코드 매핑: POST /api/feedback → routes/feedback.py:submit_feedback (L15-30)
   - Redis PUBLISH
```

### 시나리오 3: Shell Execution (Falco 실시간)

```
도구: kubectl exec
명령: kubectl exec -it target-app-xxx -n elden-production -- /bin/bash

1. Falco 규칙 "ELDEN Shell Spawned in Production" 즉시 탐지 (CRITICAL)
2. Falco Sidekick → Phase 1 webhook
3. Phase 1 파이프라인:
   - Falco 어댑터: tags=["shell"] → attack_category="Shell Execution"
   - CWE 매핑: CWE-78
   - 소스코드 매핑: 해당 없음 (source_mapping=null)
   - Redis PUBLISH
4. 긴급 대응: Lv.1 + Lv.2 (CRITICAL이므로)
```

### 시나리오 4: 권한 상승 (Falco 실시간)

```
도구: 컨테이너 내부에서 sudo/chmod +s 실행
1. Falco 규칙 "ELDEN Privilege Escalation Attempt" 탐지 (CRITICAL)
2. Phase 1 파이프라인:
   - attack_category="Privilege Escalation"
   - CWE 매핑: CWE-269
   - Redis PUBLISH
3. 긴급 대응: Lv.1 + Lv.2 + Lv.3 판단 (반복 시)
```

---

## 6. API 설계

| 엔드포인트 | Method | 설명 |
|---|---|---|
| `/api/v1/falco-events` | POST | Falco Sidekick webhook 수신 (인프라에 하드코딩됨) |
| `/api/v1/events/ingest` | POST | 범용 이벤트 수신 (어댑터 자동 감지) |
| `/api/v1/events/manual` | POST | 시연용 수동 이벤트 주입 |
| `/api/v1/contexts/{context_id}` | GET | 컨텍스트 패키지 조회 |
| `/api/v1/contexts/pending` | GET | 미전달 컨텍스트 목록 |
| `/api/v1/routes/scan` | POST | 라우트맵 갱신 (로컬 실행용) |
| `/api/v1/events/stats` | GET | 이벤트 통계 |
| `/api/v1/defense/actions` | GET | 대응 이력 |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe |
| `/metrics` | GET | Prometheus 메트릭 |

### Phase 2로 전달되는 컨텍스트 패키지 스키마

```json
{
  "context_id": "ctx-20260321-001",
  "event_id": "evt-20260321-001",
  "timestamp": "2026-03-21T14:30:00Z",
  "attack_info": {
    "category": "SQL Injection",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
    "owasp_category": "A03:2021 Injection",
    "payload_sample": "username=admin' OR 1=1--&password=test",
    "source_ip": "192.168.1.100",
    "blocked": true
  },
  "target": {
    "endpoint": { "method": "POST", "path": "/api/login" },
    "source_mapping": {
      "file": "routes/auth.py",
      "function": "login_handler",
      "line_start": 42,
      "line_end": 58
    }
  },
  "metadata": {
    "severity": "HIGH",
    "pipeline_version": "1.0.0",
    "defense_action_taken": "session_isolated",
    "requires_patch": true
  }
}
```

---

## 7. 개발 단계

### Phase A: 로컬 Python 개발 (K8s 불필요)

인프라 이슈 확인과 **병행 가능**. 순수 Python 코드이므로 K8s 환경 없이 개발/테스트.

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| A-1 | FastAPI 서버 뼈대 + Pydantic 모델 정의 | `uvicorn src.main:app --reload` 로컬 실행 |
| A-2 | Falco 어댑터 + 이벤트 정규화 | pytest 단위 테스트 (Falco JSON 샘플) |
| A-3 | CWE Rule Table 매핑 (9개 공격 유형) | pytest 단위 테스트 |
| A-4 | Flask 라우트 파서 (AST 기반) | pytest (샘플 Flask 코드로 파싱 테스트) |
| A-5 | 컨텍스트 패키지 생성 로직 | pytest 통합 테스트 (Step 1~4 연결) |
| A-6 | Redis Pub/Sub 전달 클라이언트 (`elden:phase2:context` 채널) | pytest (fakeredis mock) |
| A-7 | 긴급 대응 로직 (K8s client 호출부) | pytest (K8s client mock) |
| A-8 | Prometheus 메트릭 노출 | `/metrics` 엔드포인트 확인 |

로컬 개발 실행 방법:
```bash
cd services/runtime-defense
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8080

# 테스트
python -m pytest tests/ -v

# 수동 이벤트 테스트
curl -X POST http://localhost:8080/api/v1/falco-events \
  -H "Content-Type: application/json" \
  -d '{ "output": "Shell spawned in production ...", "priority": "Critical", "rule": "ELDEN Shell Spawned in Production", "output_fields": { "k8s.ns.name": "elden-production", "k8s.pod.name": "target-app-xxx", "proc.cmdline": "bash" } }'
```

### Phase B: 컨테이너화 (Docker만, K8s 불필요)

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| B-1 | Dockerfile + requirements.txt 작성 | `docker build` + `docker run -p 8080:8080` |
| B-2 | K8s 매니페스트 작성 (`kubernetes/environments/production/`에 배치) | `kubeval`로 문법 검증 |
| B-3 | 라우트맵 ConfigMap 작성 (`kubernetes/environments/production/`에 배치) | `kubeval`로 검증 |

### Phase C: K8s 통합 테스트 (kind 클러스터 필요)

인프라 이슈 해결 후 진행.

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| C-1 | `./scripts/setup-cluster.sh --dev`로 로컬 클러스터 구축 | `kubectl get ns` |
| C-2 | `kind load docker-image` + `kubectl apply` | Pod Running 확인 |
| C-3 | Falco → webhook 실제 연동 | Falco 이벤트 발생시켜서 컨텍스트 생성 확인 |
| C-4 | 긴급 대응 (동적 NetworkPolicy 생성) | `kubectl get networkpolicy` 확인 |
| C-5 | Redis Pub/Sub 연동 | `elden:phase2:context` 채널 PUBLISH 확인 |

### Phase D: 시연 준비

| 순서 | 작업 |
|---|---|
| D-1 | Juice Shop K8s 배포 + sqlmap 공격 시나리오 |
| D-2 | XSS 공격 시나리오 |
| D-3 | 수동 이벤트 주입 시연 |
| D-4 | Grafana 대시보드 메트릭 확인 |

---

## 8. 기술 스택

| 구성 요소 | 기술 | 이유 |
|---|---|---|
| API 서버 | FastAPI (Python) | 비동기 지원, 빠른 개발, Pydantic 내장 |
| Redis 클라이언트 | redis-py (aioredis) | Phase 2 전달용 Redis Pub/Sub |
| K8s 클라이언트 | kubernetes Python client | 동적 NetworkPolicy, Pod 제어 |
| 메트릭 | prometheus-fastapi-instrumentator | Prometheus 메트릭 자동 수집 |
| 테스트 | pytest + httpx (TestClient) | FastAPI 공식 테스트 방식 |
| 컨테이너 | Docker | 인프라 CI와 호환 |

### requirements.txt (예상)

```
fastapi>=0.100.0
uvicorn>=0.23.0
redis>=5.0.0
pydantic>=2.0.0
kubernetes>=27.0.0
prometheus-fastapi-instrumentator>=6.0.0
pytest>=7.0.0
pytest-asyncio>=0.21.0
fakeredis>=2.20.0
```

---

## 9. Git 워크플로우

```
feature/phase1-xxx  →  PR to dev  →  dev 머지  →  PR to main  →  main 머지
     (개발)              (자동 검증)    (통합)                      (운영)
```

- 브랜치 네이밍: `feature/phase1-<기능명>` (예: `feature/phase1-event-normalizer`)
- PR은 반드시 **dev 브랜치**로만
- main에 직접 PR 금지

### PR 올리면 자동 실행되는 CI

dev 머지 시 Phase 1 코드 변경이 감지되면 자동 실행:

| 단계 | 내용 |
|---|---|
| 변경 감지 | `services/runtime-defense/**` 경로 변경 감지 |
| Docker Build | `services/runtime-defense/` 컨텍스트로 이미지 빌드 |
| Trivy Scan | 빌드된 이미지 보안 취약점 스캔 |
| Deploy | `kubernetes/environments/production/` 매니페스트를 `elden-production`에 적용 |
| 이미지 태그 | `eldenring/runtime-defense:dev-<commit-sha>`, `eldenring/runtime-defense:dev-latest` |

---

## 10. CWE 매핑 테이블

| attack_category | cwe_id | cwe_name | owasp_top10 |
|---|---|---|---|
| SQL Injection | CWE-89 | SQL Command Injection | A03:2021 |
| Cross-Site Scripting (Reflected) | CWE-79 | XSS | A03:2021 |
| Cross-Site Scripting (Stored) | CWE-79 | XSS | A03:2021 |
| Path Traversal | CWE-22 | Path Traversal | A01:2021 |
| SSRF | CWE-918 | Server-Side Request Forgery | A10:2021 |
| OS Command Injection | CWE-78 | OS Command Injection | A03:2021 |
| LDAP Injection | CWE-90 | LDAP Injection | A03:2021 |
| XML External Entity (XXE) | CWE-611 | XXE | A05:2021 |
| Insecure Deserialization | CWE-502 | Deserialization of Untrusted Data | A08:2021 |

---

## 11. 긴급 대응 단계

| Level | 조건 | 대응 조치 | 구현 방식 |
|---|---|---|---|
| Lv.1 | 단일 의심 이벤트 | 비정상 세션 격리 | K8s NetworkPolicy 동적 생성 |
| Lv.2 | 반복 공격 탐지 | 소스 IP 차단 + 엔드포인트 접근 제한 | Istio AuthorizationPolicy 동적 생성 |
| Lv.3 | 대규모/Critical 공격 | Degrade Mode (핵심 기능만 유지) | 비핵심 Deployment scale → 0 |

긴급 대응과 컨텍스트 패키지 생성은 **동시에 병렬 실행**됩니다.

---

## 12. Phase 2 인터페이스 합의 사항

Phase 2 담당자와 협의 필요:

- [ ] 컨텍스트 패키지 JSON 스키마 최종 확정
- [x] 전달 방식: Redis Pub/Sub 확정 (`elden:phase2:context` 채널)
- [ ] 실패 시 재시도 정책 합의 (Redis 연결 실패 시 처리)
- [ ] Phase 2에서 추가로 필요한 컨텍스트 필드 확인
- [ ] Phase 2의 Redis SUBSCRIBE 엔드포인트 확인

