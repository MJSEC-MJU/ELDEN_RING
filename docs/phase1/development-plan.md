# Phase 1: Runtime Defense Plane - 개발 계획서 (v2)

> **최종 수정:** 2026-04-08
>
> **상태:** 인프라 구성 완료, 개발 착수 가능
>
> **주요 변경 (v1 → v2):**
> - ModSecurity WAF + OWASP CRS 도입 (HTTP 레벨 웹 공격 탐지)
> - Falco 역할 재정의 (시스템 레벨 전용)
> - 긴급 대응 체계 재설계 (WAF 1차 차단 + Phase 1 2차 능동 대응)
> - target-app을 직접 제작 (의도적 취약점 포함 Flask 앱)
> - 탐지 대상을 OWASP Top 10 중 3개로 확정: SQL Injection, XSS, Path Traversal

---

## 1. 최종 결과물

`elden-production` 네임스페이스에서 동작하는 **2개 컴포넌트**:

```
[ModSecurity WAF] ─── 1차 차단 ──── HTTP 레벨 공격 즉시 차단 (SQLi, XSS, Path Traversal)
       │
       │ audit log (JSON)
       ▼
[runtime-defense-controller] ─── 2차 능동 대응 + 이벤트 정제 + Phase 2 전달
       │
       ├── 능동 대응: Rate Limit → IP 차단 → 엔드포인트 비활성화
       └── 컨텍스트 패키지 → Redis → Phase 2
```

### 핵심 기능

| 기능 | 설명 |
|---|---|
| **WAF 탐지 (1차)** | ModSecurity + OWASP CRS가 Ingress 레벨에서 SQLi/XSS/Path Traversal 즉시 차단 |
| **이벤트 수신** | ModSecurity audit log 수신 + Falco Sidekick webhook 수신 + 시연용 수동 주입 |
| **이벤트 정규화** | 어댑터 패턴으로 ModSecurity/Falco 로그를 통일 스키마로 변환 |
| **CWE 확정 매핑** | Rule Table 기반 100% 확정 매핑 |
| **소스코드 매핑** | 공격 대상 URL 엔드포인트 → 소스코드 file:function:line 매핑 |
| **컨텍스트 패키지** | 위 결과를 구조화된 JSON으로 조립하여 Phase 2에 Redis 이중 전달 |
| **능동 대응 (2차)** | 반복/고위험 공격에 대한 Lv.1~3 단계적 대응 |

### 탐지 계층 구조 (ModSecurity vs Falco 역할 분리)

| 계층 | 도구 | 탐지 대상 | 동작 방식 |
|---|---|---|---|
| **HTTP 요청 레벨** | ModSecurity + OWASP CRS | SQLi, XSS, Path Traversal | Ingress에서 request body/params/headers 패턴 매칭 → 즉시 차단(403) |
| **시스템 콜 레벨** | Falco | Shell 실행, 파일 변조, 권한 상승, 비정상 네트워크 | 컨테이너 내부 syscall 감시 → webhook 알림 |

> **핵심 원칙**: 웹 공격은 ModSecurity가 잡고, 런타임 이상행위는 Falco가 잡는다. 두 도구의 역할은 겹치지 않는다.

---

## 2. 아키텍처 개요

```
                          ┌─────────────────────────────────┐
                          │         Ingress Gateway          │
                          │   (NGINX Ingress Controller)     │
                          │                                  │
                          │   ┌──────────────────────────┐   │
  HTTP Request ──────────▶│   │  ModSecurity WAF          │   │
  (SQLi/XSS/PathTraversal)│   │  + OWASP CRS              │   │
                          │   │                            │   │
                          │   │  차단 → 403 Forbidden      │   │
                          │   │  audit log → JSON stdout   │   │
                          │   └──────────┬───────────────┘   │
                          │              │                    │
                          │              │ 정상 요청만 통과     │
                          └──────────────┼────────────────────┘
                                         │
                    ┌────────────────────┼────────────────────┐
                    │                    ▼                     │
                    │            ┌──────────────┐             │
                    │            │  target-app   │             │
                    │            │  (Flask 취약앱)│             │
                    │            └──────────────┘             │
                    │                                         │
                    │  elden-production namespace              │
                    │                                         │
                    │  ┌───────────────────────────────────┐  │
                    │  │  runtime-defense-controller        │  │
                    │  │                                    │  │
                    │  │  ┌─ ModSecurity Adapter ◀── audit log│ │
                    │  │  │                                 │  │
                    │  │  ├─ Falco Adapter ◀── Falco Sidekick │ │
                    │  │  │                                 │  │
                    │  │  ├─ Normalizer → CWE Mapper        │  │
                    │  │  │  → Source Mapper                │  │
                    │  │  │  → Context Builder              │  │
                    │  │  │  → Redis Publisher ──▶ Phase 2   │  │
                    │  │  │                                 │  │
                    │  │  └─ Defense Manager                │  │
                    │  │     (Lv1/2/3 능동 대응)             │  │
                    │  └───────────────────────────────────┘  │
                    └─────────────────────────────────────────┘
```

---

## 3. ModSecurity WAF 구성

### 3.1 설치 방식

NGINX Ingress Controller에 내장된 ModSecurity를 활성화한다. 별도 설치 없이 ConfigMap 수정만으로 WAF가 동작한다.

#### Ingress Controller ConfigMap 설정

```yaml
# kubernetes/service-mesh/ingress/configmap.yaml (또는 기존 ingress-nginx ConfigMap)
apiVersion: v1
kind: ConfigMap
metadata:
  name: ingress-nginx-controller
  namespace: ingress-nginx
data:
  # ModSecurity 활성화
  enable-modsecurity: "true"
  # OWASP Core Rule Set 활성화
  enable-owasp-modsecurity-crs: "true"
  # snippet 허용
  allow-snippet-annotations: "true"
  # ModSecurity 상세 설정
  modsecurity-snippet: |
    # 차단 모드 (DetectionOnly가 아닌 On)
    SecRuleEngine On
    # 요청 본문 검사 활성화
    SecRequestBodyAccess On
    # JSON 파싱 활성화
    SecRule REQUEST_HEADERS:Content-Type "application/json" \
      "id:200001,phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=JSON"
    # 감사 로그를 stdout으로 JSON 형식 출력 (Phase 1이 수집)
    SecAuditLog /dev/stdout
    SecAuditLogFormat JSON
    SecAuditEngine RelevantOnly
    # 요청 본문 크기 제한
    SecRequestBodyLimit 13107200
    SecRequestBodyLimitAction Reject
```

#### target-app Ingress에 ModSecurity 적용

```yaml
# kubernetes/environments/production/target-app-ingress.yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: target-app-ingress
  namespace: elden-production
  annotations:
    nginx.ingress.kubernetes.io/enable-modsecurity: "true"
    nginx.ingress.kubernetes.io/enable-owasp-core-rules: "true"
    nginx.ingress.kubernetes.io/modsecurity-transaction-id: "$request_id"
    nginx.ingress.kubernetes.io/modsecurity-snippet: |
      SecRuleEngine On
      SecAuditLog /dev/stdout
      SecAuditLogFormat JSON
      SecAuditEngine RelevantOnly
spec:
  ingressClassName: nginx
  rules:
    - host: target-app.elden.local
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: target-app
                port:
                  number: 5000
```

### 3.2 OWASP CRS가 탐지하는 공격 유형 (우리가 사용할 3개)

| 공격 유형 | CRS Rule ID 범위 | CWE | OWASP Top 10 | 탐지 원리 |
|---|---|---|---|---|
| **SQL Injection** | 942100-942999 | CWE-89 | A03:2021 | SQL 키워드/구문 패턴 매칭 (`UNION SELECT`, `OR 1=1`, `'--` 등) |
| **Cross-Site Scripting (XSS)** | 941100-941999 | CWE-79 | A03:2021 | `<script>`, `onerror=`, `javascript:` 등 HTML/JS 패턴 |
| **Path Traversal (LFI)** | 930100-930999 | CWE-22 | A01:2021 | `../`, `/etc/passwd`, `..%2f` 등 경로 탐색 패턴 |

### 3.3 ModSecurity audit log → Phase 1 이벤트 전달 경로

ModSecurity는 차단된 요청을 JSON 형식으로 stdout에 기록한다. Phase 1이 이 로그를 수집하는 방법:

```
ModSecurity (Ingress Controller Pod)
    │
    │  stdout에 JSON audit log 출력
    ▼
┌───────────────────────────┐
│ 방법: Log Sidecar + Webhook │
│                            │
│ Ingress Controller Pod에    │
│ Fluent Bit sidecar를 붙여   │
│ ModSecurity audit log를     │
│ 필터링하고 Phase 1의         │
│ /api/v1/modsec-events       │
│ 엔드포인트로 HTTP POST 전달  │
└───────────────┬─────────────┘
                │
                ▼
  runtime-defense-controller
  /api/v1/modsec-events (POST)
```

#### Fluent Bit Sidecar 설정 (Ingress Controller Pod에 추가)

```yaml
# Fluent Bit sidecar ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: fluentbit-modsec-config
  namespace: ingress-nginx
data:
  fluent-bit.conf: |
    [SERVICE]
        Flush         1
        Log_Level     info

    [INPUT]
        Name          tail
        Path          /var/log/modsec_audit.log
        Parser        json
        Tag           modsec.*
        Refresh_Interval 5

    [FILTER]
        Name          grep
        Match         modsec.*
        Regex         transaction.messages blocked

    [OUTPUT]
        Name          http
        Match         modsec.*
        Host          runtime-defense-controller.elden-production.svc.cluster.local
        Port          8080
        URI           /api/v1/modsec-events
        Format        json
        Header        Content-Type application/json
```

> **대안 (심플 버전)**: Fluent Bit 없이, Phase 1이 Ingress Controller의 stdout 로그를 Kubernetes API로 직접 tail하는 방식도 가능. MVP에서는 이 방식이 더 간단할 수 있음.
>
> ```python
> # 대안: K8s API로 Ingress Controller 로그 스트리밍
> from kubernetes import client, watch
> 
> v1 = client.CoreV1Api()
> w = watch.Watch()
> for log_line in w.stream(v1.read_namespaced_pod_log,
>     name="ingress-nginx-controller-xxx",
>     namespace="ingress-nginx",
>     follow=True):
>     if "ModSecurity" in log_line:
>         # audit log 파싱 후 처리
>         process_modsec_event(log_line)
> ```

---

## 4. target-app: 의도적 취약 Flask 앱

### 4.1 개요

ModSecurity 탐지와 Phase 1 파이프라인 시연을 위해 **3개의 의도적 취약 엔드포인트**를 가진 Flask 앱을 직접 제작한다.

> **중요**: 이 앱은 교육/시연 목적으로 의도적으로 취약하게 작성된다. 실제 운영 환경에 배포하면 안 됨.

### 4.2 엔드포인트 설계

| 엔드포인트 | Method | 취약점 | CWE | 공격 시나리오 |
|---|---|---|---|---|
| `/api/login` | POST | **SQL Injection** | CWE-89 | `username` 파라미터에 `' OR 1=1--` 주입 |
| `/api/search` | GET | **XSS (Reflected)** | CWE-79 | `q` 파라미터에 `<script>alert(1)</script>` 주입 |
| `/api/file` | GET | **Path Traversal** | CWE-22 | `name` 파라미터에 `../../etc/passwd` 주입 |

### 4.3 target-app 코드 구조

```
services/target-app/
├── app.py                  # Flask 메인 (취약 엔드포인트 3개)
├── requirements.txt        # flask, sqlite3 등
├── Dockerfile
├── init_db.py              # SQLite 초기 데이터 생성
└── templates/
    └── search.html         # XSS 반사를 위한 템플릿
```

### 4.4 취약 코드 예시

```python
# app.py
from flask import Flask, request, render_template_string, send_file
import sqlite3
import os

app = Flask(__name__)
DB_PATH = "/app/data/users.db"

# ────────────────────────────────────────────────────
# 취약점 1: SQL Injection (CWE-89)
# username 파라미터를 문자열 포맷팅으로 직접 SQL에 삽입
# ────────────────────────────────────────────────────
@app.route('/api/login', methods=['POST'])
def login_handler():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    # 취약: 파라미터화된 쿼리를 사용하지 않음
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return {"status": "success", "user": user[1]}, 200
    return {"status": "fail", "message": "Invalid credentials"}, 401

# ────────────────────────────────────────────────────
# 취약점 2: Reflected XSS (CWE-79)
# 사용자 입력을 이스케이프 없이 HTML에 반영
# ────────────────────────────────────────────────────
@app.route('/api/search', methods=['GET'])
def search_handler():
    query = request.args.get('q', '')
    # 취약: 사용자 입력을 직접 HTML에 삽입
    html = f"<html><body><h1>Search Results for: {query}</h1><p>No results found.</p></body></html>"
    return render_template_string(html)

# ────────────────────────────────────────────────────
# 취약점 3: Path Traversal (CWE-22)
# 파일 경로 검증 없이 사용자 입력을 직접 사용
# ────────────────────────────────────────────────────
@app.route('/api/file', methods=['GET'])
def file_handler():
    filename = request.args.get('name', '')
    # 취약: 경로 탐색 필터링 없음
    filepath = os.path.join('/app/uploads', filename)
    if os.path.exists(filepath):
        return send_file(filepath)
    return {"error": "File not found"}, 404

@app.route('/healthz')
def health():
    return {"status": "ok"}, 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### 4.5 라우트맵 ConfigMap (소스코드 매핑용)

target-app이 직접 만든 Flask 앱이므로 라우트맵을 정확하게 작성할 수 있다:

```yaml
# kubernetes/environments/production/route-map-configmap.yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: route-map
  namespace: elden-production
data:
  routes.json: |
    {
      "POST /api/login": {
        "file": "app.py",
        "function": "login_handler",
        "line_start": 14,
        "line_end": 27,
        "vulnerability": "SQL Injection",
        "cwe_id": "CWE-89"
      },
      "GET /api/search": {
        "file": "app.py",
        "function": "search_handler",
        "line_start": 33,
        "line_end": 38,
        "vulnerability": "Reflected XSS",
        "cwe_id": "CWE-79"
      },
      "GET /api/file": {
        "file": "app.py",
        "function": "file_handler",
        "line_start": 44,
        "line_end": 50,
        "vulnerability": "Path Traversal",
        "cwe_id": "CWE-22"
      }
    }
```

### 4.6 target-app K8s 매니페스트

```yaml
# kubernetes/environments/production/deployment.yaml (기존 target-app 교체)
apiVersion: apps/v1
kind: Deployment
metadata:
  name: target-app
  namespace: elden-production
  labels:
    app: target-app
    elden-ring/plane: target
spec:
  replicas: 2
  selector:
    matchLabels:
      app: target-app
  template:
    metadata:
      labels:
        app: target-app
        elden-ring/plane: target
      annotations:
        sidecar.istio.io/inject: "true"
    spec:
      containers:
        - name: target-app
          image: eldenring/target-app:latest
          ports:
            - containerPort: 5000
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 250m
              memory: 256Mi
          readinessProbe:
            httpGet:
              path: /healthz
              port: 5000
            initialDelaySeconds: 5
          livenessProbe:
            httpGet:
              path: /healthz
              port: 5000
            initialDelaySeconds: 10
---
apiVersion: v1
kind: Service
metadata:
  name: target-app
  namespace: elden-production
spec:
  selector:
    app: target-app
  ports:
    - port: 5000
      targetPort: 5000
```

---

## 5. 설계 결정 사항

| 항목 | 결정 | 이유 |
|---|---|---|
| WAF | ModSecurity + OWASP CRS (NGINX Ingress 내장) | 별도 설치 불필요, Ingress ConfigMap만 수정. CRS가 SQLi/XSS/LFI 탐지 룰 제공 |
| 탐지 대상 | SQLi (CWE-89), XSS (CWE-79), Path Traversal (CWE-22) | OWASP Top 10 A03/A01에 해당하는 가장 대표적인 웹 취약점 3개 |
| target-app | 직접 제작 Flask 앱 (의도적 취약점 3개) | 라우트맵 정확도 100%, 시연 시 예측 가능한 동작, 코드가 단순하여 Phase 2 패치 생성에도 적합 |
| WAF 동작 모드 | **On (차단 모드)** | DetectionOnly가 아닌 실제 차단. Phase 1은 차단 로그를 수신하여 추가 대응 |
| ModSecurity → Phase 1 전달 | audit log JSON stdout → Fluent Bit sidecar 또는 K8s log streaming | webhook이 아닌 로그 기반 수집. MVP에서는 K8s API log streaming으로 시작 |
| Falco 역할 | 시스템 레벨 전용 (Shell, 파일변조, 권한상승) | HTTP 레벨 탐지는 ModSecurity가 전담. Falco의 "ELDEN SQL Injection Pattern" 규칙은 보완용으로만 유지 |
| Phase 2 전달 | Redis 이중 전달 (Pub/Sub + List 큐) | Pub/Sub만 쓰면 구독자 부재 시 메시지 유실. 항상 큐에도 저장하여 신뢰성 확보 |
| 소스코드 매핑 | 수동 작성 ConfigMap (MVP) | target-app이 3개 엔드포인트뿐이라 AST 파서 불필요. 확장 시 파서 추가 가능 |
| 저장소 | 인메모리 (MVP) | CWE 3개, 이벤트 이력은 인메모리 리스트로 시연 범위에 충분 |

---

## 6. 인프라 환경 연동

### 인프라에서 이미 제공되는 것

| 항목 | 파일 | 내용 |
|---|---|---|
| 네임스페이스 | `kubernetes/base/namespaces.yaml` | `elden-production` (istio-injection: enabled) |
| RBAC | `kubernetes/base/rbac.yaml` | `runtime-defense-sa` + NetworkPolicy/Istio CRUD 권한 |
| NetworkPolicy | `kubernetes/base/network-policies.yaml` | default-deny + 허용 규칙 |
| ResourceQuota | `kubernetes/base/resource-quotas.yaml` | CPU 8, Memory 16Gi, Pod 30개 |
| LimitRange | `kubernetes/base/resource-quotas.yaml` | 컨테이너당 기본 CPU 500m, Memory 512Mi |
| Falco 규칙 | `kubernetes/security/falco/values.yaml` | Shell, 네트워크, 파일변조, 권한상승 탐지 |
| Falco Sidekick | `kubernetes/security/falco/values.yaml` | → `runtime-defense-controller:8080/api/v1/falco-events` webhook |
| Istio | `kubernetes/service-mesh/istio/` | mTLS STRICT, AuthorizationPolicy |
| Redis | `kubernetes/messaging/redis/values.yaml` | Phase 간 메시지 브로커 (`redis-master.elden-monitoring:6379`) |

### Phase 1이 추가로 만드는 것

| 항목 | 위치 | 설명 |
|---|---|---|
| target-app (취약 Flask 앱) | `services/target-app/` | 의도적 취약점 3개 포함 |
| target-app K8s 매니페스트 | `kubernetes/environments/production/deployment.yaml` | Deployment + Service (기존 것 교체) |
| target-app Ingress | `kubernetes/environments/production/target-app-ingress.yaml` | ModSecurity 적용된 Ingress |
| ModSecurity 설정 | Ingress Controller ConfigMap 수정 | WAF 활성화 + CRS + 차단 모드 |
| runtime-defense-controller | `services/runtime-defense/` | FastAPI 서버 (Python) |
| controller K8s 매니페스트 | `kubernetes/environments/production/runtime-defense.yaml` | Deployment + Service |
| 라우트맵 ConfigMap | `kubernetes/environments/production/route-map-configmap.yaml` | 엔드포인트 → 소스코드 매핑 |

---

## 7. 디렉토리 구조

### target-app (`services/target-app/`)

```
services/target-app/
├── app.py                      # Flask 메인 (취약 엔드포인트 3개)
├── init_db.py                  # SQLite 초기 데이터 생성
├── requirements.txt            # flask
├── Dockerfile
└── templates/
    └── search.html             # XSS 반사용 (선택)
```

### runtime-defense-controller (`services/runtime-defense/`)

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
│   │   ├── falco.py                # Falco 어댑터
│   │   └── modsecurity.py          # ModSecurity 어댑터 (신규)
│   ├── normalizer.py               # 이벤트 정규화 (어댑터 라우팅)
│   ├── cwe_mapping.py              # CWE Rule Table
│   ├── source_mapper.py            # ConfigMap 기반 소스코드 매핑
│   ├── context_builder.py          # 컨텍스트 패키지 생성
│   ├── redis_publisher.py          # Redis 이중 전달 클라이언트
│   └── defense/
│       ├── __init__.py
│       ├── manager.py              # 능동 대응 오케스트레이션
│       ├── rate_limiter.py         # Lv.1 Rate Limit
│       ├── ip_blocker.py           # Lv.2 IP 차단
│       └── endpoint_disabler.py    # Lv.3 엔드포인트 비활성화
├── tests/
│   ├── __init__.py
│   ├── test_adapters.py            # ModSecurity/Falco 어댑터 테스트
│   ├── test_normalizer.py
│   ├── test_cwe_mapping.py
│   ├── test_source_mapper.py
│   ├── test_context_builder.py
│   ├── test_redis_publisher.py
│   └── test_defense.py
├── Dockerfile
├── requirements.txt
└── README.md
```

### K8s 매니페스트 (`kubernetes/environments/production/`)

```
kubernetes/environments/production/
├── deployment.yaml                 # target-app (취약 Flask 앱)
├── target-app-ingress.yaml         # ModSecurity 적용 Ingress (신규)
├── runtime-defense.yaml            # Phase 1 Deployment + Service
├── route-map-configmap.yaml        # 라우트맵 데이터
└── README.md
```

---

## 8. 파이프라인 상세 설계

### 8.1 전체 처리 흐름

```
                        ┌─────────────────────────────────┐
                        │  NGINX Ingress + ModSecurity     │
                        │  (1차 차단: SQLi/XSS/LFI → 403) │
                        └───────────┬─────────────────────┘
                                    │ audit log (차단된 요청)
                                    │
       Falco Sidekick ──────────────┤
       (syscall 이벤트)              │
                                    ▼
                        ┌─────────────────────┐
                        │  Step 1              │
                        │  이벤트 수신 + 정규화  │
                        │  - ModSecurity Adapter│
                        │  - Falco Adapter      │
                        └──────────┬──────────┘
                                   │
                     ┌─────────────┼─────────────┐
                     │             │              │
                     ▼             ▼              ▼
          ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
          │  Step 2       │ │  Step 3       │ │  능동 대응    │
          │  CWE 매핑     │ │  소스코드 매핑 │ │  (병렬 실행)  │
          └──────┬───────┘ └──────┬───────┘ │  Lv1/2/3     │
                 │                │          └──────────────┘
                 ▼                ▼
          ┌─────────────────────────────┐
          │  Step 4                      │
          │  컨텍스트 패키지 생성 & 전달  │
          │  → Redis PUBLISH + LPUSH     │
          │  → elden:phase2:context      │
          └─────────────────────────────┘
```

### 8.2 Step 1: 이벤트 수신 + 정규화

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

#### ModSecurity 어댑터 (신규)

```python
# adapters/modsecurity.py
from adapters.base import SecurityEventAdapter
from models import NormalizedEvent, TargetEndpoint

# CRS Rule ID 범위 → 공격 카테고리 매핑
MODSEC_RULE_CATEGORY_MAP = {
    range(942100, 943000): "SQL Injection",      # SQLi rules
    range(941100, 942000): "Cross-Site Scripting", # XSS rules
    range(930100, 931000): "Path Traversal",       # LFI rules
}

class ModSecurityAdapter(SecurityEventAdapter):
    def can_handle(self, raw_log: dict) -> bool:
        """ModSecurity audit log인지 판별"""
        # ModSecurity JSON audit log는 'transaction' 키를 가짐
        return "transaction" in raw_log and "messages" in raw_log.get("audit_data", {})

    def parse(self, raw_log: dict) -> NormalizedEvent:
        transaction = raw_log.get("transaction", {})
        audit_data = raw_log.get("audit_data", {})
        messages = audit_data.get("messages", [])

        # 가장 높은 severity의 규칙에서 카테고리 추출
        category = self._extract_category(messages)
        
        # 요청 정보 추출
        request_info = transaction.get("request", {})
        method = request_info.get("method", "UNKNOWN")
        uri = request_info.get("uri", "UNKNOWN")
        
        return NormalizedEvent(
            event_id=generate_event_id(),
            timestamp=transaction.get("time", datetime.utcnow().isoformat()),
            source="modsecurity",
            attack_category=category,
            target_endpoint=TargetEndpoint(method=method, path=uri),
            payload_sample=self._extract_payload(request_info),
            source_ip=transaction.get("remote_address", None),
            blocked=True,  # ModSecurity On 모드이므로 항상 차단됨
            severity=self._assess_severity(messages),
            raw_rule_id=self._extract_rule_ids(messages),
        )

    def _extract_category(self, messages: list) -> str:
        for msg in messages:
            rule_id = msg.get("details", {}).get("ruleId", 0)
            if isinstance(rule_id, str):
                rule_id = int(rule_id)
            for id_range, category in MODSEC_RULE_CATEGORY_MAP.items():
                if rule_id in id_range:
                    return category
        return "Unknown Web Attack"

    def _assess_severity(self, messages: list) -> str:
        severities = [msg.get("details", {}).get("severity", "").upper() for msg in messages]
        if "CRITICAL" in severities:
            return "CRITICAL"
        elif "WARNING" in severities or "ERROR" in severities:
            return "HIGH"
        return "MEDIUM"

    def _extract_payload(self, request_info: dict) -> str:
        """요청 본문 또는 쿼리스트링에서 payload 샘플 추출"""
        body = request_info.get("body", "")
        if body:
            return body[:500]  # 최대 500자
        headers = request_info.get("headers", {})
        return headers.get("query_string", "")[:500]

    def _extract_rule_ids(self, messages: list) -> str:
        rule_ids = [str(msg.get("details", {}).get("ruleId", "")) for msg in messages]
        return ",".join(filter(None, rule_ids))
```

#### Falco 어댑터 (기존 유지, 역할 축소)

```python
# adapters/falco.py
# 시스템 레벨 탐지만 담당 (HTTP 공격 탐지는 ModSecurity로 이관)
FALCO_CATEGORY_MAP = {
    "shell": "Shell Execution",
    "network": "Suspicious Network",
    "filesystem": "File Tampering",
    "privilege-escalation": "Privilege Escalation",
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

#### 이벤트 정규화 (어댑터 라우팅)

```python
# normalizer.py
from adapters.modsecurity import ModSecurityAdapter
from adapters.falco import FalcoAdapter

class EventNormalizer:
    def __init__(self):
        self.adapters = [
            ModSecurityAdapter(),
            FalcoAdapter(),
        ]

    def normalize(self, raw_log: dict) -> NormalizedEvent:
        for adapter in self.adapters:
            if adapter.can_handle(raw_log):
                return adapter.parse(raw_log)
        raise ValueError(f"No adapter can handle this log: {list(raw_log.keys())}")
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
    source: str                    # "modsecurity", "falco", "manual"
    attack_category: str           # "SQL Injection", "Cross-Site Scripting", "Path Traversal", "Shell Execution" 등
    target_endpoint: TargetEndpoint
    payload_sample: str
    source_ip: Optional[str] = None
    blocked: bool = False
    severity: str                  # "CRITICAL", "HIGH", "MEDIUM", "LOW"
    raw_rule_id: Optional[str] = None
```

#### 수동 이벤트 주입 (시연용)

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

### 8.3 Step 2: CWE 확정 매핑

Rule Table 기반 100% 확정 매핑. 3개 웹 공격 + 시스템 레벨 공격 포함:

```python
# cwe_mapping.py
CWE_MAP = {
    # 웹 공격 (ModSecurity 탐지)
    "SQL Injection":         {"cwe_id": "CWE-89",  "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command", "owasp": "A03:2021"},
    "Cross-Site Scripting":  {"cwe_id": "CWE-79",  "cwe_name": "Improper Neutralization of Input During Web Page Generation", "owasp": "A03:2021"},
    "Path Traversal":        {"cwe_id": "CWE-22",  "cwe_name": "Improper Limitation of a Pathname to a Restricted Directory", "owasp": "A01:2021"},
    # 시스템 공격 (Falco 탐지)
    "Shell Execution":       {"cwe_id": "CWE-78",  "cwe_name": "Improper Neutralization of Special Elements used in an OS Command", "owasp": "A03:2021"},
    "Privilege Escalation":  {"cwe_id": "CWE-269", "cwe_name": "Improper Privilege Management", "owasp": "A04:2021"},
    "File Tampering":        {"cwe_id": "CWE-284", "cwe_name": "Improper Access Control", "owasp": "A01:2021"},
    "Suspicious Network":    {"cwe_id": "CWE-918", "cwe_name": "Server-Side Request Forgery", "owasp": "A10:2021"},
}

def map_to_cwe(attack_category: str) -> dict:
    """attack_category → CWE 확정 매핑. 매핑 실패 시 UNKNOWN 반환."""
    for key, value in CWE_MAP.items():
        if key.lower() == attack_category.strip().lower():
            return value
    return {"cwe_id": "UNKNOWN", "cwe_name": "Unmapped Attack Type", "owasp": "UNKNOWN"}
```

### 8.4 Step 3: 소스코드 매핑

ConfigMap에 사전 정의된 라우트맵을 조회하여 공격 대상 엔드포인트 → 소스코드 위치를 매핑:

```python
# source_mapper.py
import json
import os

class SourceMapper:
    def __init__(self, route_map_path: str = "/config/routes.json"):
        self.route_map = {}
        if os.path.exists(route_map_path):
            with open(route_map_path, 'r') as f:
                self.route_map = json.load(f)

    def map(self, method: str, path: str) -> dict | None:
        """
        엔드포인트를 소스코드 위치로 매핑.
        매핑 실패 시 None 반환 → Phase 2가 풀스캔.
        """
        key = f"{method.upper()} {path}"
        mapping = self.route_map.get(key)
        if mapping:
            return {
                "file": mapping["file"],
                "function": mapping["function"],
                "line_start": mapping["line_start"],
                "line_end": mapping["line_end"],
            }
        return None
```

### 8.5 Step 4: 컨텍스트 패키지 생성 & Redis 이중 전달

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
            "pipeline_version": "2.0.0",
            "detection_source": event.source,  # "modsecurity" 또는 "falco"
            "defense_action_taken": None,       # 능동 대응 후 업데이트
            "requires_patch": cwe["cwe_id"] != "UNKNOWN",
        },
    }
```

```python
# redis_publisher.py
import redis
import json
import logging

logger = logging.getLogger(__name__)

class RedisPublisher:
    def __init__(self, host="redis-master.elden-monitoring", port=6379):
        self.client = redis.Redis(host=host, port=port, decode_responses=True)
        self.channel = "elden:phase2:context"
        self.queue_key = "elden:phase2:context:queue"

    def publish_context(self, context: dict):
        """
        이중 전달: Pub/Sub으로 실시간 알림 + List 큐에 영속 저장.
        Phase 2가 구독 중이 아니어도 큐에서 나중에 가져갈 수 있음.
        """
        payload = json.dumps(context, ensure_ascii=False)
        try:
            # 1. 큐에 항상 저장 (신뢰성 보장)
            self.client.lpush(self.queue_key, payload)
            # 2. Pub/Sub으로 실시간 알림
            self.client.publish(self.channel, payload)
            logger.info(f"Context {context['context_id']} delivered (queue + pubsub)")
        except redis.ConnectionError as e:
            logger.error(f"Redis connection failed: {e}")
            # Redis 자체가 죽은 경우: 인메모리 백업 (추후 재전달)
            self._backup_to_memory(context)

    def _backup_to_memory(self, context: dict):
        """Redis 연결 실패 시 인메모리 백업"""
        if not hasattr(self, '_memory_backup'):
            self._memory_backup = []
        self._memory_backup.append(context)
        logger.warning(f"Context {context['context_id']} backed up to memory ({len(self._memory_backup)} pending)")

    def retry_memory_backup(self):
        """Redis 복구 후 인메모리 백업 재전달"""
        if hasattr(self, '_memory_backup') and self._memory_backup:
            for ctx in self._memory_backup[:]:
                try:
                    self.publish_context(ctx)
                    self._memory_backup.remove(ctx)
                except redis.ConnectionError:
                    break
```

Redis 전달 규약:

| 채널/키 | 용도 | 방식 | 비고 |
|---|---|---|---|
| `elden:phase2:context` | 실시간 알림 | Pub/Sub (PUBLISH) | Phase 2가 구독 중일 때 즉시 수신 |
| `elden:phase2:context:queue` | 영속 저장 | List (LPUSH) | Phase 2가 BRPOP으로 가져감. 유실 방지 |

> **Phase 2 수신 방식 권장**: Phase 2는 `BRPOP elden:phase2:context:queue`로 큐에서 꺼내는 것을 주 수신 방식으로 사용하고, `SUBSCRIBE elden:phase2:context`는 즉시 알림용 보조 채널로 사용.

---

## 9. 능동 대응 상세 설계

### 9.1 대응 계층 구조

```
┌─────────────────────────────────────────────────────────┐
│  0차 대응: ModSecurity WAF (자동)                        │
│  → 공격 요청 즉시 403 차단                                │
│  → Phase 1 개입 없이 자동 동작                            │
└─────────────────────────────────────────────────────────┘
                         │
                         │ 차단 로그가 Phase 1에 전달됨
                         ▼
┌─────────────────────────────────────────────────────────┐
│  Phase 1 능동 대응 (severity + 반복 횟수 기반)            │
│                                                         │
│  Lv.1: Rate Limit 강화                                   │
│  → 해당 소스 IP에 대해 분당 요청 수 제한                    │
│  → Istio EnvoyFilter로 동적 rate limit 적용               │
│  → 조건: 모든 탐지 이벤트 (1회라도)                        │
│                                                         │
│  Lv.2: IP 완전 차단                                      │
│  → 해당 소스 IP의 모든 요청 차단                           │
│  → Istio AuthorizationPolicy DENY 동적 생성               │
│  → 조건: 동일 IP에서 3회 이상 공격 탐지 또는 severity=HIGH+ │
│                                                         │
│  Lv.3: 취약 엔드포인트 비활성화                            │
│  → 공격 대상 엔드포인트 경로를 일시적으로 차단 (503 반환)     │
│  → Istio VirtualService에 fault injection 적용            │
│  → 조건: 동일 엔드포인트에 5회 이상 공격 또는 severity=CRITICAL │
└─────────────────────────────────────────────────────────┘
```

### 9.2 능동 대응 오케스트레이션

```python
# defense/manager.py
import logging
from collections import defaultdict
from models import NormalizedEvent

logger = logging.getLogger(__name__)

class DefenseManager:
    def __init__(self):
        # 공격 횟수 추적 (인메모리)
        self.ip_attack_count = defaultdict(int)       # IP → 공격 횟수
        self.endpoint_attack_count = defaultdict(int) # 엔드포인트 → 공격 횟수

    async def handle_defense(self, event: NormalizedEvent) -> str:
        """
        이벤트 기반 능동 대응. 반환값은 실행된 대응 레벨.
        WAF가 이미 1차 차단했으므로, 여기서는 반복/고위험 공격에 대한 추가 대응.
        """
        source_ip = event.source_ip
        endpoint_key = f"{event.target_endpoint.method} {event.target_endpoint.path}"
        
        # 공격 횟수 갱신
        if source_ip:
            self.ip_attack_count[source_ip] += 1
        self.endpoint_attack_count[endpoint_key] += 1

        actions_taken = []

        # Lv.1: Rate Limit (모든 탐지 이벤트에 대해)
        if source_ip:
            await self._apply_rate_limit(source_ip)
            actions_taken.append("rate_limit")

        # Lv.2: IP 차단 (3회 이상 반복 또는 HIGH 이상)
        if source_ip and (
            self.ip_attack_count[source_ip] >= 3 or
            event.severity in ("HIGH", "CRITICAL")
        ):
            await self._block_ip(source_ip)
            actions_taken.append("ip_blocked")

        # Lv.3: 엔드포인트 비활성화 (5회 이상 반복 또는 CRITICAL)
        if (
            self.endpoint_attack_count[endpoint_key] >= 5 or
            event.severity == "CRITICAL"
        ):
            await self._disable_endpoint(endpoint_key)
            actions_taken.append("endpoint_disabled")

        result = "+".join(actions_taken) if actions_taken else "none"
        logger.info(f"Defense actions for {event.event_id}: {result}")
        return result
```

### 9.3 Lv.1: Rate Limit

```python
# defense/rate_limiter.py
from kubernetes import client

async def apply_rate_limit(source_ip: str, requests_per_minute: int = 10):
    """
    Istio EnvoyFilter로 특정 IP에 대한 요청 속도 제한.
    """
    envoy_filter = {
        "apiVersion": "networking.istio.io/v1alpha3",
        "kind": "EnvoyFilter",
        "metadata": {
            "name": f"ratelimit-{source_ip.replace('.', '-')}",
            "namespace": "elden-production",
        },
        "spec": {
            "workloadSelector": {
                "labels": {"app": "target-app"}
            },
            "configPatches": [{
                "applyTo": "HTTP_FILTER",
                "match": {
                    "context": "SIDECAR_INBOUND",
                    "listener": {"filterChain": {"filter": {"name": "envoy.filters.network.http_connection_manager"}}}
                },
                "patch": {
                    "operation": "INSERT_BEFORE",
                    "value": {
                        "name": "envoy.filters.http.local_ratelimit",
                        "typed_config": {
                            "@type": "type.googleapis.com/udpa.type.v1.TypedStruct",
                            "type_url": "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
                            "value": {
                                "stat_prefix": f"rate_limit_{source_ip.replace('.', '_')}",
                                "token_bucket": {
                                    "max_tokens": requests_per_minute,
                                    "tokens_per_fill": requests_per_minute,
                                    "fill_interval": "60s"
                                },
                                "filter_enabled": {"runtime_key": "local_rate_limit_enabled", "default_value": {"numerator": 100, "denominator": "HUNDRED"}},
                                "filter_enforced": {"runtime_key": "local_rate_limit_enforced", "default_value": {"numerator": 100, "denominator": "HUNDRED"}},
                            }
                        }
                    }
                }
            }]
        }
    }
    api = client.CustomObjectsApi()
    api.create_namespaced_custom_object(
        group="networking.istio.io", version="v1alpha3",
        namespace="elden-production", plural="envoyfilters", body=envoy_filter,
    )
```

### 9.4 Lv.2: IP 완전 차단

```python
# defense/ip_blocker.py
from kubernetes import client

async def block_ip(source_ip: str, namespace: str = "elden-production"):
    """
    Istio AuthorizationPolicy로 특정 IP 완전 차단.
    """
    policy = {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"block-{source_ip.replace('.', '-')}",
            "namespace": namespace,
            "labels": {
                "elden-ring/defense-level": "lv2",
                "elden-ring/created-by": "runtime-defense",
            },
        },
        "spec": {
            "selector": {"matchLabels": {"app": "target-app"}},
            "action": "DENY",
            "rules": [{
                "from": [{
                    "source": {"ipBlocks": [f"{source_ip}/32"]}
                }]
            }],
        },
    }
    api = client.CustomObjectsApi()
    api.create_namespaced_custom_object(
        group="security.istio.io", version="v1beta1",
        namespace=namespace, plural="authorizationpolicies", body=policy,
    )
```

### 9.5 Lv.3: 취약 엔드포인트 비활성화

```python
# defense/endpoint_disabler.py
from kubernetes import client

async def disable_endpoint(method: str, path: str, namespace: str = "elden-production"):
    """
    Istio VirtualService의 fault injection으로 특정 엔드포인트를 일시 비활성화.
    해당 경로로 들어오는 요청에 503 Service Unavailable을 반환.
    """
    vs = {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "VirtualService",
        "metadata": {
            "name": f"disable-{path.replace('/', '-').strip('-')}",
            "namespace": namespace,
            "labels": {
                "elden-ring/defense-level": "lv3",
                "elden-ring/created-by": "runtime-defense",
            },
        },
        "spec": {
            "hosts": ["target-app"],
            "http": [{
                "match": [{
                    "uri": {"exact": path},
                    "method": {"exact": method},
                }],
                "fault": {
                    "abort": {
                        "httpStatus": 503,
                        "percentage": {"value": 100.0},
                    }
                },
                "route": [{
                    "destination": {
                        "host": "target-app",
                        "port": {"number": 5000},
                    }
                }],
            }],
        },
    }
    api = client.CustomObjectsApi()
    api.create_namespaced_custom_object(
        group="networking.istio.io", version="v1beta1",
        namespace=namespace, plural="virtualservices", body=vs,
    )
```

### 9.6 대응 이력 관리

능동 대응 실행 이력은 인메모리에 저장하고 API로 조회 가능:

```python
# defense/manager.py 내부
class DefenseManager:
    def __init__(self):
        self.ip_attack_count = defaultdict(int)
        self.endpoint_attack_count = defaultdict(int)
        self.action_history = []  # 대응 이력

    def record_action(self, event_id: str, action: str, target: str):
        self.action_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "event_id": event_id,
            "action": action,  # "rate_limit", "ip_blocked", "endpoint_disabled"
            "target": target,  # IP 또는 엔드포인트
        })
```

---

## 10. API 설계

| 엔드포인트 | Method | 설명 |
|---|---|---|
| `/api/v1/modsec-events` | POST | **ModSecurity audit log 수신 (Fluent Bit 또는 log collector)** |
| `/api/v1/falco-events` | POST | Falco Sidekick webhook 수신 (인프라에 하드코딩됨) |
| `/api/v1/events/manual` | POST | 시연용 수동 이벤트 주입 |
| `/api/v1/contexts/{context_id}` | GET | 컨텍스트 패키지 조회 |
| `/api/v1/contexts/latest` | GET | 최근 컨텍스트 목록 |
| `/api/v1/defense/actions` | GET | 능동 대응 이력 |
| `/api/v1/defense/stats` | GET | IP별/엔드포인트별 공격 횟수 |
| `/api/v1/events/stats` | GET | 이벤트 통계 (소스별, 카테고리별) |
| `/healthz` | GET | Liveness probe |
| `/readyz` | GET | Readiness probe |
| `/metrics` | GET | Prometheus 메트릭 |

### Phase 2로 전달되는 컨텍스트 패키지 스키마

```json
{
  "context_id": "ctx-20260408-001",
  "event_id": "evt-20260408-001",
  "timestamp": "2026-04-08T14:30:00Z",
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
    "endpoint": { "method": "POST", "path": "/api/login" },
    "source_mapping": {
      "file": "app.py",
      "function": "login_handler",
      "line_start": 14,
      "line_end": 27
    }
  },
  "metadata": {
    "severity": "CRITICAL",
    "pipeline_version": "2.0.0",
    "detection_source": "modsecurity",
    "defense_action_taken": "rate_limit+ip_blocked",
    "requires_patch": true
  }
}
```

---

## 11. 에러 처리

| 상황 | 처리 |
|---|---|
| ModSecurity audit log 파싱 실패 | raw 로그를 인메모리에 저장, 로그 출력. 파이프라인 중단하지 않음 |
| Falco JSON 파싱 실패 | 위와 동일 |
| CWE 매핑 실패 (UNKNOWN) | `cwe_id: "UNKNOWN"`으로 컨텍스트 생성. Phase 2에서 판단 |
| 라우트맵에 없는 엔드포인트 | `source_mapping: null`. Phase 2가 풀스캔 |
| Redis 연결 실패 | 인메모리 백업에 저장. 연결 복구 시 자동 재전달 |
| K8s API 호출 실패 (능동 대응) | 로그 출력 후 계속 진행. 컨텍스트 생성이 우선 |
| 어댑터 매칭 실패 | ValueError 로그 출력, raw 로그 보관 |

---

## 12. 시연 시나리오 상세

### 시나리오 1: SQL Injection

```
공격 명령:
  curl -X POST http://target-app.elden.local/api/login \
    -d "username=admin' OR 1=1--&password=test"

예상 결과:
  1. ModSecurity CRS Rule 942100 계열이 SQLi 패턴 탐지 → 403 Forbidden 반환
  2. ModSecurity audit log (JSON)이 stdout에 기록됨
  3. Phase 1이 audit log 수신:
     - ModSecurityAdapter: CRS rule ID → attack_category="SQL Injection"
     - CWE 매핑: CWE-89
     - 소스코드 매핑: POST /api/login → app.py:login_handler (L14-27)
     - 컨텍스트 패키지 생성 → Redis 이중 전달
  4. 능동 대응:
     - Lv.1: 소스 IP에 rate limit 적용
     - (CRITICAL이므로) Lv.2: 소스 IP 차단
     - (CRITICAL이므로) Lv.3: /api/login 엔드포인트 비활성화
```

### 시나리오 2: Reflected XSS

```
공격 명령:
  curl "http://target-app.elden.local/api/search?q=<script>alert(1)</script>"

예상 결과:
  1. ModSecurity CRS Rule 941100 계열이 XSS 패턴 탐지 → 403 Forbidden
  2. Phase 1 파이프라인:
     - attack_category="Cross-Site Scripting"
     - CWE 매핑: CWE-79
     - 소스코드 매핑: GET /api/search → app.py:search_handler (L33-38)
     - Redis 전달
  3. 능동 대응: Lv.1 (rate limit)
```

### 시나리오 3: Path Traversal

```
공격 명령:
  curl "http://target-app.elden.local/api/file?name=../../etc/passwd"

예상 결과:
  1. ModSecurity CRS Rule 930100 계열이 Path Traversal 패턴 탐지 → 403 Forbidden
  2. Phase 1 파이프라인:
     - attack_category="Path Traversal"
     - CWE 매핑: CWE-22
     - 소스코드 매핑: GET /api/file → app.py:file_handler (L44-50)
     - Redis 전달
  3. 능동 대응: Lv.1 (rate limit)
```

### 시나리오 4: Shell Execution (Falco 탐지)

```
공격 명령:
  kubectl exec -it target-app-xxx -n elden-production -- /bin/bash

예상 결과:
  1. Falco 규칙 "ELDEN Shell Spawned in Production" 즉시 탐지 (CRITICAL)
  2. Falco Sidekick → Phase 1 /api/v1/falco-events webhook
  3. Phase 1 파이프라인:
     - FalcoAdapter: tags=["shell"] → attack_category="Shell Execution"
     - CWE 매핑: CWE-78
     - 소스코드 매핑: 해당 없음 (source_mapping=null)
     - Redis 전달
  4. 능동 대응: Lv.1 + Lv.2 (CRITICAL이므로)
```

### 시나리오 5: 반복 공격 (능동 대응 에스컬레이션)

```
공격 명령 (5회 반복):
  for i in $(seq 1 5); do
    curl -X POST http://target-app.elden.local/api/login \
      -d "username=admin' OR 1=1--&password=test"
    sleep 1
  done

예상 결과:
  1. 1회차: ModSecurity 차단 → Phase 1 Lv.1 (rate limit) + Lv.2 (CRITICAL이므로 IP 차단)
  2. 2회차~: ModSecurity가 계속 차단 (rate limit과 무관하게 WAF가 먼저 잡음)
  3. 5회차: endpoint_attack_count >= 5 → Lv.3 (엔드포인트 비활성화)
  4. 이후: 해당 IP는 Istio에서 차단, 해당 엔드포인트는 503 반환
```

---

## 13. 개발 단계

### Phase A: target-app 제작 (K8s 불필요)

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| A-1 | Flask 취약 앱 코드 작성 (3개 엔드포인트) | `python app.py` 로컬 실행 후 curl 테스트 |
| A-2 | SQLite 초기 데이터 생성 스크립트 | `python init_db.py` 후 DB 확인 |
| A-3 | Dockerfile 작성 | `docker build -t target-app . && docker run -p 5000:5000 target-app` |
| A-4 | 각 취약점이 실제로 동작하는지 확인 | curl로 SQLi/XSS/Path Traversal 수동 테스트 |

### Phase B: runtime-defense-controller 개발 (K8s 불필요)

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| B-1 | FastAPI 서버 뼈대 + Pydantic 모델 정의 | `uvicorn src.main:app --reload` |
| B-2 | ModSecurity 어댑터 구현 | pytest (ModSecurity audit log JSON 샘플로 테스트) |
| B-3 | Falco 어댑터 구현 | pytest (Falco JSON 샘플로 테스트) |
| B-4 | 이벤트 정규화 (어댑터 라우팅) | pytest |
| B-5 | CWE Rule Table 매핑 | pytest |
| B-6 | 소스코드 매핑 (ConfigMap 기반) | pytest (테스트용 routes.json으로) |
| B-7 | 컨텍스트 패키지 생성 | pytest (Step 1~4 통합 테스트) |
| B-8 | Redis 이중 전달 클라이언트 | pytest (fakeredis mock) |
| B-9 | 능동 대응 로직 (K8s API mock) | pytest (kubernetes client mock) |
| B-10 | Prometheus 메트릭 노출 | `/metrics` 엔드포인트 확인 |

로컬 개발 실행:
```bash
cd services/runtime-defense
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8080

# 테스트
python -m pytest tests/ -v

# 수동 ModSecurity 이벤트 테스트 (audit log 형식)
curl -X POST http://localhost:8080/api/v1/modsec-events \
  -H "Content-Type: application/json" \
  -d '{
    "transaction": {
      "time": "2026-04-08T14:30:00Z",
      "remote_address": "192.168.1.100",
      "request": {
        "method": "POST",
        "uri": "/api/login",
        "body": "username=admin'\'' OR 1=1--"
      }
    },
    "audit_data": {
      "messages": [{
        "details": {
          "ruleId": "942100",
          "severity": "CRITICAL",
          "message": "SQL Injection Attack Detected"
        }
      }]
    }
  }'

# 수동 Falco 이벤트 테스트
curl -X POST http://localhost:8080/api/v1/falco-events \
  -H "Content-Type: application/json" \
  -d '{
    "output": "Shell spawned in production",
    "priority": "Critical",
    "rule": "ELDEN Shell Spawned in Production",
    "time": "2026-04-08T14:30:00.000000000Z",
    "output_fields": {
      "k8s.ns.name": "elden-production",
      "k8s.pod.name": "target-app-xxx",
      "proc.cmdline": "bash"
    },
    "tags": ["shell"]
  }'
```

### Phase C: 컨테이너화 (Docker만)

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| C-1 | target-app Dockerfile + build | `docker run -p 5000:5000 target-app` |
| C-2 | runtime-defense Dockerfile + build | `docker run -p 8080:8080 runtime-defense` |
| C-3 | K8s 매니페스트 작성 | `kubeval`로 문법 검증 |
| C-4 | 라우트맵 ConfigMap 작성 | `kubeval`로 검증 |

### Phase D: K8s 통합 테스트 (kind 클러스터)

| 순서 | 작업 | 테스트 방법 |
|---|---|---|
| D-1 | `./scripts/setup-cluster.sh --dev`로 로컬 클러스터 구축 | `kubectl get ns` |
| D-2 | Ingress Controller에 ModSecurity 활성화 | ConfigMap 적용 후 Ingress Controller 재시작 |
| D-3 | target-app 배포 + Ingress 적용 | curl로 취약점 테스트 → 403 확인 |
| D-4 | runtime-defense-controller 배포 | Pod Running 확인 |
| D-5 | ModSecurity audit log → Phase 1 연동 | 공격 시도 → 컨텍스트 생성 확인 |
| D-6 | Falco → Phase 1 연동 | `kubectl exec` → Falco 이벤트 → 컨텍스트 확인 |
| D-7 | 능동 대응 테스트 | 반복 공격 → rate limit, IP 차단, 엔드포인트 비활성화 확인 |
| D-8 | Redis 전달 확인 | `redis-cli SUBSCRIBE elden:phase2:context` 모니터링 |

### Phase E: 시연 준비

| 순서 | 작업 |
|---|---|
| E-1 | SQLi 공격 → 탐지 → 대응 → Phase 2 전달 풀 시나리오 |
| E-2 | XSS 공격 시나리오 |
| E-3 | Path Traversal 공격 시나리오 |
| E-4 | Shell Execution (Falco) 시나리오 |
| E-5 | 반복 공격 에스컬레이션 시나리오 |
| E-6 | Grafana 대시보드 메트릭 확인 |

---

## 14. 기술 스택

| 구성 요소 | 기술 | 이유 |
|---|---|---|
| WAF | ModSecurity + OWASP CRS | NGINX Ingress 내장, 무료, SQLi/XSS/LFI 탐지 룰 제공 |
| 런타임 탐지 | Falco | 시스템 콜 레벨 이상행위 탐지 (인프라에 이미 구성됨) |
| API 서버 | FastAPI (Python) | 비동기 지원, 빠른 개발, Pydantic 내장 |
| target-app | Flask (Python) | 의도적 취약 앱, 단순한 구조 |
| Redis 클라이언트 | redis-py | Phase 2 전달용 이중 전달 (Pub/Sub + List) |
| K8s 클라이언트 | kubernetes Python client | 동적 Istio 리소스 생성 (능동 대응) |
| 메트릭 | prometheus-fastapi-instrumentator | Prometheus 메트릭 자동 수집 |
| 테스트 | pytest + httpx (TestClient) | FastAPI 공식 테스트 방식 |
| 컨테이너 | Docker | 인프라 CI와 호환 |

### requirements.txt (runtime-defense)

```
fastapi>=0.100.0
uvicorn>=0.23.0
redis>=5.0.0
pydantic>=2.0.0
kubernetes>=27.0.0
prometheus-fastapi-instrumentator>=6.0.0
httpx>=0.24.0
pytest>=7.0.0
pytest-asyncio>=0.21.0
fakeredis>=2.20.0
```

### requirements.txt (target-app)

```
flask>=3.0.0
```

---

## 15. K8s 매니페스트 작성 시 준수사항

```yaml
# 필수 설정
namespace: elden-production
serviceAccountName: runtime-defense-sa
labels:
  elden-ring/plane: runtime-defense

# 리소스
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

## 16. CWE 매핑 테이블

### 웹 공격 (ModSecurity 탐지)

| attack_category | cwe_id | cwe_name | owasp_top10 | CRS Rule 범위 |
|---|---|---|---|---|
| SQL Injection | CWE-89 | SQL Command Injection | A03:2021 | 942100-942999 |
| Cross-Site Scripting | CWE-79 | XSS | A03:2021 | 941100-941999 |
| Path Traversal | CWE-22 | Path Traversal | A01:2021 | 930100-930999 |

### 시스템 공격 (Falco 탐지)

| attack_category | cwe_id | cwe_name | owasp_top10 |
|---|---|---|---|
| Shell Execution | CWE-78 | OS Command Injection | A03:2021 |
| Privilege Escalation | CWE-269 | Improper Privilege Management | A04:2021 |
| File Tampering | CWE-284 | Improper Access Control | A01:2021 |
| Suspicious Network | CWE-918 | Server-Side Request Forgery | A10:2021 |

---

## 17. Git 워크플로우

```
feature/phase1-xxx  →  PR to dev  →  dev 머지  →  PR to main  →  main 머지
     (개발)              (자동 검증)    (통합)                      (운영)
```

- 브랜치 네이밍: `feature/phase1-<기능명>`
- PR은 반드시 **dev 브랜치**로만
- main에 직접 PR 금지

### PR 올리면 자동 실행되는 CI

| 단계 | 내용 |
|---|---|
| 변경 감지 | `services/runtime-defense/**` 또는 `services/target-app/**` 경로 변경 감지 |
| Docker Build | 해당 서비스 컨텍스트로 이미지 빌드 |
| Trivy Scan | 빌드된 이미지 보안 취약점 스캔 |
| Deploy | `kubernetes/environments/production/` 매니페스트를 `elden-production`에 적용 |

---

## 18. Phase 2 인터페이스 합의 사항

| 항목 | 상태 | 내용 |
|---|---|---|
| 컨텍스트 패키지 JSON 스키마 | 확정 | 섹션 10의 스키마 참고 |
| 전달 방식 | 확정 | Redis 이중 전달 (Pub/Sub + List 큐) |
| 수신 채널 | 확정 | `elden:phase2:context` (Pub/Sub), `elden:phase2:context:queue` (List) |
| Phase 2 권장 수신 방식 | 권장 | `BRPOP elden:phase2:context:queue` (주), `SUBSCRIBE` (보조 알림) |
| 실패 시 재시도 | 확정 | Phase 1은 항상 큐에 저장하므로 유실 없음. Phase 2가 `BRPOP`으로 재시도 |
| 추가 필요 필드 | 미확인 | Phase 2 담당자와 확인 필요 |
