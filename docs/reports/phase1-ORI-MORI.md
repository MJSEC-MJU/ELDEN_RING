# Phase 1 작업 정리 — ORI-MORI

> 본 문서는 Phase 1(Runtime Defense Plane) 담당자 본인(`ORI-MORI`,
> `dlwndh0422@naver.com`)이 직접 커밋한 변경사항만 추려 정리한 데이터입니다.
> 보고서 작성 시 자유롭게 발췌/재구성하세요.

## 0. 한눈에 보기

| 항목 | 값 |
|---|---|
| 담당자 | ORI-MORI (`dlwndh0422@naver.com`) |
| 머지된 PR | **#1** phase1-event-pipeline / **#2** phase1-integration-verified / **#7** phase1-extra |
| 본인 커밋 수 | 13 (실질 변경 9 + 머지 4) |
| 기능 영역 | 6개 (인프라 정리 / WAF / 런타임 디펜스 코어 / 인프라 안정화 / 보안 하드닝 / 신뢰성·관측성·문서) |

### 영역별 매핑 요약

| # | 영역 | 대표 커밋 | 결과물 |
|---|---|---|---|
| 1 | 인프라 정리 + Phase 1 계획 수립 | `32f4393` | 레거시 `elden-ring-infra/` 제거, Phase 1 개발 계획서 v1 |
| 2 | ModSecurity WAF 활성화 | `853b54b` | Ingress ConfigMap (OWASP CRS, JSON audit log) |
| 3 | 런타임 디펜스 컨트롤러 + 취약 target-app | `ee02dbe` | FastAPI 파이프라인, 어댑터/CWE/소스맵/방어/Redis, target-app, K8s 매니페스트 |
| 4 | kind 클러스터 배포 안정화 | `6b410c3` | NetworkPolicy/ResourceQuota/Falco values 수정, manual-testing-guide |
| 5 | 보안 하드닝 (Bearer 인증 + 컨테이너 격리) | `a1069c0` | 웹훅 인증, K8s Secret, non-root + readOnlyRoot, WAF 회귀 테스트, cross-team-handoffs |
| 6 | HA + 신뢰성 + 관측성 + E2E + 운영 문서 | `95a54a4`, `d20d293`, `51b2820` | replicas=2 + HPA, Redis 메모리 백업/드레인, JSON 로깅+trace_id, 비즈니스 메트릭, 튜너블 외부화, E2E 테스트, onboarding/troubleshooting |

---

## 1. 커밋 인덱스 (시간 역순)

| Date | SHA | 영역 | 커밋 메시지 |
|---|---|---|---|
| 2026-04-28 | `bd6cd27` | (merge) | Merge PR #7 from `feature/phase1-extra` |
| 2026-04-28 | `8c52891` | (merge) | Merge `origin/dev` into `feature/phase1-extra` |
| 2026-04-28 | `51b2820` | E2E·운영 문서·튜너블 | chore: add E2E tests, dedupe event-id, externalize tunables, write ops docs |
| 2026-04-28 | `d20d293` | 관측성 | feat: add JSON logging with trace_id, business metrics, async Redis, and payload cap |
| 2026-04-28 | `95a54a4` | HA·신뢰성 | feat: add Redis backup drain, /diagnostics, HPA, and HA-friendly rollout |
| 2026-04-28 | `a1069c0` | 보안 하드닝 | feat: add webhook auth, K8s Secret, container hardening, and WAF config tests |
| 2026-04-08 | `a29ca16` | (merge) | Merge PR #2 from `feature/phase1-integration-verified` |
| 2026-04-08 | `6b410c3` | 인프라 안정화 | fix(phase1): resolve kind cluster deployment issues in base infra and Falco config |
| 2026-04-08 | `d05dfde` | (merge) | Merge PR #1 from `feature/phase1-event-pipeline` |
| 2026-04-08 | `853b54b` | WAF | feat(phase1): enable ModSecurity WAF with OWASP CRS on ingress controller |
| 2026-04-08 | `ee02dbe` | 디펜스 코어 | feat(phase1): implement runtime defense controller, target-app, and K8s manifests |
| 2026-04-03 | `32f4393` | 인프라 정리 | refactor: remove legacy elden-ring-infra subdirectory |
| 2026-04-03 | `c73123f` | (merge) | Merge `origin/main` into dev |

전체 변경량(머지 제외): **9 커밋 / 121 파일 / +6 822 / -4 539** (대부분의 삭제는 레거시 디렉토리 정리)

---

## 2. 영역별 상세

### 2-1. 인프라 정리 + Phase 1 계획 수립

#### `32f4393` — refactor: remove legacy elden-ring-infra subdirectory
- 날짜: 2026-04-03
- 변경량: 36 파일, +862 / -3 806

**변경 파일 (요약)**
- 삭제: `elden-ring-infra/**` 전체 (35 파일) — 옛 인프라 모노레포의 잔재
  - `elden-ring-infra/.github/workflows/{dev-ci, main-promote, pr-validation}.yaml`
  - `elden-ring-infra/.harness/{connectors,delegates,environments,pipelines,services}/*.yaml`
  - `elden-ring-infra/kubernetes/{base,environments,monitoring,security,service-mesh}/...`
  - `elden-ring-infra/scripts/{install-harness-delegate,setup-cluster}.sh`
  - `elden-ring-infra/{CONTRIBUTING.md, README.md}`
- 추가: `docs/phase1/development-plan.md` (861줄, Phase 1 개발 계획서 v1)
- 수정: `.gitignore` (`.DS_Store` 추가)

**핵심 변경사항**
- 인프라 코드를 모노레포 최상위 `kubernetes/`로 통합한 뒤 남아 있던 `elden-ring-infra/` 하위 디렉토리를 일괄 제거. CI/Harness/매니페스트가 두 곳에 중복 존재하던 상태를 단일 소스로 정리.
- Phase 1 개발 계획서 v1 작성: 결과물(=runtime-defense-controller), 핵심 기능 6종(이벤트 수신/정규화/CWE/소스맵/컨텍스트/긴급대응), 인프라 연동 표(이미 제공되는 항목 vs Phase 1이 추가할 항목), Falco 우선·인메모리·ConfigMap 라우트맵 등 설계 결정 근거 명시.

#### `c73123f` — Merge `origin/main` into dev
- 날짜: 2026-04-03 (머지 커밋)
- main의 K8s 인프라 초기 구축(`f0d5082`)·CI 워크플로우(`23a3d5e`, `90e01b3`)를 dev로 끌어와 정리 작업의 기준점을 맞춤.

---

### 2-2. ModSecurity WAF 활성화

#### `853b54b` — feat(phase1): enable ModSecurity WAF with OWASP CRS on ingress controller
- 날짜: 2026-04-08
- 변경량: 1 파일, +37

**변경 파일**
- 신규: `kubernetes/service-mesh/ingress/configmap.yaml`

**핵심 변경사항**
- `ingress-nginx` 네임스페이스의 `ingress-nginx-controller` ConfigMap을 새로 작성해 NGINX Ingress Controller에 ModSecurity + OWASP CRS를 활성화.
- 핵심 설정값:
  - `enable-modsecurity: "true"` / `enable-owasp-modsecurity-crs: "true"` / `allow-snippet-annotations: "true"`
  - `SecRuleEngine On` (DetectionOnly가 아닌 차단 모드)
  - `SecRequestBodyAccess On` + JSON Content-Type 파싱(`requestBodyProcessor=JSON`)
  - `SecAuditLog /dev/stdout` + `SecAuditLogFormat JSON` + `SecAuditEngine RelevantOnly` → 감사 로그를 stdout JSON으로 흘려 runtime-defense-controller가 수집 가능하도록 형태 표준화
  - `SecRequestBodyLimit 13 107 200` + `SecRequestBodyLimitAction Reject`
- 적용 절차 주석 포함: `kubectl apply -f` 후 `rollout restart deployment ingress-nginx-controller`.

---

### 2-3. 런타임 디펜스 컨트롤러 + 취약 target-app + K8s 매니페스트

#### `ee02dbe` — feat(phase1): implement runtime defense controller, target-app, and K8s manifests
- 날짜: 2026-04-08
- 변경량: 37 파일, +3 353 / -546 (Phase 1의 가장 큰 단일 PR)

**변경 파일 (분류)**
- **runtime-defense 서비스** (`services/runtime-defense/`)
  - 코어: `src/main.py`, `src/config.py`, `src/models.py`, `src/normalizer.py`, `src/context_builder.py`, `src/cwe_mapping.py`, `src/source_mapper.py`, `src/redis_publisher.py`, `requirements.txt`
  - 어댑터: `src/adapters/{__init__.py, base.py, modsecurity.py, falco.py}`
  - 능동 방어: `src/defense/{__init__.py, manager.py, rate_limiter.py, ip_blocker.py, endpoint_disabler.py}`
  - 테스트: `tests/test_{adapters, context_builder, cwe_mapping, defense, normalizer, redis_publisher, source_mapper}.py`
- **target-app** (`services/target-app/`) — 의도적 취약 Flask 앱
  - `Dockerfile`, `app.py`, `init_db.py`, `requirements.txt`, `templates/search.html`
- **K8s 매니페스트** (`kubernetes/environments/production/`)
  - 신규: `runtime-defense.yaml`, `route-map-configmap.yaml`, `target-app-ingress.yaml`
  - 수정: `deployment.yaml` (target-app 포함)
- **문서**: `docs/phase1/development-plan.md` v1→v2 업데이트, `docs/phase2-integration-guide.md` 신규
- **기타**: `.gitignore`

**핵심 변경사항**

**개발 계획서 v2 재정의** (`docs/phase1/development-plan.md`)
- ModSecurity WAF(HTTP 레벨, 1차 차단)와 Falco(시스템 콜 레벨, 2차 탐지) 역할 분리 명문화. 두 도구의 탐지 영역은 겹치지 않음.
- 탐지 대상을 OWASP Top 10 중 **SQLi/XSS/Path Traversal 3종**으로 확정.
- ModSecurity audit log → Phase 1 전달 경로: Fluent Bit sidecar webhook 또는 K8s API 로그 tail 두 가지 방식 검토.

**파이프라인 오케스트레이션** (`src/main.py`, FastAPI)
- 진입점 3개: `POST /api/v1/modsec-events`, `POST /api/v1/falco-events`, `POST /api/v1/events/manual`
- 조회 5개: `GET /api/v1/contexts/{id}`, `GET /api/v1/contexts/latest?limit=20`, `GET /api/v1/defense/actions?limit=50`, `GET /api/v1/defense/stats`, `GET /api/v1/events/stats` (by_source/by_category/by_severity/failed_parses 집계)
- 헬스 2개: `GET /healthz`, `GET /readyz`(`adapters: 2, routes_loaded: ...`)
- `run_pipeline`: 어댑터 정규화 → CWE 매핑 → 소스맵 조회 → 능동 방어 → 컨텍스트 빌드 → Redis 이중 전달 (단계 5번을 단일 함수에 직선 배치)
- 메모리 저장소 3종 (`events_store`, `contexts_store`, `failed_logs`) 인메모리 보관 → 시연/조회용
- `Instrumentator().instrument(app).expose(app, "/metrics")` — prometheus_fastapi_instrumentator로 HTTP 기본 메트릭 노출 (이 시점엔 비즈니스 메트릭 없음)
- 수동 주입 시 event_id가 `evt-manual-{uuid8}` 형식 (어댑터가 만드는 `evt-{ts}-{uuid8}` 와 다름 → 후속 `51b2820`에서 통합)

**어댑터 패턴** (`src/normalizer.py`, `src/adapters/`)
- `SecurityEventAdapter` ABC: `can_handle(raw_log) -> bool`, `parse(raw_log) -> NormalizedEvent` 두 메서드.
- `EventNormalizer`는 `[ModSecurityAdapter(), FalcoAdapter()]` 순회하며 첫 번째 `can_handle=True` 어댑터로 dispatch. 미스 시 `ValueError("No adapter can handle this log: <keys>")` raise → 200대신 400 응답으로 변환.
- **ModSecurityAdapter**: `transaction` 키 + `audit_data.messages` 존재로 식별. CRS Rule ID 범위 dict (`942000-942999`=SQLi / `941000-941999`=XSS / `930000-930999`=Path Traversal)로 카테고리 결정. 메시지 배열의 severity를 escalate해 최고치(CRITICAL>HIGH>MEDIUM>LOW) 채택. body 또는 query_string을 500자까지 `payload_sample`에 보존. ModSecurity가 On 모드이므로 `blocked=True` 고정.
- **FalcoAdapter**: `rule` + `output_fields` 키 존재로 식별. `FALCO_CATEGORY_MAP` (`shell→Shell Execution`, `network→Suspicious Network`, `file→File Tampering`, `privilege→Privilege Escalation`)을 tags 기반으로 매칭. `FALCO_PRIORITY_MAP` (`EMERGENCY/ALERT/CRITICAL→CRITICAL`, `ERROR/WARNING→HIGH/MEDIUM`, `NOTICE/INFO/DEBUG→LOW`). target_endpoint에 method=`SYSCALL`/path=Pod 이름 채움. `blocked=False` (Falco는 탐지만, 차단 아님).

**데이터 모델** (`src/models.py`, Pydantic v2)
- `TargetEndpoint(method="UNKNOWN", path="UNKNOWN")`
- `NormalizedEvent`: `event_id, timestamp, source('modsecurity'|'falco'|'manual'), attack_category, target_endpoint, payload_sample, source_ip, blocked, severity, raw_rule_id` (10개 필드)
- `ManualEventRequest`: 수동 주입 페이로드 스키마 (severity 기본 MEDIUM)

**CWE 결정 매핑** (`src/cwe_mapping.py`)
- 7개 카테고리 정적 dict (SQL Injection→CWE-89, XSS→CWE-79, Path Traversal→CWE-22, Shell Execution→CWE-78, Privilege Escalation→CWE-269, File Tampering→CWE-284, Suspicious Network→CWE-918) + 각 OWASP Top 10 카테고리 동봉.
- `map_to_cwe`는 case-insensitive + strip 처리. 미스 시 `UNKNOWN_CWE` (이후 `metadata.requires_patch=False`로 흘러감).

**소스맵** (`src/source_mapper.py` + `route-map-configmap.yaml`)
- 생성 시점에 `/config/routes.json` 1회 로드 (없으면 warn 후 빈 dict). 런타임 hot-reload 없음.
- `routes.json`은 3개 엔드포인트 매핑 — `POST /api/login → app.py:login_handler:28-42`, `GET /api/search → search_handler:51-60`, `GET /api/file → file_handler:68-74`. 각 항목에 `vulnerability` + `cwe_id` 동봉(소스맵은 file/function/line만 반환, vulnerability/cwe_id는 운영자 reference용).
- `map(method, path)`는 `"METHOD PATH"` 키로 룩업, hit 시 `{file, function, line_start, line_end}` dict, miss 시 `None`.

**3단계 능동 방어** (`src/defense/`)
- **Lv.1 Rate Limit** (`rate_limiter.apply_rate_limit`): Istio `EnvoyFilter`(`networking.istio.io/v1alpha3`) 생성. SIDECAR_INBOUND HTTP filter로 `envoy.filters.http.local_ratelimit` INSERT_BEFORE. token_bucket(`max_tokens=requests_per_minute`, `fill_interval=60s`), `filter_enabled/enforced` 100% HUNDRED. workloadSelector는 `app=target-app`. 모든 source_ip 보유 이벤트에 적용.
- **Lv.2 IP Block** (`ip_blocker.block_ip`): Istio `AuthorizationPolicy`(`security.istio.io/v1beta1`) 생성, action DENY, source `ipBlocks: [{ip}/32]`. **트리거: 같은 IP 누적 ≥3회 또는 단일 이벤트가 HIGH/CRITICAL** (둘 중 하나).
- **Lv.3 Endpoint Disable** (`endpoint_disabler.disable_endpoint`): Istio `VirtualService`(`networking.istio.io/v1beta1`) 생성, fault.abort.httpStatus=503/percentage=100%. **트리거: 같은 엔드포인트 누적 ≥5회 또는 CRITICAL severity**.
- 세 함수 모두 K8s API 미가용 시 `Exception → logger.warning` 후 graceful skip → 로컬에서도 동작하고 단위 테스트가 mock 없이도 통과.
- `DefenseManager`는 `ip_attack_count` / `endpoint_attack_count` defaultdict + `_blocked_ips` / `_disabled_endpoints` set으로 중복 방지(같은 IP/엔드포인트에 같은 액션 두 번 안 함). `action_history` list로 시연용 추적.

**컨텍스트 패키지** (`src/context_builder.py`, Phase 2 계약)
- 최상위: `context_id, event_id, timestamp, attack_info, target, metadata`
- `attack_info`: category, cwe_id, cwe_name, owasp_category, payload_sample, source_ip, blocked
- `target`: endpoint(method+path) + source_mapping(file/function/line)
- `metadata`: severity, pipeline_version("2.0.0"), detection_source, defense_action_taken, **`requires_patch` = (cwe_id != "UNKNOWN")** ← Phase 2가 패치 생성 여부 판단

**Redis 이중 전달** (`src/redis_publisher.py`, 초기 버전)
- 채널 `elden:phase2:context` PUBLISH(real-time) + 큐 `elden:phase2:context:queue` LPUSH(persistent) 동시 발행 → Phase 2가 둘 중 어느 패턴으로 구독해도 됨.
- 연결 실패 시 `_memory_backup: list[dict]`에 적재(상한 없음, 후속 `95a54a4`에서 deque(1000)로 교체). `retry_memory_backup`은 첫 실패에서 break (FIFO 보장).

**target-app — 의도적 취약 Flask 앱** (`services/target-app/`)
- **`app.py`** (5개 라우트):
  - `POST /api/login` (SQLi): `f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"` — 파라미터 바인딩 없는 문자열 포맷팅. `sqlite3.OperationalError`만 try/except로 감싸 400 반환(에러 메시지 노출), 정상 hit는 200, miss는 401.
  - `GET /api/search` (Reflected XSS): `f"<html><body><h1>Search Results for: {query}</h1>..."` 를 `render_template_string`으로 렌더 → `<script>alert(1)</script>` 그대로 반사. (templates/search.html은 폼 제출용, 반사는 인라인 문자열에서 발생)
  - `GET /api/file` (Path Traversal): `os.path.join('/app/uploads', filename)` 후 `send_file` — `../` 정규화 없음, `name=../../etc/passwd` 허용.
  - `GET /healthz` 단순 200, `GET /readyz` DB 파일 존재 확인(없으면 503 "database not initialized").
  - `GET /` 인덱스: 자기 자신의 취약점 목록을 JSON으로 광고 (시연·교육용).
- **`init_db.py`**: `users` 테이블(id, username UNIQUE, password, role) + 4명(admin/admin1234, user1/password1, user2/password2, demo/demo1234) 초기 적재. INSERT는 파라미터 바인딩(`?, ?, ?`) — DB 시드는 안전, 취약점은 login 쿼리에만 의도적으로 존재.
- **`Dockerfile`**: python:3.11-slim, `/app/data` + `/app/uploads` 생성 후 `echo "This is a sample file." > /app/uploads/sample.txt` (path traversal 시연용 normal 파일), **이미지 빌드 시점에 `python init_db.py` 실행**해 SQLite 파일을 이미지에 baked-in. ENV `DB_PATH=/app/data/users.db`.
- **`requirements.txt`**: `flask>=3.0.0` 한 줄 (sqlite3는 stdlib).
- **`templates/search.html`**: 검색 폼 한 페이지. 코멘트로 XSS 위치 명시.

**K8s 매니페스트** (`kubernetes/environments/production/`)
- **`runtime-defense.yaml`** 신규: Deployment + Service. `replicas: 1`, `runtime-defense-sa` SA, route-map ConfigMap mount(`/config`), `REDIS_HOST=redis-master.elden-monitoring`, `K8S_NAMESPACE=elden-production`, readiness/liveness probe `/readyz`/`/healthz`. (이 시점엔 securityContext / Secret / 백업 emptyDir 없음 — 후속 `a1069c0`/`95a54a4`에서 보강)
- **`route-map-configmap.yaml`** 신규: target-app 3개 엔드포인트 정적 매핑.
- **`target-app-ingress.yaml`** 신규: target-app용 Ingress + ModSecurity annotation 4종 (`enable-modsecurity`, `enable-owasp-core-rules`, `modsecurity-transaction-id=$request_id`, `modsecurity-snippet`로 stdout JSON audit log). host: `target-app.elden.local`.
- **`deployment.yaml`** 수정: target-app Deployment 포함하도록 갱신.

**문서**
- `docs/phase2-integration-guide.md` 신규 — Phase 2가 컨텍스트를 소비할 때 따를 인터페이스 가이드.

**단위 테스트 7개 모듈** (`tests/`)
- `test_adapters.py`: ModSec SQLi(942100)/XSS(941100)/PathTraversal(930100) sample log 3종, Falco shell(Critical)/network(Warning) 2종 → `can_handle` boolean + `parse` field-by-field 단언(source/attack_category/method/path/source_ip/blocked/severity/raw_rule_id).
- `test_context_builder.py`: 정상 컨텍스트 / source_map=None / unknown CWE → `requires_patch=False` 3 케이스.
- `test_cwe_mapping.py`: 5개 카테고리 매핑 + unknown + case-insensitive(`"sql injection"`) + whitespace(`"  SQL Injection  "`) 8 케이스.
- `test_defense.py` (`@pytest.mark.asyncio`): K8s 호출 3개를 `AsyncMock`으로 패치. ① Lv.1은 항상 발동 ② Lv.2는 HIGH severity에서 발동 ③ Lv.3은 CRITICAL에서 발동 ④ MEDIUM 3회 반복 → IP block ⑤ LOW 5회 반복 → endpoint disable ⑥ stats tracking. severity 매핑이 코드와 다른 부분(HIGH severity가 Lv.2 즉발하는 가정)이 보이는데 — 코드는 `("HIGH", "CRITICAL")` tuple 멤버십이므로 일치.
- `test_normalizer.py`: ModSec / Falco 라우팅 + 알 수 없는 포맷 시 `ValueError` 3 케이스.
- `test_redis_publisher.py`: `fakeredis.FakeRedis`로 발행 → queue rpop 검증, 다중 발행 LLEN, `client=None` 강제 후 메모리 백업 카운트 검증.
- `test_source_mapper.py`: 임시 routes.json 작성 → 존재/없음/파일 미존재 graceful 처리.

---

### 2-4. kind 클러스터 배포 안정화

#### `6b410c3` — fix(phase1): resolve kind cluster deployment issues in base infra and Falco config
- 날짜: 2026-04-08
- 변경량: 4 파일, +278 / -8

**변경 파일**
- 신규: `docs/phase1/manual-testing-guide.md` (249줄)
- 수정: `kubernetes/base/network-policies.yaml`, `kubernetes/base/resource-quotas.yaml`, `kubernetes/security/falco/values.yaml`

**핵심 변경사항**
- **NetworkPolicy**: egress 화이트리스트에 Istio control plane(`istio-system` 네임스페이스) 추가 → istiod 통신이 default-deny에 막혀 sidecar injection이 실패하던 이슈 해소.
- **ResourceQuota**:
  - `elden-production`: `jobs.batch` → `count/jobs.batch` (K8s ResourceQuota의 올바른 키 명. 기존 키는 무시됨)
  - `elden-monitoring`: 모니터링 스택(Prometheus/Loki/Grafana/Falco) 실제 사용량에 맞춰 quota 2배 상향(`requests.cpu 4→8`, `requests.memory 8→16Gi`, `limits.cpu 8→16`, `limits.memory 16→32Gi`, `pods 20→40`).
  - `elden-monitoring`에 `LimitRange`(default 500m/512Mi, request 100m/128Mi) 신규 추가 → ResourceQuota 활성화 시 모든 컨테이너에 limit 명시 필수 요구사항 충족.
- **Falco values**: 커스텀 룰을 `falco.rules` 키 아래가 아닌 `customRules.elden-ring-rules.yaml` 키로 이동 → Helm chart가 ConfigMap으로 mount하는 정식 경로로 교정 (이전 위치는 무시되어 룰이 적재되지 않던 상태).
- **manual-testing-guide.md**: kind 부트스트랩 → Pod 상태 확인 → port-forward → 수동 이벤트 주입(SQLi/XSS/Path Traversal curl 예시) → 결과 확인까지의 단계별 검증 절차 문서화.

---

### 2-5. 보안 하드닝 (Bearer 인증 + 컨테이너 격리)

#### `a1069c0` — feat: add webhook auth, K8s Secret, container hardening, and WAF config tests
- 날짜: 2026-04-28
- 변경량: 14 파일, +517 / -4

**변경 파일**
- 신규: `services/runtime-defense/src/auth.py`, `tests/test_auth.py`, `tests/test_waf_config.py`
- 신규: `kubernetes/environments/production/runtime-defense-secret.yaml`
- 신규: `docs/phase1/cross-team-handoffs.md`, `docs/phase1/Phase1_구현완료_보고서.pdf`
- 수정: `services/runtime-defense/{Dockerfile, README.md, requirements.txt, src/config.py, src/main.py, tests/test_adapters.py}`
- 수정: `kubernetes/environments/production/runtime-defense.yaml`, `docs/phase1/manual-testing-guide.md`

**핵심 변경사항**
- **웹훅 Bearer 인증** (`src/auth.py`):
  - FastAPI dependency `verify_webhook_token`을 만들어 `/api/v1/modsec-events`, `/api/v1/falco-events`, `/api/v1/events/manual`에 부착.
  - `secrets.compare_digest`로 timing-safe 비교, 401(Authorization 누락/스킴 불일치) / 403(토큰 불일치) 분리.
  - `WEBHOOK_AUTH_TOKEN`이 비어 있으면 인증 비활성 모드(로컬 개발용 escape hatch) — 시작 시 경고 1회 로그.
- **K8s Secret 분리** (`runtime-defense-secret.yaml`): `runtime-defense-secrets/webhook-auth-token` 키. 커밋된 값은 dev placeholder, 로테이션 절차(`openssl rand -hex 32` → `kubectl create secret … --dry-run=client -o yaml | kubectl apply -f -`)를 주석에 명시. Deployment는 `secretKeyRef`로 환경변수 주입.
- **컨테이너 하드닝**:
  - Dockerfile: `PYTHONDONTWRITEBYTECODE/PYTHONUNBUFFERED` 설정, UID/GID 1000 비특권 user 생성, `/home/app` writable home(K8s readOnly rootfs에서도 kube discovery cache 동작) 후 `USER 1000`.
  - Deployment securityContext: `runAsNonRoot: true / runAsUser: 1000 / fsGroup: 1000 / seccompProfile: RuntimeDefault`. 컨테이너는 `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`.
  - 쓰기 필요한 두 경로만 emptyDir로 노출: `/tmp` (Memory 64Mi) + `/home/app/.kube` (32Mi).
- **WAF 회귀 테스트** (`tests/test_waf_config.py` + `tests/test_adapters.py`의 `TestModSecurityRuleIDBoundaries`): CRS Rule ID 범위 경계값(942099/942100/942999/943000 등) 매개변수 테스트, 문자열 ruleId 강제 int 변환, 혼합 severity escalate, blocked 플래그 항상 true 등 — 어댑터 분류 로직이 오타로 깨지는 회귀를 가드.
- **인증 테스트** (`tests/test_auth.py`): 토큰 누락/스킴 불일치/토큰 불일치 각각 401/403, 정상 토큰 통과, dev 모드(빈 토큰) 비활성 동작 검증.
- **cross-team-handoffs.md (H-001)**: Falco Sidekick(`falcosidekick.config.webhook.customheaders`)에 같은 토큰을 동기화해야 한다는 핸드오프 항목을 시스템 담당자(이종윤)에게 전달. 환경별 우선순위(dev=Low, staging=Medium, production=High)와 회전 절차 4단계 명시.
- **manual-testing-guide.md 갱신**: `Authorization: Bearer $TOKEN` 헤더가 모든 수동 주입 curl 예시에 추가되도록 업데이트.

---

### 2-6. HA + 신뢰성 + 관측성 + E2E + 운영 문서 (PR #7 `feature/phase1-extra`)

PR #7은 세 개의 테마별 커밋으로 분리되어 있음.

#### `95a54a4` — feat: add Redis backup drain, /diagnostics, HPA, and HA-friendly rollout
- 날짜: 2026-04-28
- 변경량: 6 파일, +373 / -52

**변경 파일**
- 신규: `kubernetes/environments/production/runtime-defense-hpa.yaml`
- 수정: `kubernetes/environments/production/runtime-defense.yaml`
- 수정: `services/runtime-defense/{README.md, src/main.py, src/redis_publisher.py, tests/test_redis_publisher.py}`

**핵심 변경사항**
- **HA 롤아웃**: `replicas: 1 → 2`, `strategy.rollingUpdate.maxUnavailable: 0 / maxSurge: 1` → 롤링 업데이트 중에도 항상 최소 1대 가용(웹훅 누락 최소화). 리소스도 상향(`requests cpu 200m→250m, mem 256Mi→512Mi / limits cpu 500m→1, mem 512Mi→1Gi`).
- **HPA**: CPU 70% / Memory 80% 임계, `minReplicas=2 / maxReplicas=5`. behavior:
  - scaleUp: `stabilizationWindowSeconds: 30 + Percent 100 / 30s` (공격 파동 빠른 흡수)
  - scaleDown: `stabilizationWindowSeconds: 300 + Pods 1 / 300s` (메모리 백업 큐 유실 방지)
- **Redis 메모리 백업 → 자동 드레인**:
  - 백업을 `list`에서 `collections.deque(maxlen=MAX_BACKUP_SIZE=1000)`로 교체 → 가득 차면 가장 오래된 항목 FIFO drop, drop 카운터(`_dropped_count`) 노출. 신선한 공격 컨텍스트가 더 가치 있다는 판단 근거.
  - `_try_publish` / `publish_context` / `drain_memory_backup` / `is_connected` 로 분리. socket connect/op timeout 2초로 옥죄어 hang 방지. 첫 실패에서 멈춰 다음 사이클에서 FIFO 순서 유지.
  - `lifespan` 핸들러로 백그라운드 `_drain_loop` (30초 주기) 시작/취소.
- **Probe / 진단 엔드포인트 정책**:
  - `/readyz`는 어댑터·route-map 로드 여부만 확인하고 항상 200 — Redis 다운으로 readiness 실패 시 Pod이 Service에서 빠져 Falco/ModSec 웹훅 자체를 잃기 때문에, 메모리 백업으로 흡수하는 게 더 안전. 이 결정의 근거를 docstring과 README에 명시.
  - `/diagnostics` 신규 — Redis(host/port/connected/backup_pending/dropped_total) + pipeline(adapters/routes/events/contexts/failed) + auth_enforced 한눈에 노출(K8s probe 미사용, 운영자용).
- **README 신뢰성 섹션** 신설 — 백업·드레인·readiness 정책·HA 구성을 문서화.

#### `d20d293` — feat: add JSON logging with trace_id, business metrics, async Redis, and payload cap
- 날짜: 2026-04-28
- 변경량: 13 파일, +347 / -40

**변경 파일**
- 신규: `services/runtime-defense/src/{logging_config.py, metrics.py, payload_utils.py}`, `tests/test_payload_utils.py`
- 수정: `src/main.py`, `src/redis_publisher.py`, `src/context_builder.py`, `src/defense/manager.py`, `src/adapters/{modsecurity, falco}.py`, `services/runtime-defense/{README.md, requirements.txt}`, `docs/phase1/cross-team-handoffs.md`

**핵심 변경사항**
- **구조화된 JSON 로깅** (`src/logging_config.py`):
  - `python-json-logger` 사용, root logger를 idempotent하게 재설정. handler 중복 방지.
  - `ContextVar`(`trace_id_var`) + `_TraceIdFilter`로 코루틴 간 trace_id 자동 전파.
  - 필드: `timestamp`, `level`, `name`, `message`, `trace_id`. `extra={...}`로 임의 필드 첨부.
  - `set_trace_id` / `reset_trace_id` / `get_trace_id` API.
- **trace_id 파이프라인 통합** (`src/main.py`): `run_pipeline` 진입 시 12자리 hex trace_id 발급 → `set_trace_id` → 모든 로그가 동일 trace_id, `try/finally`로 정리. `context_builder`가 `metadata.trace_id`에 포함시켜 Phase 2 측 전파 발판 마련.
- **비즈니스 메트릭** (`src/metrics.py`, prometheus_client):
  - `runtime_defense_events_total` Counter [source, attack_category, severity]
  - `runtime_defense_actions_total` Counter [action]
  - `runtime_defense_pipeline_duration_seconds` Histogram [source]
  - `runtime_defense_redis_publish_seconds` Histogram
  - `runtime_defense_redis_backup_pending` Gauge
  - `runtime_defense_redis_backup_dropped_total` Counter
  - 호출처: `run_pipeline`(events_total/pipeline_duration/publish_duration/backup_pending), `defense.manager`(actions_total), `redis_publisher`(backup_pending/dropped).
- **비차단 Redis 발행**: `await asyncio.to_thread(redis_pub.publish_context, context)` — 동기 redis-py LPUSH+PUBLISH(+재연결 retry)가 이벤트 루프를 블록하지 않도록 워커 스레드 오프로드. `pipeline_complete` 로그를 `extra=` 구조화 형태로 변경.
- **Payload 크기 캡** (`src/payload_utils.py`):
  - `truncate_payload(value, max_bytes=1024)` — bytes/None/임의 객체 모두 안전하게 문자열화. UTF-8 바이트 기준 1 KiB로 자르고 멀티바이트 경계는 `errors='ignore'`로 안전 처리, `...[truncated]` 마커 부착.
  - 어댑터(`modsecurity.py`, `falco.py`)의 `payload_sample`, `body`/`query_string`/`output` 필드에 일괄 적용 → 대용량 업로드/base64 페이로드가 Redis·Phase 2를 폭주시키는 것을 방지.
- **README 관측성 섹션 신설**: 메트릭 표, 로깅 스키마, async Redis 설명.
- **cross-team-handoffs.md (H-002)**: Phase 2/3/4(이윤태/이종윤)에 trace_id 전파 합의 요청 — 각 Phase가 수신 컨텍스트의 `metadata.trace_id`를 자기 로그/하류 메시지에 그대로 propagate. additive 변경이라 미적용 시에도 동작 영향 없음.

#### `51b2820` — chore: add E2E tests, dedupe event-id, externalize tunables, write ops docs
- 날짜: 2026-04-28
- 변경량: 10 파일, +515 / -33

**변경 파일**
- 신규: `services/runtime-defense/tests/test_e2e_pipeline.py`
- 신규: `docs/phase1/{onboarding.md, troubleshooting.md}`
- 수정: `services/runtime-defense/src/{config.py, main.py, payload_utils.py, redis_publisher.py, adapters/base.py, adapters/falco.py, adapters/modsecurity.py}`

**핵심 변경사항**
- **event_id 생성기 단일화** (`adapters/base.py`): ModSecurity·Falco 양쪽에 사적으로 정의돼 있던 `_generate_event_id`(완전 동일 구현)를 `adapters.base.generate_event_id`로 끌어올려 import. drift/오타로 어댑터별 ID 포맷이 갈라지는 회귀 차단.
- **튜너블 외부화** (`src/config.py`): hard-coded 상수를 환경변수로 노출.
  - `REDIS_PUBSUB_CHANNEL`, `REDIS_QUEUE_KEY`, `REDIS_CONNECT_TIMEOUT`, `REDIS_OP_TIMEOUT`
  - `MEMORY_BACKUP_MAX_SIZE`, `DRAIN_INTERVAL_SECONDS`
  - `MAX_PAYLOAD_BYTES`
  - `_int_env` 헬퍼 도입으로 boilerplate 정리.
- 호출처(`main.py`/`payload_utils.py`/`redis_publisher.py`)가 `settings.*`를 참조하도록 수정 → 매니페스트에서 환경별 튜닝 가능 (kind 클러스터에서는 짧은 timeout, 프로덕션에서는 더 큰 백업 큐 등).
- **End-to-End 테스트** (`tests/test_e2e_pipeline.py`, 196줄): FastAPI `TestClient` + `fakeredis` 백엔드로 인입 엔드포인트→인증→정규화→CWE→소스맵→방어→컨텍스트 빌드→Redis 발행 전체 경로 구동. 검증 포인트:
  - Redis queue/pubsub에 컨텍스트가 실제로 도달하는지 (LPUSH 결과 + 채널 PUBSUB 카운트)
  - 반복 공격 시 IP 카운트 누적 → Lv.2 차단 진입(`/api/v1/defense/stats`로 확인)
  - CRITICAL 단발 이벤트는 첫 요청에 IP 즉시 차단
  - 토큰 누락 시 401 + Redis 큐에 부작용 없음
  - `/diagnostics`가 `auth_enforced: true` / `redis.connected: true` 노출
- **운영 문서 2종 신설**:
  - `docs/phase1/onboarding.md` (131줄) — 신규 합류자용 4주 가이드. 1주차(읽을 문서/개념), 2주차(로컬 환경/테스트), 3주차(코드 17개 파일 읽기 순서), 4주차(첫 PR 체크리스트), FAQ(WEBHOOK_AUTH_TOKEN 비어있을 때 위험성, Redis 다운 시 동작, Phase 2 인터페이스 변경 절차, 담당자 매트릭스).
  - `docs/phase1/troubleshooting.md` (138줄) — 운영 중 자주 만나는 5개 시나리오: ① Pod CrashLoopBackOff(OOMKilled/route_map 손상/ImportError/RBAC), ② 이벤트 미수신(auth_enforced/readyz/Falco webhook 로그), ③ Phase 2 컨텍스트 미수신(diagnostics.redis/LLEN/PUBSUB CHANNELS), ④ WAF 정상 트래픽 차단(rule id 확인 + paranoia level 조정), ⑤ 메트릭/로그 미수집(scrape annotation/Promtail label).

---

## 3. 머지 커밋 부록

| SHA | 날짜 | 의미 |
|---|---|---|
| `c73123f` | 2026-04-03 | `origin/main` → dev 머지. main의 K8s 인프라 초기 구축(`f0d5082`)·CI 워크플로우(`23a3d5e`, `90e01b3`)를 끌어와 Phase 1 작업의 출발선 정렬 |
| `d05dfde` | 2026-04-08 | PR #1 `feature/phase1-event-pipeline` 머지 — 디펜스 코어 + WAF 활성화 |
| `a29ca16` | 2026-04-08 | PR #2 `feature/phase1-integration-verified` 머지 — kind 클러스터 통합 검증 후 안정화 픽스 |
| `8c52891` | 2026-04-28 | `origin/dev` → `feature/phase1-extra` 동기화 머지 (다른 팀원의 phase4 governance/E2E demo 등을 끌어옴) |
| `bd6cd27` | 2026-04-28 | PR #7 `feature/phase1-extra` 머지 — 보안 하드닝 + HA + 관측성 + E2E + 운영 문서 일괄 |

---

## 4. 산출 문서·매니페스트 인덱스

본인이 신규 작성한 산출물(보고서 보충용):

**문서**
- `docs/phase1/development-plan.md` (`32f4393` v1 → `ee02dbe` v2)
- `docs/phase1/manual-testing-guide.md` (`6b410c3` 신규, `a1069c0`에서 인증 헤더 보강)
- `docs/phase1/cross-team-handoffs.md` (`a1069c0` H-001 / `d20d293` H-002)
- `docs/phase1/onboarding.md` (`51b2820`)
- `docs/phase1/troubleshooting.md` (`51b2820`)
- `docs/phase1/Phase1_구현완료_보고서.pdf` (`a1069c0`)
- `docs/phase2-integration-guide.md` (`ee02dbe`)
- `services/runtime-defense/README.md` (보안/신뢰성/관측성 섹션 — `a1069c0`/`95a54a4`/`d20d293`)

**K8s 매니페스트**
- `kubernetes/service-mesh/ingress/configmap.yaml` (`853b54b`)
- `kubernetes/environments/production/runtime-defense.yaml` (`ee02dbe` 신규, `a1069c0`/`95a54a4` 보강)
- `kubernetes/environments/production/runtime-defense-secret.yaml` (`a1069c0`)
- `kubernetes/environments/production/runtime-defense-hpa.yaml` (`95a54a4`)
- `kubernetes/environments/production/route-map-configmap.yaml` (`ee02dbe`)
- `kubernetes/environments/production/target-app-ingress.yaml` (`ee02dbe`)
- `kubernetes/base/network-policies.yaml` 일부 수정 (`6b410c3`)
- `kubernetes/base/resource-quotas.yaml` 일부 수정 (`6b410c3`)
- `kubernetes/security/falco/values.yaml` 일부 수정 (`6b410c3`)

**소스 (services/runtime-defense/)**
- 코어: `src/main.py`, `src/config.py`, `src/models.py`, `src/normalizer.py`, `src/context_builder.py`, `src/cwe_mapping.py`, `src/source_mapper.py`, `src/redis_publisher.py`
- 어댑터: `src/adapters/{base, modsecurity, falco}.py`
- 능동 방어: `src/defense/{manager, rate_limiter, ip_blocker, endpoint_disabler}.py`
- 보안: `src/auth.py`
- 신뢰성/관측성: `src/logging_config.py`, `src/metrics.py`, `src/payload_utils.py`
- 컨테이너: `Dockerfile`
- 테스트: `tests/test_{adapters, context_builder, cwe_mapping, defense, normalizer, redis_publisher, source_mapper, auth, waf_config, payload_utils, e2e_pipeline}.py` (총 11개 모듈)

**target-app (services/target-app/)**
- `app.py`, `init_db.py`, `Dockerfile`, `requirements.txt`, `templates/search.html`

---

## 5. 현재 Phase 1 최신 상태 (스냅샷)

> 기준: `dev` 브랜치 HEAD (`f1e257b`), 본인 마지막 커밋 머지 후 다른 팀원이 Phase 1 파일을 수정한 사례 **없음**(검증 완료). Phase 1 디렉토리/파일/매니페스트는 본인 작업의 그대로의 결과물.
>
> 단 한 가지 예외: Deployment image가 `eldenring/runtime-defense:latest` → `ghcr.io/mjsec-mju/elden-runtime-defense:dev-latest`로 변경됨 (시스템 담당 `a41f1e7` GHCR 마이그레이션).

### 5-1. 디렉토리 트리

```
services/runtime-defense/        총 22 .py / 1 327 LOC (소스) + 11 테스트 / 1 105 LOC
├── Dockerfile
├── README.md
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── main.py              283 LOC  FastAPI 앱, run_pipeline, 11개 엔드포인트
│   ├── config.py             47      Settings (16개 환경변수 외부화)
│   ├── auth.py               59      Bearer 토큰 dependency
│   ├── models.py             33      Pydantic 3종
│   ├── normalizer.py         21      어댑터 라우팅
│   ├── adapters/
│   │   ├── __init__.py        5
│   │   ├── base.py           24      ABC + generate_event_id
│   │   ├── modsecurity.py    77      CRS Rule ID 매핑
│   │   └── falco.py          58      Falco webhook 매핑
│   ├── cwe_mapping.py        51      7개 카테고리 → CWE
│   ├── source_mapper.py      38      routes.json 룩업
│   ├── context_builder.py    42      Phase 2 컨텍스트 패키지
│   ├── defense/
│   │   ├── __init__.py        3
│   │   ├── manager.py        90      Lv1→Lv2→Lv3 에스컬레이션 + 메트릭
│   │   ├── rate_limiter.py   85      Istio EnvoyFilter
│   │   ├── ip_blocker.py     45      Istio AuthorizationPolicy
│   │   └── endpoint_disabler.py 67   Istio VirtualService
│   ├── redis_publisher.py   148      이중 발행 + deque 백업 + 드레인
│   ├── logging_config.py     68      JSON 로깅 + ContextVar trace_id
│   ├── metrics.py            48      6개 비즈니스 메트릭
│   └── payload_utils.py      35      1 KiB UTF-8 truncate
└── tests/
    ├── test_adapters.py        250  ModSec 3종 + Falco 2종 + CRS Rule 경계 매개변수
    ├── test_auth.py            103  Bearer 인증 401/403/dev-mode
    ├── test_context_builder.py  61
    ├── test_cwe_mapping.py      39
    ├── test_defense.py          95  Lv1/2/3 + 반복 IP/엔드포인트 + 통계
    ├── test_e2e_pipeline.py    196  fakeredis로 인입→발행 전체 경로
    ├── test_normalizer.py       39
    ├── test_payload_utils.py    49
    ├── test_redis_publisher.py 124
    ├── test_source_mapper.py    68
    └── test_waf_config.py       81  WAF ConfigMap 정합성

services/target-app/             5 파일
├── Dockerfile                       빌드 시 init_db 실행 → SQLite baked-in
├── app.py                           SQLi/XSS/PathTraversal 의도적 취약 + healthz/readyz/index
├── init_db.py                       4명 시드 (admin/user1/user2/demo)
├── requirements.txt                 flask>=3.0.0
└── templates/search.html            검색 폼

kubernetes/environments/production/   Phase 1 매니페스트 5종
├── runtime-defense.yaml             Deployment + Service (replicas=2, 하드닝 적용)
├── runtime-defense-secret.yaml      runtime-defense-secrets/webhook-auth-token
├── runtime-defense-hpa.yaml         CPU 70% / Mem 80%, 2~5 replicas
├── route-map-configmap.yaml         3개 엔드포인트 정적 매핑
└── target-app-ingress.yaml          ModSecurity annotation 적용 Ingress

kubernetes/service-mesh/ingress/configmap.yaml   ingress-nginx ConfigMap (WAF 활성화)

docs/phase1/                          본인이 작성한 Phase 1 문서 6종
├── development-plan.md              개발 계획서 v2
├── manual-testing-guide.md          kind 클러스터 수동 검증
├── cross-team-handoffs.md           H-001(Falco 토큰) / H-002(trace_id)
├── onboarding.md                    신규 합류자 4주 가이드
├── troubleshooting.md               운영 5개 시나리오
└── Phase1_구현완료_보고서.pdf
```

### 5-2. 외부에 노출된 11개 엔드포인트 (현재)

| Method | Path | 인증 | 용도 |
|---|---|:---:|---|
| POST | `/api/v1/modsec-events` | Bearer | ModSecurity audit log 인입 |
| POST | `/api/v1/falco-events` | Bearer | Falco Sidekick webhook 인입 |
| POST | `/api/v1/events/manual` | Bearer | 시연/수동 이벤트 주입 |
| GET | `/api/v1/contexts/{context_id}` | - | 컨텍스트 단건 조회 |
| GET | `/api/v1/contexts/latest?limit=20` | - | 최근 컨텍스트 |
| GET | `/api/v1/defense/actions?limit=50` | - | 능동 방어 액션 이력 |
| GET | `/api/v1/defense/stats` | - | 차단된 IP / 비활성 엔드포인트 / 카운트 |
| GET | `/api/v1/events/stats` | - | source/category/severity 집계 |
| GET | `/healthz` | - | liveness probe |
| GET | `/readyz` | - | readiness probe (Redis 다운 시에도 200) |
| GET | `/diagnostics` | - | Redis/pipeline/auth 상세 진단 |
| GET | `/metrics` | - | Prometheus scrape (HTTP 기본 + 6개 비즈니스 메트릭) |

### 5-3. 배포·운영 파라미터 현황

**Deployment (`runtime-defense.yaml`)**
- 이미지: `ghcr.io/mjsec-mju/elden-runtime-defense:dev-latest`
- replicas: **2** (HPA min과 정합)
- strategy: RollingUpdate, `maxUnavailable: 0` / `maxSurge: 1`
- resources: requests `cpu 250m / mem 512Mi`, limits `cpu 1 / mem 1Gi`
- securityContext (Pod): `runAsNonRoot=true`, `runAsUser/Group=1000`, `fsGroup=1000`, `seccompProfile=RuntimeDefault`
- securityContext (Container): `allowPrivilegeEscalation=false`, `readOnlyRootFilesystem=true`, `capabilities.drop=[ALL]`
- volumes: `route-map`(ConfigMap, RO) + `tmp`(emptyDir Memory 64Mi) + `kube-cache`(emptyDir 32Mi at `/home/app/.kube`)
- env 6종: `REDIS_HOST`, `REDIS_PORT`, `ROUTE_MAP_PATH`, `K8S_NAMESPACE`, `LOG_LEVEL`, `WEBHOOK_AUTH_TOKEN`(secretKeyRef)
- annotations: `sidecar.istio.io/inject=true`, prometheus scrape on port 8080 path `/metrics`

**HPA (`runtime-defense-hpa.yaml`)**
- target: CPU 평균 70% / Memory 평균 80%
- 범위: minReplicas **2** ↔ maxReplicas **5**
- scaleUp behavior: stabilization 30 s + Percent 100 / 30 s (공격 파동 빠른 흡수)
- scaleDown behavior: stabilization 300 s + Pods 1 / 300 s (메모리 백업 큐 유실 방지)
- 의존: kube-system metrics-server

**Secret (`runtime-defense-secret.yaml`)**
- `runtime-defense-secrets/webhook-auth-token` — 현재 dev placeholder(`elden-ring-dev-CHANGE_ME_IN_PROD`). 프로덕션 회전 절차는 매니페스트 주석 + `services/runtime-defense/README.md` 보안 섹션에 명시.

**Ingress / WAF**
- `kubernetes/service-mesh/ingress/configmap.yaml` → ingress-nginx에 ModSecurity + OWASP CRS 활성화 (`SecRuleEngine On`, JSON audit log)
- `kubernetes/environments/production/target-app-ingress.yaml` → target-app용 Ingress에 ModSecurity annotation 4종 적용. host `target-app.elden.local`.

### 5-4. 환경변수로 노출된 튜너블 (`src/config.py` 16종)

| 변수 | 기본값 | 역할 |
|---|---|---|
| `HOST` / `PORT` | 0.0.0.0 / 8080 | FastAPI 바인딩 |
| `REDIS_HOST` / `REDIS_PORT` | redis-master.elden-monitoring / 6379 | Phase 2 발행 대상 |
| `REDIS_PUBSUB_CHANNEL` / `REDIS_QUEUE_KEY` | `elden:phase2:context` / `…:queue` | 채널/큐 키 |
| `REDIS_CONNECT_TIMEOUT` / `REDIS_OP_TIMEOUT` | 2.0s / 2.0s | hang 방지 |
| `ROUTE_MAP_PATH` | `/config/routes.json` | 소스맵 |
| `K8S_NAMESPACE` | `elden-production` | Defense CR 생성 대상 |
| `LOG_LEVEL` | `INFO` | 로깅 |
| `WEBHOOK_AUTH_TOKEN` | (빈 값 = 인증 비활성) | Bearer 토큰 |
| `IP_BLOCK_THRESHOLD` | 3 | Lv.2 누적 임계 |
| `ENDPOINT_DISABLE_THRESHOLD` | 5 | Lv.3 누적 임계 |
| `RATE_LIMIT_RPM` | 10 | Lv.1 token bucket |
| `MEMORY_BACKUP_MAX_SIZE` | 1000 | Redis 백업 deque 상한 |
| `DRAIN_INTERVAL_SECONDS` | 30 | 백그라운드 드레인 주기 |
| `MAX_PAYLOAD_BYTES` | 1024 | payload truncate 한계 |

### 5-5. 운영자 진단 명령 (현재)

```bash
# 컨트롤러 로그 (JSON 한 줄씩)
kubectl logs -n elden-production deployment/runtime-defense-controller --tail=50

# port-forward 후 진단
kubectl port-forward -n elden-production svc/runtime-defense-controller 8080:8080
curl -s localhost:8080/diagnostics | jq      # Redis/pipeline/auth 한눈
curl -s localhost:8080/readyz | jq           # adapters/routes/redis_connected/backup_pending
curl -s localhost:8080/metrics | head -40    # Prometheus 메트릭

# Phase 2 큐 길이
kubectl exec -n elden-monitoring redis-master-0 -c redis -- redis-cli LLEN elden:phase2:context:queue

# 토큰 조회 (수동 주입 시 필요)
kubectl get secret runtime-defense-secrets -n elden-production -o jsonpath='{.data.webhook-auth-token}' | base64 -d
```

### 5-6. 합의/미해결 핸드오프 항목

| ID | 대상자 | 항목 | 상태 |
|---|---|---|---|
| H-001 | 시스템(이종윤) | Falco Sidekick `customheaders`에 webhook-auth-token 동기화 | **미적용**(dev에선 토큰 비활성이라 무영향, 프로덕션 회전 시점에 필수) |
| H-002 | Phase 2(이윤태) / Phase 4(이종윤) | 컨텍스트의 `metadata.trace_id` 자기 로그·하류 메시지에 propagate | **미적용**(현재 Phase 1 단독 추적만 가능, additive 변경) |

### 5-7. Phase 1 종합 메트릭

| 항목 | 값 |
|---|---|
| 운영 컴포넌트 | runtime-defense-controller (FastAPI, K8s Deployment) + target-app (Flask, K8s Deployment) |
| 코드 베이스 | 22 .py, 1 327 LOC (소스) / 11 test, 1 105 LOC (테스트) |
| 외부 매니페스트 | 6 yaml (Deployment/Service/Secret/HPA/ConfigMap×2/Ingress) |
| 노출 엔드포인트 | 12개 (인입 3 / 조회 5 / 헬스 2 / 진단 1 / 메트릭 1) |
| 비즈니스 메트릭 | 6개 (events_total, actions_total, pipeline_duration, redis_publish_seconds, redis_backup_pending, redis_backup_dropped_total) |
| 능동 방어 | 3단계 (rate limit → IP block → endpoint disable) |
| 신뢰성 | Redis 메모리 백업 deque(1000) + 30s 드레인, 2~5 replica HPA, maxUnavailable=0 롤링 |
| 보안 | Bearer 토큰 인증, K8s Secret 분리, non-root + readOnlyRoot + cap drop ALL + seccomp |
| 관측성 | JSON 로깅 + 12자 hex trace_id + Prometheus 비즈니스 메트릭 6종 + `/diagnostics` |
| 문서 | 6 .md/pdf (계획·매뉴얼·온보딩·트러블슈팅·핸드오프·보고서) |
| 머지된 PR | 3건 (#1, #2, #7) |
| 외부 의존성 | Redis(elden-monitoring), Istio(Lv1~3 방어), ingress-nginx(WAF), metrics-server(HPA), Falco Sidekick(이벤트 인입) |
