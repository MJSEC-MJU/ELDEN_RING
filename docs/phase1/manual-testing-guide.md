# Phase 1 Manual Testing Guide

Phase 1 Runtime Defense Plane의 수동 테스트 가이드.
ModSecurity WAF 차단, 이벤트 파이프라인, Redis 컨텍스트 전달을 직접 검증한다.

## Prerequisites

- kind 클러스터 `elden-ring` 실행 중
- `setup-cluster.sh --dev` 완료
- ingress-nginx (ModSecurity + OWASP CRS), runtime-defense-controller, target-app 배포 완료

## 1. Port Forward 설정

```bash
# target-app (Flask 앱 직접 접근, WAF 없음)
kubectl port-forward -n elden-production svc/target-app 5000:5000 &

# target-app via WAF (ModSecurity 경유)
kubectl port-forward -n ingress-nginx svc/ingress-nginx-controller 8443:80 &

# runtime-defense-controller (이벤트/컨텍스트 API)
kubectl port-forward -n elden-production svc/runtime-defense-controller 8080:8080 &
```

| 서비스 | URL | 용도 |
|--------|-----|------|
| target-app (직접) | `http://localhost:5000` | WAF 없이 앱 직접 접근 |
| target-app (WAF 경유) | `http://localhost:8443` | ModSecurity 거쳐서 접근 |
| runtime-defense | `http://localhost:8080` | 이벤트/컨텍스트 조회 |

종료 시:
```bash
kill %1 %2 %3
```

## 2. 브라우저 접근

직접 접근 (WAF 없음):
```
http://localhost:5000
```

브라우저에서 WAF 경유 테스트를 하려면 `/etc/hosts`에 추가:
```
127.0.0.1  target-app.elden.local
```
이후:
```
http://target-app.elden.local:8443/
```

## 3. 공격 테스트 (WAF 차단 확인)

WAF 경유 시 반드시 `Host: target-app.elden.local` 헤더를 붙여야 한다.
모든 공격은 **403 Forbidden**으로 차단되어야 정상이다.

### SQL Injection

```bash
curl -v -X POST http://localhost:8443/api/login \
  -H "Host: target-app.elden.local" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1 --","password":"x"}'
```

브라우저 (hosts 설정 후):
```
http://target-app.elden.local:8443/api/login
POST body에 {"username":"admin' OR 1=1 --","password":"x"}
```

### XSS (Cross-Site Scripting)

```bash
curl -v "http://localhost:8443/api/search?q=<script>alert(1)</script>" \
  -H "Host: target-app.elden.local"
```

브라우저:
```
http://target-app.elden.local:8443/api/search?q=<script>alert(1)</script>
```

### Path Traversal

```bash
curl -v "http://localhost:8443/api/file?name=../../../etc/passwd" \
  -H "Host: target-app.elden.local"
```

브라우저:
```
http://target-app.elden.local:8443/api/file?name=../../../etc/passwd
```

### WAF 없이 비교 (취약점 확인)

직접 접근하면 WAF가 없으므로 공격이 통과된다:
```bash
curl "http://localhost:5000/api/search?q=<script>alert(1)</script>"
# 200 OK - 취약점이 그대로 노출됨
```

## 4. 실시간 모니터링

### ModSecurity 차단 로그

```bash
kubectl logs -f -n ingress-nginx \
  -l app.kubernetes.io/name=ingress-nginx \
  | grep -i "modsecurity\|owasp\|403"
```

전체 ingress 로그:
```bash
kubectl logs -f -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx
```

### runtime-defense-controller 로그

```bash
kubectl logs -f -n elden-production \
  -l app=runtime-defense-controller -c controller
```

## 5. 이벤트 파이프라인 테스트

> **인증 필요**: 이벤트 주입 엔드포인트(`/api/v1/modsec-events`,
> `/api/v1/falco-events`, `/api/v1/events/manual`)는 Bearer 토큰
> 인증이 적용되어 있다. 클러스터에서 현재 토큰 조회:
>
> ```bash
> TOKEN=$(kubectl get secret runtime-defense-secrets \
>   -n elden-production \
>   -o jsonpath='{.data.webhook-auth-token}' | base64 -d)
> ```
>
> 로컬에서 `WEBHOOK_AUTH_TOKEN` 미설정으로 컨트롤러를 띄운 경우
> 인증 비활성 모드라 헤더를 생략해도 된다 (시작 로그 경고로 확인).

### 수동 이벤트 주입

SQLi:
```bash
curl -X POST http://localhost:8080/api/v1/events/manual \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "attack_category": "SQL Injection",
    "target_endpoint": {"method": "POST", "path": "/api/login"},
    "payload_sample": "admin'\'' OR 1=1 --",
    "source_ip": "192.168.1.50",
    "severity": "CRITICAL"
  }'
```

XSS:
```bash
curl -X POST http://localhost:8080/api/v1/events/manual \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "attack_category": "Cross-Site Scripting",
    "target_endpoint": {"method": "GET", "path": "/api/search"},
    "payload_sample": "<script>alert(document.cookie)</script>",
    "source_ip": "192.168.1.51",
    "severity": "HIGH"
  }'
```

Path Traversal:
```bash
curl -X POST http://localhost:8080/api/v1/events/manual \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "attack_category": "Path Traversal",
    "target_endpoint": {"method": "GET", "path": "/api/file"},
    "payload_sample": "../../../etc/passwd",
    "source_ip": "192.168.1.52",
    "severity": "HIGH"
  }'
```

### 조회 API

```bash
# 이벤트 통계
curl -s http://localhost:8080/api/v1/events/stats | python3 -m json.tool

# 실행된 방어 조치 목록
curl -s http://localhost:8080/api/v1/defense/actions | python3 -m json.tool

# 방어 통계
curl -s http://localhost:8080/api/v1/defense/stats | python3 -m json.tool

# 특정 컨텍스트 조회 (context_id는 이벤트 주입 응답에서 확인)
curl -s http://localhost:8080/api/v1/contexts/<context_id> | python3 -m json.tool
```

## 6. Redis 큐 확인

```bash
# 큐 길이
kubectl exec -n elden-monitoring redis-master-0 -c redis \
  -- redis-cli LLEN elden:phase2:context:queue

# 큐 내용 전체 조회
kubectl exec -n elden-monitoring redis-master-0 -c redis \
  -- redis-cli LRANGE elden:phase2:context:queue 0 -1

# 최신 1건 (보기 좋게)
kubectl exec -n elden-monitoring redis-master-0 -c redis \
  -- redis-cli LINDEX elden:phase2:context:queue 0 \
  | python3 -m json.tool

# 실시간 Pub/Sub 모니터링 (이벤트 주입할 때 같이 켜두면 실시간 확인)
kubectl exec -it -n elden-monitoring redis-master-0 -c redis \
  -- redis-cli SUBSCRIBE elden:phase2:context
```

## 7. 컨텍스트 패키지 구조

Redis 큐에 전달되는 JSON 구조:

```json
{
  "context_id": "ctx-evt-manual-xxxxxxxx",
  "event_id": "evt-manual-xxxxxxxx",
  "timestamp": "2026-04-08T...",
  "attack_info": {
    "category": "SQL Injection",
    "cwe_id": "CWE-89",
    "cwe_name": "Improper Neutralization of Special Elements used in an SQL Command",
    "owasp_category": "A03:2021",
    "payload_sample": "admin' OR 1=1 --",
    "source_ip": "192.168.1.50",
    "blocked": false
  },
  "target": {
    "endpoint": {"method": "POST", "path": "/api/login"},
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
    "detection_source": "manual",
    "defense_action_taken": "rate_limit+ip_blocked+endpoint_disabled",
    "requires_patch": true
  }
}
```

## 8. 소스 코드 매핑 (route-map)

| Endpoint | 파일 | 함수 | 라인 | CWE |
|----------|------|------|------|-----|
| `POST /api/login` | app.py | login_handler | 28-42 | CWE-89 (SQL Injection) |
| `GET /api/search` | app.py | search_handler | 51-60 | CWE-79 (Reflected XSS) |
| `GET /api/file` | app.py | file_handler | 68-74 | CWE-22 (Path Traversal) |
