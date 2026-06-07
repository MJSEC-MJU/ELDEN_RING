# Phase 1 Troubleshooting

운영 중 가장 자주 만나는 문제와 1차 진단 방법.

---

## 사용 도구 빠른 참조

| 명령 | 용도 |
|---|---|
| `kubectl logs -n elden-production deployment/runtime-defense-controller --tail=50` | 컨트롤러 최근 로그 (JSON 한 줄씩) |
| `kubectl get pods -n elden-production -l app=runtime-defense-controller` | Pod 상태 |
| `kubectl port-forward -n elden-production svc/runtime-defense-controller 8080:8080` | 로컬에서 API 직접 호출 |
| `curl -s localhost:8080/diagnostics \| jq` | Redis/파이프라인/auth 상태 한눈에 |
| `curl -s localhost:8080/metrics` | Prometheus 메트릭 raw |

---

## 1. Pod 이 CrashLoopBackOff

**증상**: `kubectl get pods` 가 `CrashLoopBackOff` 또는 `Error` 표시

**1차 진단**
```bash
kubectl describe pod -n elden-production -l app=runtime-defense-controller | tail -40
kubectl logs -n elden-production deployment/runtime-defense-controller --previous --tail=80
```

**자주 발생하는 원인**

| 단서 | 가능성 |
|---|---|
| `OOMKilled` (describe 의 Last State) | 메모리 한도 초과. `runtime-defense.yaml` 의 `limits.memory` 올리거나 백업 큐(`MEMORY_BACKUP_MAX_SIZE`) 줄이기 |
| `route_map` 파싱 실패 로그 | `route-map` ConfigMap 손상. `kubectl get cm route-map -o yaml` 확인 |
| `ImportError` / `ModuleNotFoundError` | 빌드 시 의존성 누락. `requirements.txt` ↔ 이미지 태그 미스매치 |
| `Permission denied` (in-cluster auth) | `runtime-defense-sa` ServiceAccount 또는 RoleBinding 누락 |

---

## 2. 이벤트가 수신되지 않는다

**증상**: 공격이 발생해도 컨트롤러 로그에 `pipeline_complete` 안 나옴

**1차 진단**
```bash
# (a) 인증 활성 여부
curl -s localhost:8080/diagnostics | jq .auth_enforced

# (b) 어댑터/route-map 로드 상태
curl -s localhost:8080/readyz | jq

# (c) 발신 측에 도달하는지 (Falco)
kubectl logs -n falco -l app.kubernetes.io/name=falco-falcosidekick --tail=30 | grep -i webhook
```

**자주 발생하는 원인**

| 증상 | 원인 |
|---|---|
| `auth_enforced: true` 인데 발신 측 로그에 401 | 토큰 불일치. 회전 후 Falco/ModSec 시퍼와 동기화 안 됨 (cross-team-handoffs.md H-001) |
| 발신측에서 400/422 응답 | 페이로드 스키마 불일치. `failed_parses` 카운트 증가 (`/api/v1/events/stats`) |
| 발신측 로그에 `connection refused` | Service/Pod 가 안 떠 있거나 NetworkPolicy 차단 |

---

## 3. Phase 2 가 컨텍스트를 못 받는다

**증상**: 컨트롤러는 정상 동작인데 Phase 2 처리량이 0

**1차 진단**
```bash
# (a) Redis 연결 상태
curl -s localhost:8080/diagnostics | jq .redis

# (b) 큐 길이 (Phase 2 가 쌓고만 있는 경우)
kubectl exec -n elden-monitoring redis-master-0 -c redis \
  -- redis-cli LLEN elden:phase2:context:queue

# (c) Phase 2 가 구독 중인지
kubectl exec -n elden-monitoring redis-master-0 -c redis \
  -- redis-cli PUBSUB CHANNELS 'elden:*'
```

**자주 발생하는 원인**

| 증상 | 원인 |
|---|---|
| `redis.connected: false` | NetworkPolicy 또는 Redis Pod 다운. 그동안 이벤트는 메모리 백업으로 들어감 (`backup_pending` 증가) |
| `backup_pending` 이 1000 (상한) | Redis 장기 다운으로 백업 가득. 가장 오래된 항목 폐기 중 (`backup_dropped_total` 증가) |
| Pub/Sub 채널은 받는데 큐가 비어있음 | Phase 2 가 LPUSH 가 아닌 PUBLISH 만 구독. Phase 2 워커 로직 확인 필요 |

---

## 4. WAF 가 정상 트래픽을 차단

**증상**: 평소 잘 되던 요청이 갑자기 403

**1차 진단**
```bash
# 차단 사유 (rule id)
kubectl logs -n ingress-nginx -l app.kubernetes.io/name=ingress-nginx --tail=100 \
  | grep -i "ModSecurity\[id"

# 컨트롤러가 받은 분류
curl -s localhost:8080/api/v1/events/stats | jq .by_category
```

ModSecurity rule ID 가 942xxx(SQLi), 941xxx(XSS), 930xxx(Path Traversal) 인지 확인.
False positive 가 잦으면 OWASP CRS 의 paranoia level 조정 또는 특정 룰 예외 처리 필요.
ModSecurity 설정 변경은 `kubernetes/service-mesh/ingress/configmap.yaml`.

---

## 5. 메트릭/로그가 비어있다

**증상**: Grafana 대시보드 또는 Loki 검색에 Phase 1 데이터 없음

**1차 진단**
```bash
# 메트릭 스크랩 가능한지
curl -s localhost:8080/metrics | head -20

# Pod annotation 확인 (prometheus.io/scrape=true)
kubectl get pod -n elden-production -l app=runtime-defense-controller -o yaml \
  | grep prometheus
```

로그가 안 나오면:
- `LOG_LEVEL=DEBUG` 로 일시 변경 후 `kubectl rollout restart`
- Loki Promtail label selector 가 `app=runtime-defense-controller` 와 매치하는지 확인 (모니터링 담당자에게)

---

## 더 봐야 할 곳

- `services/runtime-defense/README.md` — 보안/신뢰성/관측성 설계 메모
- `docs/phase1/manual-testing-guide.md` — kind 클러스터에서 직접 공격해보기
- `docs/phase1/cross-team-handoffs.md` — 다른 Phase/시스템 담당자와의 합의 사항
