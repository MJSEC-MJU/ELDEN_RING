# Phase 1 Onboarding

신규로 Phase 1 (Runtime Defense Plane) 에 합류한 팀원을 위한 4주 가이드.
이미 코드는 있고, 본인이 첫 변경을 안전하게 만들 수 있게 되는 것이 목표.

---

## 1주차 — 무엇을 만드는지 이해

**읽을 것** (순서대로)

1. 루트 `README.md` — ELDEN RING 4 Phase 전체 흐름
2. `CONTRIBUTING.md` — 작업 위치 / 브랜치 / CI 규약
3. `docs/phase1/development-plan.md` — Phase 1 자세한 계획
4. `services/runtime-defense/README.md` — 보안/신뢰성/관측성 설계
5. `docs/phase1/manual-testing-guide.md` — 동작을 직접 본다

**개념 학습** (Phase 1 이 의지하는 것)

- ModSecurity + OWASP CRS — WAF 규칙 분류 (942xxx=SQLi 등)
- Falco — 시스템 콜 기반 런타임 탐지
- Redis Pub/Sub + List — Phase 2 로 컨텍스트 전달 패턴
- FastAPI + asyncio — 어댑터/디펜스의 비차단 처리

---

## 2주차 — 로컬 개발환경

**클러스터 세팅**
```bash
./scripts/setup-cluster.sh --dev    # kind + Phase 1 ~ 4 기본 배포
kubectl get pods -A -l elden-ring/plane
```

**runtime-defense 단독 실행**
```bash
cd services/runtime-defense
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 토큰 미설정 → 인증 비활성 모드. 빠른 실행용.
uvicorn src.main:app --reload --port 8080
```

**테스트 실행**
```bash
python -m pytest tests/ -v
```

**파이프라인 직접 호출**
```bash
curl -X POST localhost:8080/api/v1/events/manual \
  -H "Content-Type: application/json" \
  -d '{"attack_category":"SQL Injection",
       "target_endpoint":{"method":"POST","path":"/api/login"},
       "payload_sample":"admin'\'' OR 1=1 --",
       "severity":"CRITICAL"}'

curl -s localhost:8080/diagnostics | jq
```

---

## 3주차 — 코드 읽기 순서

읽어내려가면 자연스럽게 이해됨:

```
src/main.py                       (1) FastAPI 엔드포인트 + run_pipeline 흐름
  └── src/auth.py                 (2) Bearer 토큰 dependency
src/normalizer.py                 (3) 어댑터 라우팅
  ├── src/adapters/base.py        (4) 베이스 + generate_event_id
  ├── src/adapters/modsecurity.py (5) ModSec audit log → NormalizedEvent
  └── src/adapters/falco.py       (6) Falco webhook → NormalizedEvent
src/cwe_mapping.py                (7) 카테고리 → CWE 테이블
src/source_mapper.py              (8) URL → 파일:함수:라인
src/defense/manager.py            (9) Lv1→Lv3 에스컬레이션
  ├── src/defense/rate_limiter.py     (10) Istio EnvoyFilter
  ├── src/defense/ip_blocker.py       (11) AuthorizationPolicy
  └── src/defense/endpoint_disabler.py (12) VirtualService
src/context_builder.py            (13) 최종 JSON 패키지
src/redis_publisher.py            (14) Pub/Sub + Queue + 메모리 백업
src/logging_config.py             (15) JSON 로그 + trace_id
src/metrics.py                    (16) 비즈니스 SLI
src/payload_utils.py              (17) 1KB truncate
```

각 파일에 대응하는 `tests/test_*.py` 가 있다. 새 코드를 짤 땐 기존 테스트
스타일을 따라가면 리뷰 통과율이 높아진다.

---

## 4주차 — 첫 변경

작은 변경부터:

- 새 ModSecurity rule range 추가 (예: 921xxx Protocol Anomaly)
- Falco custom rule 의 새 tag → `FALCO_CATEGORY_MAP` 추가
- 메트릭 라벨 추가 / Histogram bucket 조정
- 트러블슈팅 문서에 자기 시나리오 추가

PR 체크리스트:

- [ ] `pytest tests/ -q` 전부 통과
- [ ] `docs/phase1/cross-team-handoffs.md` 에 Phase 2/3/4 인터페이스 변경 사항이 있다면 기록
- [ ] `services/runtime-defense/README.md` / `manual-testing-guide.md` 가 새 동작과 일치
- [ ] 커밋 메시지 형식: `feat(phase1): ...` / `fix(phase1): ...`
- [ ] PR 대상 브랜치는 항상 `dev` (CONTRIBUTING.md 참조)

---

## 자주 묻는 질문

**Q. WEBHOOK_AUTH_TOKEN 이 비어있으면 위험하지 않나?**
로컬 개발용 escape hatch. 컨트롤러 시작 시 경고 로그 1줄로 명시되며
프로덕션 manifest 는 항상 Secret 으로 토큰을 채운다 (`runtime-defense-secret.yaml`).

**Q. Redis 가 다운되면 이벤트는 어디로?**
컨트롤러 메모리 deque(상한 1000개, FIFO drop). 30 초마다 백그라운드
드레인 태스크가 Redis 회복 시 다시 보낸다. `/diagnostics` 의
`redis.backup_pending` / `backup_dropped_total` 로 모니터링.

**Q. Phase 2 와 인터페이스를 바꿔야 한다면?**
`context_builder.py` 의 결과 스키마는 Phase 2 가 의존하는 계약.
필드 추가는 안전(additive). 필드 제거/이름 변경은 `cross-team-handoffs.md`
에 항목 추가 후 Phase 2 담당자(이윤태)와 합의.

**Q. 누가 어떤 영역을 담당?**
루트 `README.md` 의 "Phase ↔ 네임스페이스 ↔ 담당자" 표 참조.
공유 인프라(Falco, NetworkPolicy, ResourceQuota, 모니터링)는 시스템
담당(이종윤)이며, Phase 1 단독으로 손대지 않는다.
