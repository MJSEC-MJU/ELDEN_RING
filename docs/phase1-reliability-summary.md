# Phase 1 부하 / 장애 복구 검증 결과

> 11주차 중간 발표 신뢰성 섹션용 요약.
> 측정 원본: `scripts/loadtest/results/20260511T051313Z/` (= `latest`).
> 재현: `make chaos` (루트 Makefile).

## 한 줄 요약

> 정상 200 RPS + SQLi 50 RPS를 5분간 흘리고 도중 Redis를 60초 다운시켰을 때 **Phase 1은 이벤트 0건 손실로 백업 큐 활성화 → 9초 드레인**까지 회복했으며, 발표 합격 기준 6개 항목 모두 PASS했다.

## 시나리오

| 항목 | 값 |
|---|---|
| 부하 대상 | Phase 1 컨트롤러 단독 (`POST /api/v1/modsec-events`) |
| 부하 도구 | vegeta 12.13.0 |
| 정상 트래픽 | 200 RPS × 5분 = 60,000건 (ModSec 942100 룰 매칭 X, 양성 페이로드) |
| 공격 트래픽 | 50 RPS × 5분 = 15,000건 (ModSec CRS 942100/942130, SQLi tautology) |
| 장애 주입 | 부하 시작 60초 후 `docker stop redis` → 60초 후 자동 `docker start` |
| 환경 | docker-compose: `runtime-defense + redis + prometheus` 단독. WAF/target-app 우회, K8s 없음 |

## 측정 결과

| # | 합격 기준 | 결과 | 측정값 |
|---|---|:---:|---|
| 1 | dropped events == 0 | ✅ PASS | **0건** |
| 2 | backup queue가 activate하고 capacity 내 | ✅ PASS | **peak 124 / 1000** |
| 3 | `redis_healthy` 후 drain ≤ 30 s | ✅ PASS | **9.0 s** |
| 4 | HPA max replicas ≥ 4 | ➖ N/A | docker 환경 (HPA 없음) |
| 5 | HPA 5분 내 2 복귀 (DEMO 프로필) | ➖ N/A | 동상 |
| 6 | `/diagnostics` 5xx == 0 | ✅ PASS | **0건** |

**구간별 처리량 (events/sec, 1분 sliding window)**

| 구간 | 샘플 수 | 평균 throughput | redis_up 비율 | max queue |
|---|---|---|---|---|
| Outage 전 (warm-up 포함) | 57 | 123 eps | 100% | 0 |
| **Outage 중 (60 s)** | 14 | **247 eps** | 14% | **124** |
| Outage 후 | 190 | 245 eps | 100% | 0 |

> Outage 중에도 Phase 1은 `247 eps`를 유지. Redis가 죽은 동안 publish 실패 → in-memory FIFO 큐로 폴백 → 복구 후 일괄 drain까지 자동.

## 그래프

### `scripts/loadtest/results/latest/throughput_hpa.png`
**캡션**: Phase 1 처리량은 부하 시작 30 초 후 250 eps에 도달, **Redis 60초 다운 구간(빨간 음영)에도 throughput 거의 흔들림 없이 유지**. 다운 직후 슬라이딩 윈도우 상 일시 surge는 큐 drain 시 누적 이벤트가 가산된 결과. (HPA는 docker 환경 미적용)

### `scripts/loadtest/results/latest/redis_outage_queue.png`
**캡션**: `redis_up`(시안)이 outage 시작 직후 0으로 전환, `backup queue length`(주황)가 0 → 124까지 선형 증가, **redis 복구 시점에 9초 만에 0으로 drain**. 누적 drop(보라)은 전 구간 0.

## 한계 / 남은 이슈

이번 측정에서 드러난 부수적 finding (향후 작업 항목):

1. **vegeta 클라이언트 측 timeout 21%** — outage 중 vegeta 요청 5초 타임아웃이 ~15,000건 누적. Phase 1 내부 합격 기준(드롭 0, 큐 capacity 내, 9초 drain)은 모두 만족했지만, 클라이언트는 outage 동안 응답을 거의 받지 못함. 원인은 `redis-py` 동기 클라이언트가 `asyncio.to_thread` 기본 풀(32 워커)에 묶여 250 RPS 입력을 따라가지 못함. 운영 시 publish 경로를 `redis.asyncio`로 비동기화하거나 풀 사이즈를 늘리는 작업이 필요.

2. **Defense layer가 이벤트 루프 차단** — 발견 후 본 측정에서는 `DEFENSE_APPLY_ENABLED=false`로 단락. `apply_rate_limit`/`block_ip`/`disable_endpoint`가 `async`로 선언됐지만 내부에서 동기 `kubernetes-python` 호출을 수행하여 K8s API가 느려지면 이벤트 루프 전체가 멈추는 구조. 운영 K8s 환경에서도 API 지연 시 동일 증상 가능 → defense 호출을 thread offload 또는 fire-and-forget으로 분리할 것.

3. **HPA 거동 미측정** — docker-compose에 HPA가 없어 합격 기준 4·5 N/A. kind 클러스터에서 `runtime-defense-hpa-demo.yaml`을 apply한 뒤 동일 시나리오 재현하면 측정 가능. **합격 기준 5의 "5분 내 복귀"는 데모 전용 HPA 프로필** 기준이며, 운영 HPA(`runtime-defense-hpa.yaml`)는 백업 큐 유실 방지를 위해 의도적으로 더 느림(약 15분).

## 재현 절차

```bash
# 사전: Docker Desktop 실행, vegeta(brew install vegeta) 설치
make chaos
# → scripts/loadtest/results/<timestamp>/REPORT.md 자동 생성
# → throughput_hpa.png, redis_outage_queue.png 자동 생성
```

자동 합격 판정 기준 코드: `scripts/observe/verify.py`. exit 0 = PASS, 1 = FAIL.
