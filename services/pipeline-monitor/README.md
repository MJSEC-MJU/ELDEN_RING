# Pipeline Monitor

ELDEN RING 4-Phase 파이프라인의 실시간 시각화 + 결과 대시보드.

## 화면 구성

| 탭 | 내용 |
|---|---|
| **Live Pipeline** | 4-phase 노드 다이어그램, 메시지 흐를 때 노드 하이라이트 + 엣지 애니메이션, 실시간 이벤트 로그 |
| **Incidents** | 모든 incident 테이블, 행 클릭 시 Phase 1~4 전체 결과를 보여주는 상세 모달 |
| **Stats** | 카운터 (전체 incident, high-risk, manual approval 대기) + CWE/Risk 분포, CWE별 평균 처리 시간과 최근 incident 드릴다운 |

## 동작 원리

```
Phase 1 → Redis(elden:phase2:context) ─┐
Phase 2 → Redis(elden:phase3:validate) ─┤
Phase 3 → Redis(elden:phase4:promote)  ─┼─▶ pipeline-monitor (subscribe)
                                        │      ├─▶ in-memory state (events + incidents)
                                        │      ├─▶ /ws  WebSocket 브로드캐스트
                                        │      ├─▶ /api/incidents (REST)
                                        │      ├─▶ /api/events    (REST)
                                        │      └─▶ /api/stats     (REST)
                                        │      
governance /incidents API ──[poll 5s]───┘      ▶  서빙: /  → SPA (React + ReactFlow + Chart.js, CDN)

브라우저
  ├─ ws://host/ws         → 실시간 노드 하이라이트 + 이벤트 로그
  └─ http://host/api/...  → 상세 모달, 통계 차트
```

## 로컬 실행 (개발)

```bash
cd services/pipeline-monitor
python -m pip install -r requirements.txt
python -m uvicorn src.main:app --host 0.0.0.0 --port 8080 --reload
# 브라우저: http://localhost:8080
```

Redis 가 로컬에서 돌고있어야 함:
```bash
docker run -d --rm --name elden-redis -p 6379:6379 redis:7-alpine
export MONITOR_REDIS_URL=redis://localhost:6379/0
```

## 클러스터 배포 (Kind)

```bash
# 이미지 빌드 + kind load
docker build -t ghcr.io/mjsec-mju/elden-pipeline-monitor:dev-latest services/pipeline-monitor
kind load docker-image ghcr.io/mjsec-mju/elden-pipeline-monitor:dev-latest --name elden-gov-test

# 배포
kubectl apply -f kubernetes/environments/monitoring/pipeline-monitor.yaml

# 브라우저 접속
kubectl port-forward -n elden-monitoring svc/pipeline-monitor 3000:80
# http://localhost:3000
```

## 환경 변수

| 변수 | 기본값 | 설명 |
|---|---|---|
| `MONITOR_REDIS_URL` | `redis://redis-master.elden-monitoring:6379/0` | Redis 브로커 |
| `MONITOR_GOVERNANCE_URL` | `http://governance-controller.elden-governance:8080` | Phase 4 controller (incident 상태 polling) |
| `LOG_LEVEL` | `INFO` | 로그 레벨 |

## API

| 엔드포인트 | 설명 |
|---|---|
| `GET /` | SPA (HTML) |
| `GET /healthz` | health check |
| `GET /api/incidents` | 모든 incident 스냅샷 (Phase 1~4 정보 포함) |
| `GET /api/events` | 최근 이벤트 (최대 500건) |
| `GET /api/stats` | 통계 (CWE/Risk/Stage 분포, CWE별 평균 처리 시간/최근 incident) |
| `WS /ws` | 실시간 이벤트 + incident 업데이트 push |

## 시연 시나리오

1. setup-elden-ring 으로 4-phase 클러스터 띄움
2. pipeline-monitor port-forward → 브라우저 열기
3. 다른 터미널에서 Phase 1 attack 주입 (`/api/v1/events/manual`)
4. **화면에서 실시간으로**:
   - Phase 1 노드 → 노란색 (active) → 초록색 (recent)
   - Phase 1 → Phase 2 엣지 cyan 애니메이션
   - Phase 2 노드 → active → recent
   - Phase 3 → Phase 4 순차 활성화
   - Phase 4 가 manual_approval 단계면 빨간색 유지
5. Incidents 탭 → 새 incident 클릭 → 상세 모달에서 CWE / patch / 검증 / governance 결과 한 눈에
