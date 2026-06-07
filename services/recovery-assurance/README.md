# Phase 3: Recovery Assurance Plane

Secure Coding Plane이 만든 `candidate_image`를 staging 환경 기준으로 검증하고, 통과하면 Governance Plane으로 넘기는 Phase 3 구현이다.
Startup, regression, security replay, SLO 판정은 configured LLM CLI(`codex` 또는 `claude`)의 structured JSON 응답으로 수행한다.

## 구조

```text
phase3/
├─ src/
│  ├─ main.py
│  └─ recovery_assurance_plane/
│     ├─ app.py
│     ├─ config.py
│     ├─ constants.py
│     ├─ messaging.py
│     ├─ models.py
│     ├─ service.py
│     ├─ stages.py
│     └─ store.py
├─ tests/
│  └─ test_phase3_contract.py
├─ Dockerfile
├─ requirements.txt
└─ README.md
```

## 실행

```bash
cd phase3
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8080
```

Redis 구독 워커:

```bash
python -m worker
```

## API

Base path:

```text
/api/v1/recovery-assurance
```

주요 엔드포인트:

- `POST /validate`
- `GET /jobs/{validation_job_id}`
- `GET /jobs/{validation_job_id}/result`
- `POST /jobs/{validation_job_id}/rerun`
- `GET /health`

## 검증 순서

```text
deploy
-> startup_check
-> regression_test
-> security_replay
-> slo_check
-> finalize
```

실패하면 이후 단계는 `not_run`으로 남기고 `elden:phase2:retry` payload를 만든다. 성공하면 `elden:phase4:promote` payload를 만든다.

## LLM 설정

| 변수 | 기본값 | 설명 |
|---|---|---|
| `RA_LLM_PROVIDER` | `codex` | `codex` 또는 `claude` |
| `RA_CODEX_COMMAND` | `codex` | Codex CLI 경로/명령 |
| `RA_CODEX_MODEL` | - | Codex 모델 override |
| `RA_CLAUDE_COMMAND` | `claude` | Claude Code CLI 경로/명령 |
| `RA_CLAUDE_MODEL` | - | Claude 모델 override |
| `RA_LLM_TIMEOUT_SEC` | `180` | Stage별 LLM 호출 timeout |

`elden:phase4:promote`는 Phase 4의 `Phase3Result.parse()`가 바로 읽을 수 있도록 다음 구조로 발행한다.

```json
{
  "phase2": { "patch_id": "patch-001", "candidate_image": "..." },
  "exploit": "PASSED",
  "regression": "PASSED",
  "slo": "PASSED",
  "severity": "HIGH"
}
```

## Redis 채널

| 방향 | 채널 |
|---|---|
| Phase 2 -> Phase 3 | `elden:phase3:validate` |
| Phase 3 -> Phase 4 | `elden:phase4:promote` |
| Phase 3 -> Phase 2 | `elden:phase2:retry` |
