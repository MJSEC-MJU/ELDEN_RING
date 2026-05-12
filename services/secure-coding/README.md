# Secure Coding Service

Phase 2만 담당하는 독립 서비스다. 입력으로 `RuntimeContextPackage`를 받아 취약 코드 범위를 읽고, 패치 생성, 안전성 재검사, workspace 반영, candidate image 생성까지 수행한다.

## 포함 범위

- `src/secure_coding_plane/config.py`: 서비스 로컬 설정 로더
- `src/secure_coding_plane/schemas.py`: Phase 2 전용 Pydantic 모델
- `src/secure_coding_plane/storage.py`: SQLite 기반 job/artifact store
- `src/secure_coding_plane/messaging.py`: Redis publish helper
- `src/secure_coding_plane/worker.py`: Redis subscribe worker
- `src/secure_coding_plane/*.py`: analysis, strategy, patch, apply, build 엔진

이 디렉토리는 `elden_planes` 공용 패키지에 의존하지 않는다.

## 실행

```powershell
cd services/secure-coding
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PLANE_WORKSPACE_ROOT = "$PWD\\runtime\\workspace"
$env:SECURE_CODING_LLM_PROVIDER = "mock"
python -m uvicorn src.main:app --host 0.0.0.0 --port 8080
```

Redis worker를 별도로 띄우려면:

```powershell
cd services/secure-coding
$env:PLANE_REDIS_URL = "redis://localhost:6379/0"
python -m src.worker
```

## 테스트

```powershell
cd services/secure-coding
python -m unittest discover tests -v
```

## 주요 환경변수

- `PLANE_WORKSPACE_ROOT`: 패치 대상 코드 root
- `PLANE_ARTIFACT_ROOT`: diff, snapshot, build log 저장 위치
- `PLANE_DB_PATH`: SQLite DB 경로
- `PLANE_REDIS_URL`: Redis 연결 문자열
- `SECURE_CODING_LLM_PROVIDER`: `mock`, `codex`, `claude`, `anthropic`
- `SECURE_CODING_BUILD_MODE`: `simulate`, `command`
- `SECURE_CODING_BUILD_COMMAND`: 실제 이미지 빌드 명령
- `SECURE_CODING_BUILD_IMAGE_TAG`: 결과 candidate image tag override

### LLM provider 별 동작

| provider | 인증 | temperature | prompt cache | 권장 용도 |
|---|---|---|---|---|
| `mock` | 불필요 | 무시 | 무관 | CI / 빠른 dev 루프 |
| `codex` | `codex login` | **무시됨** (CLI 미노출, metadata `llm_temperature_applied=false`) | CLI 자체 처리 | 기존 OpenAI Codex 사용자 |
| `claude` (= `claude_code`) | `claude auth login` | **무시됨** (CLI 미노출, metadata `llm_temperature_applied=false`) | CLI 자체 처리 | Claude Code OAuth 사용자 |
| `anthropic` | `ANTHROPIC_API_KEY` | **적용됨** (메시지 API kwargs) | **`cache_control: ephemeral`** 부착 | 보고서 약속(70% 절감 측정) 검증 시 |

### Retry / Cache / Temperature 환경변수 (Tier 1 PR 추가)

- `SECURE_CODING_MAX_PATCH_RETRY`: LLM 패치 실패 시 재시도 횟수 (default `3`)
- `SECURE_CODING_LLM_TEMPERATURE`: 첫 시도 temperature (default `0.2`)
- `SECURE_CODING_RETRY_TEMP_STEP`: 매 재시도마다 추가되는 값 (default `0.3`)
- `SECURE_CODING_RETRY_TEMP_CAP`: temperature 상한 (default `1.0`)
- `SECURE_CODING_PROMPT_CACHE_ENABLED`: Anthropic `cache_control` 부착 여부 (default `true`)
- `SECURE_CODING_LLM_MAX_TOKENS`: Anthropic max_tokens (default `2048`)
- `SECURE_CODING_ANTHROPIC_API_KEY` 또는 `ANTHROPIC_API_KEY`: `anthropic` provider 인증
- `SECURE_CODING_ANTHROPIC_MODEL`: Anthropic 모델 (default `claude-sonnet-4-6`)

재시도 정책:
- `LlmConfigError` (CLI not found / auth 실패 / SDK 미설치 / API key 누락) → **즉시 중단** (재시도 의미 없음)
- `LlmPatchClientError` (네트워크/일시 오류 / `patched_snippet` 누락 / `change_summary.security_fix` 누락) → 다음 시도, temperature += step
- `MAX_PATCH_RETRY` 회 모두 실패 → 최종 raise

`change_summary` 에 기록되는 추적 필드:
- `llm_attempts`: 성공까지 걸린 시도 횟수
- `llm_requested_temperature`: 마지막 시도의 요청 temperature
- `llm_temperature_applied`: SDK 호출에 실제 적용됐는지 (CLI provider 는 `false`)
- `llm_usage`: Anthropic provider 시 `input_tokens`, `output_tokens`, `cache_creation_input_tokens`, `cache_read_input_tokens`
