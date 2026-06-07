# Secure Coding Service

Phase 2만 담당하는 독립 서비스다. 입력으로 `RuntimeContextPackage`를 받아 취약 코드 범위를 읽고, 패치 생성, 안전성 재검사, workspace 반영, candidate image 생성까지 수행한다.

## 포함 범위

- `src/secure_coding_plane/config.py`: 서비스 로컬 설정 로더
- `src/secure_coding_plane/schemas.py`: Phase 2 전용 Pydantic 모델
- `src/secure_coding_plane/storage.py`: SQLite 기반 job/artifact store
- `src/secure_coding_plane/messaging.py`: Redis publish helper
- `src/secure_coding_plane/worker.py`: Redis queue/retry worker
- `src/secure_coding_plane/*.py`: analysis, strategy, patch, apply, build 엔진

이 디렉토리는 `elden_planes` 공용 패키지에 의존하지 않는다.

## 실행

```powershell
cd services/secure-coding
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:PLANE_WORKSPACE_ROOT = "$PWD\\runtime\\workspace"
$env:SECURE_CODING_LLM_PROVIDER = "codex"   # or "claude"
python -m uvicorn src.main:app --host 0.0.0.0 --port 8080
```

Redis worker를 별도로 띄우려면:

```powershell
cd services/secure-coding
$env:PLANE_REDIS_URL = "redis://localhost:6379/0"
$env:SECURE_CODING_INGEST_QUEUE = "elden:phase2:context:queue"
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
- `SECURE_CODING_INGEST_QUEUE`: Phase 1 context 영속 큐. 기본값 `elden:phase2:context:queue`
- `SECURE_CODING_INGEST_CHANNEL`: Pub/Sub fallback 채널. 기본값 `elden:phase2:context`
- `SECURE_CODING_VALIDATE_CHANNEL`: Phase 3 검증 요청 발행 채널. 기본값 `elden:phase3:validate`
- `SECURE_CODING_RETRY_CHANNEL`: Phase 3/4 실패 retry 수신 채널. 기본값 `elden:phase2:retry`
- `SECURE_CODING_LLM_PROVIDER`: `codex`, `claude`
- `SECURE_CODING_BUILD_MODE`: `simulate`, `command`
- `SECURE_CODING_BUILD_COMMAND`: 실제 이미지 빌드 명령
- `SECURE_CODING_BUILD_IMAGE_TAG`: 결과 candidate image tag override
