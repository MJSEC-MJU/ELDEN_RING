# Codex 재검증 프롬프트 — Tier 1 Round 2 (이전 REQUEST CHANGES 피드백 반영 후)

## 사용 방법

```bash
git worktree add /tmp/elden-tier1-v2 feature/phase2-tier1-retry-caching
cd /tmp/elden-tier1-v2
codex exec --skip-git-repo-check -C . < .github/PROMPT_codex_verify_tier1_round2.md
```

또는 본문 복붙.

---

# 재검증 요청 — 1라운드 REQUEST CHANGES 의 5개 액션 후속 확인

당신은 1라운드에서 이 PR(`feature/phase2-tier1-retry-caching`) 에 대해 **REQUEST CHANGES** 를 냈다. 그때 지적한 5개 액션:

| # | severity | 요약 |
|---|---|---|
| 1 | High | pytest 가 PYTHONPATH=src 없이 실패 — `secure_coding_plane` import vs 기존 `src.secure_coding_plane` 패턴 불일치 |
| 2 | Medium | temperature step-up 이 codex/claude_code CLI provider 에서는 무시되는데 코드/문서에 그 사실이 명확하지 않음 |
| 3 | Medium | `change_summary.security_fix` 누락이 retry 대상이 아님 (그냥 빈 dict 로 대체) |
| 4 | Low/Medium | SDK 미설치 / auth / API key 같은 non-retryable error 도 retry 한도까지 반복 |
| 5 | Low | README 에 anthropic provider 와 신규 env 미명시 |

작성자가 이 5개를 모두 처리했다고 주장한다. 당신은 그 처리가 실제 코드로 정확히 반영됐는지, 그리고 처리 과정에서 새로운 회귀가 없는지 검증해야 한다.

## 검증 대상

```
services/secure-coding/src/secure_coding_plane/config.py
services/secure-coding/src/secure_coding_plane/llm_clients.py
services/secure-coding/src/secure_coding_plane/patching.py
services/secure-coding/README.md
services/secure-coding/tests/test_llm_retry_and_caching.py
```

## 액션별 검증 체크리스트

### 1. [High] pytest 디폴트 명령으로 통과
- [ ] `python -m pytest tests/ -v` (PYTHONPATH 없이) 가 통과하는가?
- [ ] `python -m unittest discover tests -v` 도 통과하는가? (README 명시 명령)
- [ ] 신규 테스트가 `src.secure_coding_plane.*` import 패턴으로 통일됐는가?

### 2. [Medium] CLI provider temperature 투명성
- [ ] `BasePatchCliClient.supports_temperature` 속성이 있는가? CLI 는 `False`, Anthropic SDK 는 `True` 인가?
- [ ] `LlmStructuredResponse` 에 `requested_temperature`, `temperature_applied` 필드가 있는가?
- [ ] CLI provider 가 `temperature` 인자를 받아도 `temperature_applied=False` 로 metadata 에 기록하는가?
- [ ] Anthropic SDK provider 는 실제 SDK kwargs 에 `temperature` 가 들어가고 `temperature_applied=True` 인가?
- [ ] README LLM provider 표가 각 provider 의 temperature 지원 여부를 명시하는가?

### 3. [Medium] change_summary.security_fix 누락도 retry
- [ ] `_call_llm_with_retry` 가 `change_summary` 가 dict 가 아니면 `LlmPatchClientError` raise 하는가?
- [ ] `change_summary.security_fix` 가 누락/빈 문자열이면 `LlmPatchClientError` raise 하는가?
- [ ] 이 raise 가 retry 루프 안에서 잡혀서 다음 attempt 가 진행되는가?
- [ ] 단위 테스트 (`test_retry_loop_treats_missing_security_fix_as_failure`, `test_retry_loop_treats_non_dict_change_summary_as_failure`) 가 이를 검증하는가?
- [ ] 검증된 후 `_generate_patch_payload` 가 다시 동일 검증을 반복하지 않는가? (DRY)

### 4. [Low/Medium] Non-retryable error 즉시 raise
- [ ] `LlmConfigError` 가 신설됐고 `LlmPatchClientError` 의 하위 클래스인가?
- [ ] `LlmConfigError` 가 다음 경우에 raise 되는가:
  - CLI not found (`_check_command_exists`)
  - Codex/Claude auth status 실패
  - Anthropic SDK 미설치 / API key 누락
  - Anthropic SDK 의 `AuthenticationError`, `PermissionDeniedError`, `BadRequestError`, `NotFoundError`, `UnprocessableEntityError`
- [ ] retry 루프가 `LlmConfigError` 를 **즉시 raise** (재시도 0회) 하는가? `except LlmConfigError` 가 `except LlmPatchClientError` 보다 **앞에** 있는가?
- [ ] 단위 테스트 (`test_retry_loop_raises_immediately_on_non_retryable_config_error`) 가 `call_count == 1` 을 검증하는가?

### 5. [Low] README 업데이트
- [ ] `SECURE_CODING_LLM_PROVIDER` 의 값 목록에 `anthropic` 이 추가됐는가?
- [ ] LLM provider 별 동작 표가 있는가 (인증/temperature/cache/권장 용도)?
- [ ] 신규 env 7개 모두 문서화됐는가:
  - `SECURE_CODING_MAX_PATCH_RETRY`
  - `SECURE_CODING_LLM_TEMPERATURE`
  - `SECURE_CODING_RETRY_TEMP_STEP`
  - `SECURE_CODING_RETRY_TEMP_CAP`
  - `SECURE_CODING_PROMPT_CACHE_ENABLED`
  - `SECURE_CODING_LLM_MAX_TOKENS`
  - `SECURE_CODING_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY`
  - `SECURE_CODING_ANTHROPIC_MODEL`
- [ ] retry 정책 (retryable vs non-retryable 분류) 가 README 에 명시됐는가?
- [ ] `change_summary` 추적 필드 (`llm_attempts`, `llm_requested_temperature`, `llm_temperature_applied`, `llm_usage`) 가 설명됐는가?

## 추가 회귀 점검

- [ ] 기존 4개 테스트 모듈 (`test_secure_build_engine`, `test_secure_coding_flow`, `test_secure_coding_worker`, `test_phase3_contract` 등) 도 모두 통과하는가?
- [ ] mock provider 경로 (`_generate_patch_payload` 의 if mock 분기) 가 `attempts=1` / `temperature_applied=False` 로 일관되게 동작하는가?
- [ ] CLI provider 의 기존 호출자(만약 있다면) 가 시그니처 변경(temperature 인자 추가)에 영향 받지 않는가? (default `None`)
- [ ] `LlmConfigError` 가 외부 모듈(`service.py`, `worker.py` 등) 에서 catch 되어야 하는데 catch 안 되면 어떻게 되는가?

## 보고 형식

```markdown
# Codex 재검증 Round 2 — Phase 2 Tier 1

## 핵심 요약
- 머지 권고: [APPROVE / REQUEST CHANGES / NEEDS DISCUSSION]
- Round 1 5개 액션 해결 현황: [N/5 PASS]

## 액션별 검증

| # | 액션 | 1라운드 severity | 2라운드 결과 | 근거 |
|---|---|---|---|---|
| 1 | pytest 디폴트 명령 통과 | High | ✅/⚠️/❌ | ... |
| 2 | CLI temperature 투명성 | Medium | ✅/⚠️/❌ | ... |
| 3 | change_summary.security_fix retry | Medium | ✅/⚠️/❌ | ... |
| 4 | Non-retryable 즉시 raise | Low/Medium | ✅/⚠️/❌ | ... |
| 5 | README 업데이트 | Low | ✅/⚠️/❌ | ... |

## 신규 결함 (있다면)
- ...

## pytest 결과
- `python -m pytest tests/` (PYTHONPATH 없이): N PASS / N FAIL
- `python -m unittest discover tests`: N PASS / N FAIL

## 머지 전 권장 액션 (있다면)
- ...
```

## 지시

- 1라운드 보고와 동일한 엄격함 유지. 부분 해결도 ⚠️ 처리.
- Round 2 만의 새 발견을 우선 보고.
- `git diff feature/phase2-tier1-retry-caching..2bbdb75` (Round 1 vs 현재) 로 diff 확인하면 변경 폭이 명확.
- APPROVE 권고는 5개 액션 모두 ✅ 이고 신규 결함이 없을 때만.
