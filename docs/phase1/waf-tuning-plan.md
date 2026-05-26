# Phase 1 — WAF (ModSecurity CRS) 튜닝 계획

> 본 문서는 Phase 1 Week 11~12 검토에서 식별된 **CRS 942 (SQL Injection) 룰 family의 오탐(False Positive)** 처리 방침을 정리한다. 이번 단계의 범위는 **샘플 분리 + 튜닝 항목 등록**까지이며, 실제 룰 변경은 후속 작업에서 진행한다.

---

## 1. 배경

- 환경: NGINX Ingress + ModSecurity + OWASP CRS v3.3 (`kubernetes/service-mesh/ingress/configmap.yaml`)
- 부하 측정: `scripts/loadtest/run.sh` (200 RPS × 5분 정상 + 50 RPS SQLi)
- 관찰된 오탐율: **약 0.3%** (≈ 180건 / 200 RPS × 300s × ~0.003)
- 룰 family: **CRS 942100 – 942999** (`SQL Injection`)
  - 빈도 상위 ID: `942100` (common testing), `942130` (tautology), `942190` (UNION pattern), `942260` (stacked queries)

## 2. FP 샘플 분리

오탐 샘플은 다음 위치에 별도 파일로 분리해 등록한다.

- `scripts/loadtest/payloads/fp-samples/942_false_positives.json`
  - 7개 representative shape (자연어 따옴표 / 검색어 OR / bio 세미콜론 / `O'Reilly` 파일명 / `>>` 인용 / `union_id` 필드명 / OR'd 주문 메모)
  - 각 항목에 `modsec_rule_hits` 와 `expected_to_be: allowed` 명시

## 3. 튜닝 항목 (등록만, 적용은 후속)

| ID | CRS Rule | FP Trigger 표현 | 제안 대응 | 위험 |
|---|---|---|---|---|
| WAF-T-01 | 942100 | 자연어 텍스트 내 `'` + 동사형 단어 | `SecRuleUpdateTargetById 942100 !REQUEST_BODY:bio` (특정 필드 화이트리스트) | low — bio 필드는 자유 텍스트 |
| WAF-T-02 | 942130 | tautology heuristic, `OR`+숫자 | 부정 lookbehind 또는 `t:lowercase, t:removeWhitespace` 후 단어경계 강제 | medium — 진짜 tautology와 충돌 가능 |
| WAF-T-03 | 942190 | `UNION`이 식별자 일부 (`union_id`) | 단어경계 + 케이스 보존 (`\bUNION\b` 정규식 강화) | low |
| WAF-T-04 | 942260 | 자연어 세미콜론 절 분리 | 세미콜론 뒤 SQL 키워드 동반 시에만 fire (`(?i);\s*(select|update|insert|delete|drop)`) | medium — stacked query 패턴 협소화 |
| WAF-T-05 | 942500 | `SELECT *`가 인용문 안에 등장 | `REQUEST_BODY` 인용 문맥 안에서는 skip | medium |

## 4. 적용 방향 (후속)

1. **rule exclusion 좁게 적용**
   - 룰 자체를 *비활성화*하지 않는다. `SecRuleUpdateTargetById` 또는 `ctl:ruleRemoveById` 를 **엔드포인트 / 파라미터 단위**로 한정.
2. **샘플 수 확대 후 결정**
   - 현재 7건은 representative만. 본 적용 전 같은 부하 셋업으로 **최소 1주 분량 (~10만 요청)** 로깅 후 동일 shape이 재현되는지 확인.
3. **튜닝 후 회귀 보호**
   - `scripts/loadtest/payloads/fp-samples/942_false_positives.json` 의 모든 sample이 `expected_to_be: allowed` 로 통과하는지 검증하는 회귀 테스트를 `services/runtime-defense/tests/` 에 추가.
   - 동시에 `scripts/loadtest/payloads/sqli.json` 류 진짜 SQLi 샘플 30건은 여전히 blocked 되는지 동일 회귀에서 확인.

## 5. 이번 단계 산출물

- [x] FP 샘플 분리 — `scripts/loadtest/payloads/fp-samples/942_false_positives.json`
- [x] 튜닝 항목 등록 — 본 문서 3절
- [ ] 실제 룰 튜닝 적용 — **후속 작업** (별도 PR 예정)
- [ ] 회귀 테스트 (튜닝 적용 후 동시에 추가)

## 6. 참고

- CRS 942 룰 family 공식 문서: <https://coreruleset.org/docs/rules/sqli/>
- ModSecurity exclusion 방식 비교: `SecRuleRemoveById` (전체 비활성) vs `SecRuleUpdateTargetById` (대상 좁힘) — 본 계획은 후자만 사용.
