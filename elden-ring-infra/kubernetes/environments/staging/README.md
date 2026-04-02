# Recovery Assurance Plane - 공동 (이주오 + 이윤태)

> Staging 환경에서 패치 후보를 3단계로 검증하는 Plane
> 이주오: 검증 시나리오 자동화 / 이윤태: 테스트 환경 정리

---

## 네임스페이스 정보

| 항목 | 값 |
|---|---|
| Namespace | `elden-staging` |
| ServiceAccount | `recovery-assurance-sa` |
| CPU 제한 | requests 4 / limits 8 |
| Memory 제한 | requests 8Gi / limits 16Gi |
| 최대 Pod | 30 |
| Istio | injection **enabled** |

## 이 폴더의 기존 파일

- `deployment.yaml` - target-app Staging 배포 (패치 후보가 여기에 배포됨)

## 추가로 올릴 것

### 3단계 검증 컴포넌트

#### 1단계: 공격 재현 테스트 (Exploit Replay)

패치 적용 후 동일 공격이 차단되는지 확인

```yaml
# exploit-replay-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: exploit-replay
  namespace: elden-staging
spec:
  template:
    spec:
      serviceAccountName: recovery-assurance-sa
      containers:
        - name: exploit-runner
          image: eldenring/exploit-runner:latest
          env:
            - name: TARGET_URL
              value: "http://target-app.elden-staging:8080"
            - name: ATTACK_TYPE
              value: "sqli,xss,path-traversal"
      restartPolicy: Never
  backoffLimit: 1
```

#### 2단계: 회귀 테스트 (Regression)

패치가 기존 기능을 깨뜨리지 않았는지 확인

```yaml
# regression-test-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: regression-test
  namespace: elden-staging
spec:
  template:
    spec:
      serviceAccountName: recovery-assurance-sa
      containers:
        - name: regression
          image: eldenring/regression-tester:latest
          env:
            - name: TARGET_URL
              value: "http://target-app.elden-staging:8080"
            - name: TEST_SUITE
              value: "full"
      restartPolicy: Never
  backoffLimit: 1
```

#### 3단계: SLO 성능 검증

패치 적용 후 성능 저하가 없는지 확인

```yaml
# slo-check-job.yaml
apiVersion: batch/v1
kind: Job
metadata:
  name: slo-check
  namespace: elden-staging
spec:
  template:
    spec:
      serviceAccountName: recovery-assurance-sa
      containers:
        - name: slo-checker
          image: eldenring/slo-checker:latest
          env:
            - name: TARGET_URL
              value: "http://target-app.elden-staging:8080"
            - name: SLO_LATENCY_P99
              value: "1000"
            - name: SLO_ERROR_RATE
              value: "5"
            - name: LOAD_DURATION
              value: "60s"
            - name: LOAD_VUS
              value: "20"
      restartPolicy: Never
  backoffLimit: 1
```

## 검증 결과 저장 규약

검증 결과는 아래 ConfigMap에 저장해야 합니다.
Governance Plane과 GitHub Actions가 이 ConfigMap을 읽어서 승격 여부를 판단합니다.

```yaml
# 각 Job이 완료 후 이 ConfigMap을 업데이트
apiVersion: v1
kind: ConfigMap
metadata:
  name: ra-exploit-results    # 또는 ra-regression-results, ra-slo-results
  namespace: elden-staging
data:
  status: "PASSED"             # PASSED 또는 FAILED
  timestamp: "2026-04-02T15:00:00Z"
  details: "All 5 exploit replays blocked successfully"
```

| ConfigMap 이름 | 검증 단계 | 작성 주체 |
|---|---|---|
| `ra-exploit-results` | 공격 재현 | exploit-replay Job |
| `ra-regression-results` | 회귀 테스트 | regression-test Job |
| `ra-slo-results` | SLO 성능 | slo-check Job |

## 작업 흐름

```
1. Secure Coding Plane이 패치 후보 생성
2. 패치 후보가 elden-staging에 배포됨 (CI/CD 자동 또는 수동)
3. 3단계 검증 Job 실행:
   - exploit-replay → ra-exploit-results 에 결과 저장
   - regression-test → ra-regression-results 에 결과 저장
   - slo-check → ra-slo-results 에 결과 저장
4. Governance Plane이 3개 ConfigMap 확인
5. 모두 PASSED → Canary → Production 승격
```
