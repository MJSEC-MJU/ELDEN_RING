# Phase 3: Recovery Assurance - 이윤태

> 기동 검증, 회귀 테스트, 공격 재현, SLO 검증

## 구조

```
services/recovery-assurance/
├── src/
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

## K8s 매니페스트

`kubernetes/environments/staging/` 에 작성

## CI 자동화

`services/recovery-assurance/**` 변경 시 자동 빌드/배포됨 (dev 브랜치 push)
