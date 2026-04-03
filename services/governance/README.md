# Phase 4: Governance - 이종윤

> 정책 검증, GitOps 반영, Canary 승격, 자동 롤백, 모니터링/대시보드

## 구조

```
services/governance/
├── src/
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

## K8s 매니페스트

`kubernetes/environments/governance/` 에 작성

## CI 자동화

`services/governance/**` 변경 시 자동 빌드/배포됨 (dev 브랜치 push)
