# Phase 2: Secure Coding - 이윤태

> 정적 분석, LLM 패치 생성, 후보 이미지 빌드

## 구조

```
services/secure-coding/
├── src/
├── tests/
├── Dockerfile
├── requirements.txt
└── README.md
```

## K8s 매니페스트

`kubernetes/environments/secure-coding/` 에 작성

## CI 자동화

`services/secure-coding/**` 변경 시 자동 빌드/배포됨 (dev 브랜치 push)
