# Phase 1: Runtime Defense - 이주오

> 위협 탐지, 이벤트 정규화, CWE 매핑, 소스코드 매핑, 컨텍스트 패키지 생성

## 구조

```
services/runtime-defense/
├── src/                  # 애플리케이션 코드
│   └── main.py
├── tests/                # 테스트
├── Dockerfile
├── requirements.txt
└── README.md
```

## 개발

```bash
cd services/runtime-defense
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn src.main:app --reload --port 8080
```

## 빌드

```bash
docker build -t eldenring/runtime-defense:dev .
```

## K8s 매니페스트

K8s 매니페스트는 `kubernetes/environments/production/` 에 작성:
- `runtime-defense.yaml` (Deployment + Service)

## CI 자동화

`services/runtime-defense/**` 변경 시 자동 빌드/배포됨 (dev 브랜치 push)
