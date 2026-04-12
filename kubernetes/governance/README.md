# ELDEN RING Governance Plane

Phase 4 governance infrastructure — three independent control layers.

| Layer | Dir | Role | Tools |
|---|---|---|---|
| A | `a-policy-validation/` | 정책/권한/구성 적합성 검증 | Kyverno |
| B | `b-gitops/`             | 선언적 상태 + 승격 이력 | ArgoCD |
| C | `c-deployment-control/` | 승격 게이트 + canary + rollback | Argo Rollouts |

Each layer is intentionally scoped to exactly one concern. Do not move promotion logic into A, or policy checks into C.

## Install order

```bash
kubectl apply -k kubernetes/governance/a-policy-validation/
kubectl apply -k kubernetes/governance/b-gitops/
kubectl apply -k kubernetes/governance/c-deployment-control/
```

The orchestrator service lives at `services/governance/` — it watches Phase 3 ConfigMaps and drives A → B → C.
