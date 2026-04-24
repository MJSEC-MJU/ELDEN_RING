# Phase 4 — Governance Plane Guide

> Owner: 이종윤 (ialleejy)

Three independent layers — keep them separate.

| Layer | What it controls                | Where it lives                            |
|-------|---------------------------------|-------------------------------------------|
| **A** Policy Validation  | Policy / permission / config conformance | `kubernetes/governance/a-policy-validation/` (Kyverno) |
| **B** GitOps             | Declarative state + promotion audit      | `kubernetes/governance/b-gitops/` (ArgoCD) |
| **C** Deployment Control | Promotion gates + canary + rollback      | `kubernetes/governance/c-deployment-control/` (Argo Rollouts) |

Orchestrator: `services/governance/` — wires Phase 3 results → A → B → C.

## Install (once per cluster)

```bash
# A. Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm upgrade --install kyverno kyverno/kyverno \
  -n kyverno --create-namespace --version 3.2.6
kubectl apply -k kubernetes/governance/a-policy-validation/

# B. ArgoCD
helm repo add argo https://argoproj.github.io/argo-helm
helm upgrade --install argocd argo/argo-cd \
  -n argocd --create-namespace --version 7.7.7
kubectl apply -k kubernetes/governance/b-gitops/

# C. Argo Rollouts
helm upgrade --install argo-rollouts argo/argo-rollouts \
  -n argo-rollouts --create-namespace --version 2.37.7
kubectl apply -k kubernetes/governance/c-deployment-control/

# Orchestrator
kubectl apply -k kubernetes/environments/governance/
```

## Flow (incident → prod)

```
Phase 3 PASSED (ConfigMap + Redis pub)
   │
   ▼
[orchestrator] risk_classifier → low / medium / high
   │
   ▼
[B] git_writer → defense/inc-<id> branch + PR (labeled defense-candidate)
   │
   ▼
[B] ArgoCD ApplicationSet syncs into elden-canary
   │
   ▼
[A] Kyverno admission → PolicyReports aggregated by policy_gate
   │    ├─ fail → publish elden:phase2:retry
   │    └─ pass ↓
   ▼
[C] Rollout: 10% → analysis(SLO) → 30% → analysis → 50%
   │    ├─ low/medium: promotion_gate auto-resume
   │    └─ high     : paused → /incidents/{id}/approve
   │
   ▼
merge dev→main → elden-prod Application syncs (manual trigger)
   │
   ▼
rollback_watcher tails Prometheus; SLO breach → abort + revert
```

## API (governance-controller)

| Method | Path | Purpose |
|---|---|---|
| GET  | `/healthz`, `/readyz`, `/metrics` | liveness/readiness/Prometheus |
| GET  | `/incidents`                      | list in-flight promotions |
| POST | `/incidents/{id}/approve?approver=X` | manual approval (high risk) |
| POST | `/incidents/{id}/rollback?reason=Y`  | force rollback |

## Layering rules (do not violate)

- Policy engine (A) **never** drives Rollout state.
- Rollout controller (C) **never** queries Git.
- Git (B) holds the single source of truth — no out-of-band `kubectl apply` to prod.

## Phase 3 → Phase 4 data contract

Redis channel `elden:phase4:promote` payload:

```json
{
  "incident_id": "inc-2026-0412-001",
  "candidate_image": "ghcr.io/mjsec-mju/elden-target-app:sha-abc123",
  "exploit": "PASSED",
  "regression": "PASSED",
  "slo": "PASSED",
  "manifests": [
    {"kind": "NetworkPolicy", "metadata": {"name": "allow-redis"}, "spec": {...}}
  ]
}
```

Manifests must be self-contained K8s objects; orchestrator writes each one under
`kubernetes/environments/canary/incidents/<id>/NN-kind-name.yaml` on the defense branch.

## Smoke test (no cluster)

```bash
cd services/governance
pip install -r requirements.txt pytest pytest-asyncio
pytest tests/ -q
```
