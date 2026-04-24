import logging

from .k8s_client import K8sClient
from .models import PolicyGateResult

logger = logging.getLogger(__name__)


class PolicyGate:
    def __init__(self, k8s: K8sClient, canary_namespace: str):
        self.k8s = k8s
        self.ns = canary_namespace

    def evaluate(self, incident_id: str) -> PolicyGateResult:
        reports = self.k8s.list_policy_reports(self.ns)
        violations: list[str] = []
        report_names: list[str] = []
        for r in reports:
            meta = r.get("metadata", {})
            labels = meta.get("labels") or {}
            if labels.get("elden-ring/incident") not in (incident_id, None):
                continue
            report_names.append(meta.get("name", ""))
            for res in r.get("results", []):
                if res.get("result") == "fail":
                    policy = res.get("policy", "?")
                    rule = res.get("rule", "?")
                    msg = res.get("message", "")
                    violations.append(f"{policy}/{rule}: {msg}")
        passed = len(violations) == 0
        logger.info(
            "policy gate incident=%s passed=%s violations=%d",
            incident_id, passed, len(violations),
        )
        return PolicyGateResult(passed=passed, violations=violations, policy_reports=report_names)
