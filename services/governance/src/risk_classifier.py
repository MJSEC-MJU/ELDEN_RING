import re
from typing import Any

import yaml

from .models import RiskClass


class RiskClassifier:
    HIGH_KINDS = {"Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding", "ServiceAccount"}
    LOW_KINDS = {"NetworkPolicy", "EnvoyFilter"}
    LOW_CM_NAME_RE = re.compile(r"^(modsecurity|rate-limit|waf-).*")

    def __init__(self, policy_yaml: str | None = None):
        self.policy = yaml.safe_load(policy_yaml) if policy_yaml else None

    def classify(self, manifests: list[dict[str, Any]]) -> RiskClass:
        highest = RiskClass.LOW
        for m in manifests:
            r = self._classify_one(m)
            if r == RiskClass.HIGH:
                return RiskClass.HIGH
            if r == RiskClass.MEDIUM and highest == RiskClass.LOW:
                highest = RiskClass.MEDIUM
        return highest

    def _classify_one(self, m: dict[str, Any]) -> RiskClass:
        kind = m.get("kind", "")
        name = (m.get("metadata") or {}).get("name", "")
        annotations = (m.get("metadata") or {}).get("annotations") or {}
        change_kind = annotations.get("elden-ring/change-kind", "")

        if kind in self.HIGH_KINDS:
            return RiskClass.HIGH
        if kind in ("Deployment", "Rollout") and change_kind == "image":
            return RiskClass.HIGH
        if kind in ("Deployment", "Rollout") and change_kind == "config-only":
            return RiskClass.MEDIUM
        if kind == "VirtualService":
            return RiskClass.MEDIUM
        if kind == "ConfigMap" and self.LOW_CM_NAME_RE.match(name):
            return RiskClass.LOW
        if kind in self.LOW_KINDS:
            return RiskClass.LOW
        return RiskClass.HIGH
