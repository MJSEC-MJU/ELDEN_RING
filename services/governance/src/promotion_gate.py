import logging

from .k8s_client import K8sClient
from .metrics import rollbacks_total
from .models import RiskClass

logger = logging.getLogger(__name__)


class PromotionGate:
    def __init__(self, k8s: K8sClient):
        self.k8s = k8s

    def resume_if_allowed(self, namespace: str, name: str, risk: RiskClass) -> bool:
        if risk == RiskClass.HIGH:
            logger.info("rollout %s/%s HIGH risk — leaving paused for manual approval",
                        namespace, name)
            return False
        self._set_pause(namespace, name, False)
        return True

    def approve(self, namespace: str, name: str, approver: str) -> None:
        logger.info("manual approval rollout=%s/%s by=%s", namespace, name, approver)
        self._set_pause(namespace, name, False)

    def abort(self, namespace: str, name: str, reason: str) -> None:
        logger.warning("aborting rollout=%s/%s reason=%s", namespace, name, reason)
        bucket = "slo_breach" if reason.startswith("slo_breach") else "manual"
        rollbacks_total.labels(reason=bucket).inc()
        body = {"status": {"abort": True, "abortedAt": None}}
        self.k8s.patch_rollout_status(namespace, name, body)

    def _set_pause(self, namespace: str, name: str, paused: bool) -> None:
        body = {"spec": {"paused": paused}}
        self.k8s.custom.patch_namespaced_custom_object(
            group="argoproj.io",
            version="v1alpha1",
            namespace=namespace,
            plural="rollouts",
            name=name,
            body=body,
        )
