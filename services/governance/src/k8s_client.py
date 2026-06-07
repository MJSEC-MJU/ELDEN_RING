import json
import logging
from typing import Any

from kubernetes import client, config

logger = logging.getLogger(__name__)


class K8sClient:
    def __init__(self):
        try:
            config.load_incluster_config()
        except config.ConfigException:
            config.load_kube_config()
        self.core = client.CoreV1Api()
        self.custom = client.CustomObjectsApi()

    def read_configmap(self, namespace: str, name: str) -> dict[str, str]:
        try:
            cm = self.core.read_namespaced_config_map(name=name, namespace=namespace)
            return cm.data or {}
        except client.ApiException as e:
            if e.status == 404:
                return {}
            raise

    def patch_rollout_status(self, namespace: str, name: str, body: dict[str, Any]) -> None:
        self.custom.patch_namespaced_custom_object(
            group="argoproj.io",
            version="v1alpha1",
            namespace=namespace,
            plural="rollouts",
            name=name,
            body=body,
        )

    def get_rollout(self, namespace: str, name: str) -> dict[str, Any]:
        return self.custom.get_namespaced_custom_object(
            group="argoproj.io",
            version="v1alpha1",
            namespace=namespace,
            plural="rollouts",
            name=name,
        )

    def list_policy_reports(self, namespace: str) -> list[dict[str, Any]]:
        try:
            resp = self.custom.list_namespaced_custom_object(
                group="wgpolicyk8s.io",
                version="v1alpha2",
                namespace=namespace,
                plural="policyreports",
            )
            return resp.get("items", [])
        except client.ApiException as e:
            logger.warning("PolicyReport list failed: %s", e)
            return []

    def patch_argocd_app(self, name: str, namespace: str, body: dict[str, Any]) -> None:
        self.custom.patch_namespaced_custom_object(
            group="argoproj.io",
            version="v1alpha1",
            namespace=namespace,
            plural="applications",
            name=name,
            body=body,
            _content_type="application/merge-patch+json" if not isinstance(body, list) else "application/json-patch+json",
        )
