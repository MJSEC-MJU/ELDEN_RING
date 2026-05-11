"""Lv.2 Defense: IP Block via Istio AuthorizationPolicy."""

import logging

from src.config import settings

logger = logging.getLogger(__name__)


async def block_ip(source_ip: str, namespace: str = "elden-production"):
    """
    Create an Istio AuthorizationPolicy to DENY all requests from a specific IP.
    """
    if not settings.DEFENSE_APPLY_ENABLED:
        logger.debug(f"Lv.2 IP block (apply skipped) for {source_ip}")
        return
    policy = {
        "apiVersion": "security.istio.io/v1beta1",
        "kind": "AuthorizationPolicy",
        "metadata": {
            "name": f"block-{source_ip.replace('.', '-')}",
            "namespace": namespace,
            "labels": {
                "elden-ring/defense-level": "lv2",
                "elden-ring/created-by": "runtime-defense",
            },
        },
        "spec": {
            "selector": {"matchLabels": {"app": "target-app"}},
            "action": "DENY",
            "rules": [
                {"from": [{"source": {"ipBlocks": [f"{source_ip}/32"]}}]}
            ],
        },
    }

    try:
        from kubernetes import client

        api = client.CustomObjectsApi()
        api.create_namespaced_custom_object(
            group="security.istio.io",
            version="v1beta1",
            namespace=namespace,
            plural="authorizationpolicies",
            body=policy,
        )
        logger.info(f"Lv.2 IP blocked: {source_ip}")
    except Exception as e:
        logger.warning(f"Lv.2 IP block for {source_ip} (K8s unavailable: {e})")
