"""Lv.3 Defense: Endpoint Disable via Istio VirtualService fault injection."""

import logging

logger = logging.getLogger(__name__)


async def disable_endpoint(
    method: str, path: str, namespace: str = "elden-production"
):
    """
    Create an Istio VirtualService that returns 503 for a specific endpoint.
    """
    vs = {
        "apiVersion": "networking.istio.io/v1beta1",
        "kind": "VirtualService",
        "metadata": {
            "name": f"disable-{path.replace('/', '-').strip('-')}",
            "namespace": namespace,
            "labels": {
                "elden-ring/defense-level": "lv3",
                "elden-ring/created-by": "runtime-defense",
            },
        },
        "spec": {
            "hosts": ["target-app"],
            "http": [
                {
                    "match": [
                        {
                            "uri": {"exact": path},
                            "method": {"exact": method},
                        }
                    ],
                    "fault": {
                        "abort": {
                            "httpStatus": 503,
                            "percentage": {"value": 100.0},
                        }
                    },
                    "route": [
                        {
                            "destination": {
                                "host": "target-app",
                                "port": {"number": 5000},
                            }
                        }
                    ],
                }
            ],
        },
    }

    try:
        from kubernetes import client

        api = client.CustomObjectsApi()
        api.create_namespaced_custom_object(
            group="networking.istio.io",
            version="v1beta1",
            namespace=namespace,
            plural="virtualservices",
            body=vs,
        )
        logger.info(f"Lv.3 Endpoint disabled: {method} {path}")
    except Exception as e:
        logger.warning(f"Lv.3 Endpoint disable for {method} {path} (K8s unavailable: {e})")
